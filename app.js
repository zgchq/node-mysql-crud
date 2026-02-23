// ======================
// 1. 核心依赖导入（全量且去重）
// ======================
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2'); // 统一使用 mysql2
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const url = require('url'); // 解析 Railway MySQL URL 必备
const cors = require('cors'); // 新增：解决跨域问题（Railway 生产环境必需）

// ======================
// 2. 全局配置（适配 Railway）
// ======================
const app = express();
// 端口：优先读取 Railway 自动分配的 PORT 环境变量
const PORT = process.env.PORT || 3000;
// 项目根目录（Railway 中为 /app）
const ROOT_DIR = __dirname;
// 图片上传目录（Railway 卷挂载路径，添加 Railway 环境判断）
const UPLOAD_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH 
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'uploads') // Railway 卷挂载路径
  : path.join(ROOT_DIR, 'uploads'); // 本地开发路径

// ======================
// 3. 数据库连接配置（核心优化：连接池替代单连接）
// ======================
let dbConfig = {};

// 优先使用 Railway 的 MYSQL_URL（跨服务变量引用）
if (process.env.DATABASE_URL) {
  try {
    const dbUrl = new url.URL(process.env.DATABASE_URL);
    dbConfig = {
      host: dbUrl.hostname,
      user: dbUrl.username,
      password: dbUrl.password,
      database: dbUrl.pathname.slice(1), // 去掉路径开头的 "/"
      port: dbUrl.port || 3306,
      charset: 'utf8mb4',
      // 移除无效的 authPlugin 配置（避免 Railway 警告）
      // 连接池优化（适配 Railway 连接限制，生产环境推荐）
      waitForConnections: true,
      connectionLimit: 10, // 适度提高连接数
      queueLimit: 0,
      enableKeepAlive: true, // 保持连接，减少重连开销
      keepAliveInitialDelay: 300000
    };
    console.log('✅ 已解析 Railway MySQL URL，数据库名：', dbConfig.database);
  } catch (err) {
    console.error('❌ 解析 MySQL URL 失败：', err.message);
    process.exit(1);
  }
} else {
  // 本地开发环境（备用）
  dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '123456',
    database: process.env.DB_NAME || 'test_db',
    port: process.env.DB_PORT || 3306,
    charset: 'utf8mb4',
    connectionLimit: 5,
    enableKeepAlive: true
  };
}

// 优化：使用连接池替代单连接（生产环境更稳定）
const dbPool = mysql.createPool(dbConfig);

// ======================
// 4. 中间件配置（顺序合理，适配 Railway 生产环境）
// ======================
// 新增：CORS 配置（解决 Railway 跨域问题）
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.RAILWAY_PUBLIC_DOMAIN // 生产环境限定域名
    : '*', // 本地开发允许所有
  credentials: true // 允许携带 Cookie/Session
}));

// 解析 JSON 请求体（提高限制大小，适配文件上传）
app.use(express.json({ limit: '10mb' }));
// 解析 FormData 表单（支持文件上传）
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// 托管静态文件（public 目录）
app.use(express.static('public'));
// 托管上传的图片（Railway 卷挂载路径）
app.use('/uploads', express.static(UPLOAD_DIR));

// Session 配置（优化：适配 Railway HTTPS 和 Redis 存储）
app.use(session({
  secret: process.env.SESSION_SECRET || 'railway-secret-123456789',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.RAILWAY_ENVIRONMENT ? true : false, // 优先用 Railway 环境变量
    httpOnly: true,
    sameSite: 'none', // 适配跨域 Cookie
    maxAge: 7 * 24 * 60 * 60 * 1000 // 延长至 7 天
  },
  // Railway 推荐：使用内存存储仅用于开发，生产环境建议用 Redis（可选）
  store: process.env.REDIS_URL ? new (require('connect-redis')(session))({
    url: process.env.REDIS_URL
  }) : undefined
}));

// ======================
// 5. 图片上传配置（Railway 卷挂载持久化 + 错误处理）
// ======================
// 确保 uploads 文件夹存在（递归创建，添加错误捕获）
try {
  if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    console.log('✅ 创建 uploads 文件夹成功：', UPLOAD_DIR);
  }
} catch (err) {
  console.error('❌ 创建 uploads 文件夹失败：', err.message);
  // 不退出服务，使用临时目录
  const TEMP_DIR = path.join(ROOT_DIR, 'temp-uploads');
  fs.mkdirSync(TEMP_DIR, { recursive: true });
  UPLOAD_DIR = TEMP_DIR;
  console.log('⚠️  降级使用临时上传目录：', TEMP_DIR);
}

// multer 存储配置（优化：添加文件大小校验）
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase(); // 统一小写扩展名
    const fileName = `${Date.now()}-${Math.random().toString(36).substr(2, 8)}${ext}`;
    cb(null, fileName);
  }
});

// 图片格式过滤（优化：支持更多格式，更友好的错误提示）
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/jpg'];
  const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  const ext = path.extname(file.originalname).toLowerCase();

  if (allowedTypes.includes(file.mimetype) && allowedExts.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error(`只允许上传 ${allowedExts.join('、')} 格式的图片！`), false);
  }
};

// 初始化 multer（优化：更合理的大小限制，添加错误捕获）
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
}).single('image');

// 封装上传中间件，统一错误处理
const uploadMiddleware = (req, res, next) => {
  upload(req, res, (err) => {
    if (err) {
      return res.json({ code: -1, msg: err.message });
    }
    next();
  });
};

// ======================
// 6. 核心工具函数/中间件（优化）
// ======================
/**
 * 管理员权限校验中间件（优化：异步兼容）
 */
function checkAdmin(req, res, next) {
  if (!req.session) {
    return res.json({ code: -1, msg: 'Session 初始化失败' });
  }
  if (!req.session.user) {
    return res.json({ code: -1, msg: '请先登录' });
  }
  if (req.session.user.is_admin !== 1) {
    return res.json({ code: -1, msg: '无管理员权限' });
  }
  next();
}

/**
 * CSV 转义函数（解决导出乱码）
 */
const escapeCsv = (str) => {
  if (str === null || str === undefined) return '';
  if (typeof str !== 'string') str = String(str);
  str = str.replace(/"/g, '""');
  if (str.includes(',') || str.includes('\n') || str.includes('"') || str.includes('\r')) {
    str = `"${str}"`;
  }
  return str;
};

// ======================
// 7. 健康检查接口（Railway 保活用，优化返回信息）
// ======================
app.get('/health', async (req, res) => {
  try {
    // 新增：数据库健康检查
    const [pingResult] = await dbPool.query('SELECT 1 as health');
    res.status(200).json({
      status: 'ok',
      time: new Date().toISOString(),
      port: PORT,
      database: dbConfig.database,
      database_health: pingResult[0].health === 1,
      upload_dir: UPLOAD_DIR,
      railway_env: !!process.env.RAILWAY_ENVIRONMENT
    });
  } catch (err) {
    res.status(503).json({
      status: 'error',
      message: '服务不可用',
      error: err.message
    });
  }
});

// ======================
// 8. 用户模块接口（优化：使用连接池，异步处理）
// ======================
// 注册
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password) {
      return res.json({ code: -1, msg: '用户名和密码不能为空' });
    }
    if (password.length < 6) {
      return res.json({ code: -1, msg: '密码长度不能少于6位' });
    }

    const salt = bcrypt.genSaltSync(10);
    const hashPassword = bcrypt.hashSync(password, salt);

    const [results] = await dbPool.query(
      'INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, 0)',
      [username, hashPassword, email || '']
    );

    res.json({ code: 0, msg: '注册成功', data: { userId: results.insertId } });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.json({ code: -1, msg: '用户名已存在' });
    }
    console.error('注册失败：', err);
    res.json({ code: -1, msg: '注册失败：' + err.message });
  }
});

// 登录
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.json({ code: -1, msg: '用户名和密码不能为空' });
    }

    const [results] = await dbPool.query(
      'SELECT id, username, password, is_admin FROM users WHERE username = ?',
      [username]
    );

    if (results.length === 0) {
      return res.json({ code: -1, msg: '用户名或密码错误' });
    }

    const user = results[0];
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.json({ code: -1, msg: '用户名或密码错误' });
    }

    // 保存用户信息到 Session
    req.session.user = {
      id: user.id,
      username: user.username,
      is_admin: user.is_admin
    };

    res.json({ code: 0, msg: '登录成功', data: { username: user.username } });
  } catch (err) {
    console.error('登录失败：', err);
    res.json({ code: -1, msg: '登录失败：' + err.message });
  }
});

// 获取用户信息
app.get('/api/user/info', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ code: -1, msg: '未登录' });
  }
  res.json({
    code: 0,
    data: req.session.user
  });
});

// 退出登录
app.post('/api/logout', (req, res) => {
  if (!req.session) {
    return res.json({ code: 0, msg: '退出成功' });
  }
  req.session.destroy((err) => {
    if (err) {
      console.error('退出登录失败：', err);
      return res.json({ code: -1, msg: '退出失败：' + err.message });
    }
    res.json({ code: 0, msg: '退出成功' });
  });
});

// ======================
// 9. 数据项模块接口（带图片上传，优化）
// ======================
// 新增数据（使用封装的上传中间件）
app.post('/api/data/add', uploadMiddleware, async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.json({ code: -1, msg: '请先登录' });
    }

    const title = req.body.title?.trim() || '';
    const content = req.body.content?.trim() || '';
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';

    if (!title || !content) {
      return res.json({ code: -1, msg: '标题和内容不能为空' });
    }

    const [results] = await dbPool.query(
      'INSERT INTO data_items (title, content, user_id, image_url, createdAt) VALUES (?, ?, ?, ?, NOW())',
      [title, content, req.session.user.id, imageUrl]
    );

    res.json({ code: 0, msg: '新增成功', data: { id: results.insertId, image_url: imageUrl } });
  } catch (err) {
    console.error('新增数据失败：', err);
    res.json({ code: -1, msg: '新增数据失败：' + err.message });
  }
});

// 获取个人数据列表
app.get('/api/data/list', async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.json({ code: -1, msg: '请先登录' });
    }

    const [results] = await dbPool.query(`
      SELECT id, title, content, image_url, createdAt 
      FROM data_items 
      WHERE user_id = ? 
      ORDER BY createdAt DESC
    `, [req.session.user.id]);

    res.json({ code: 0, data: results });
  } catch (err) {
    console.error('获取数据失败：', err);
    res.json({ code: -1, msg: '获取数据失败：' + err.message });
  }
});

// 删除个人数据（含图片，优化：异步删除）
app.delete('/api/data/delete/:id', async (req, res) => {
  try {
    if (!req.session || !req.session.user) {
      return res.json({ code: -1, msg: '请先登录' });
    }

    const { id } = req.params;
    const [checkResults] = await dbPool.query(
      `SELECT id, image_url, user_id FROM data_items WHERE id = ?`,
      [id]
    );

    if (checkResults.length === 0) {
      return res.json({ code: -1, msg: '数据不存在' });
    }

    const data = checkResults[0];
    if (data.user_id !== req.session.user.id) {
      return res.json({ code: -1, msg: '无权限删除该数据' });
    }

    // 删除数据库记录
    await dbPool.query('DELETE FROM data_items WHERE id = ?', [id]);

    // 删除图片文件（异步，不阻塞响应）
    if (data.image_url) {
      const imagePath = path.join(ROOT_DIR, data.image_url);
      fs.unlink(imagePath, (err) => {
        if (err) console.error('删除图片失败：', err);
        else console.log('✅ 删除图片成功：', imagePath);
      });
    }

    res.json({ code: 0, msg: '删除成功' });
  } catch (err) {
    console.error('删除数据失败：', err);
    res.json({ code: -1, msg: '删除失败：' + err.message });
  }
});

// ======================
// 10. 管理员模块接口（优化）
// ======================
// 获取所有用户
app.get('/api/admin/users', checkAdmin, async (req, res) => {
  try {
    const [results] = await dbPool.query(
      'SELECT id, username, email, is_admin FROM users ORDER BY id DESC'
    );
    res.json({ code: 0, data: results });
  } catch (err) {
    console.error('查询用户失败：', err);
    res.json({ code: -1, msg: '查询用户失败：' + err.message });
  }
});

// 修改用户权限
app.post('/api/admin/set-admin/:userId', checkAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { is_admin } = req.body;

    if (is_admin !== 0 && is_admin !== 1) {
      return res.json({ code: -1, msg: '权限值必须是 0（普通用户）或 1（管理员）' });
    }

    await dbPool.query(
      'UPDATE users SET is_admin = ? WHERE id = ?',
      [is_admin, userId]
    );

    res.json({ code: 0, msg: '权限修改成功' });
  } catch (err) {
    console.error('修改权限失败：', err);
    res.json({ code: -1, msg: '修改权限失败：' + err.message });
  }
});

// 获取所有数据
app.get('/api/admin/all-data', checkAdmin, async (req, res) => {
  try {
    const [results] = await dbPool.query(`
      SELECT d.id, d.title, d.content, d.image_url, d.createdAt, u.username 
      FROM data_items d
      LEFT JOIN users u ON d.user_id = u.id
      ORDER BY d.createdAt DESC
    `);
    res.json({ code: 0, data: results });
  } catch (err) {
    console.error('查询数据失败：', err);
    res.json({ code: -1, msg: '查询数据失败：' + err.message });
  }
});

// 导出 CSV（优化：更大的响应缓冲区）
app.get('/api/admin/export-excel', checkAdmin, async (req, res) => {
  try {
    const [results] = await dbPool.query(`
      SELECT d.title, d.content, d.image_url, d.createdAt, u.username 
      FROM data_items d
      LEFT JOIN users u ON d.user_id = u.id
    `);

    if (!results || results.length === 0) {
      return res.json({ code: -1, msg: '导出失败：暂无数据可导出' });
    }

    const fileName = encodeURIComponent(`所有数据_${new Date().toLocaleDateString().replace(/\//g, '-')}.csv`);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Transfer-Encoding', 'chunked');

    // 加 BOM 解决 Excel 中文乱码
    const bom = '\uFEFF';
    const header = `${escapeCsv('标题')},${escapeCsv('内容')},${escapeCsv('图片路径')},${escapeCsv('创建时间')},${escapeCsv('所属用户')}\n`;
    
    // 分批发送数据，避免内存溢出
    res.write(bom + header);
    results.forEach((item, index) => {
      const title = item.title || '';
      const content = item.content || '';
      const imageUrl = item.image_url || '';
      const createdAt = item.createdAt ? new Date(item.createdAt).toLocaleString() : '';
      const username = item.username || '未知用户';
      const row = `${escapeCsv(title)},${escapeCsv(content)},${escapeCsv(imageUrl)},${escapeCsv(createdAt)},${escapeCsv(username)}\n`;
      res.write(row);
      // 每 100 行刷新一次缓冲区
      if (index % 100 === 0) res.flush();
    });

    res.end();
  } catch (error) {
    console.error('导出CSV失败：', error);
    res.json({ code: -1, msg: '导出失败：' + error.message });
  }
});

// ======================
// 11. 服务启动（核心适配 Railway，优化）
// ======================
// 测试数据库连接（使用连接池）
async function testDBConnection() {
  try {
    await dbPool.query('SELECT 1');
    console.log('✅ 数据库连接成功！');
    
    // 配置 utf8mb4 编码
    await dbPool.query('SET NAMES utf8mb4');
    console.log('✅ 数据库编码配置为 utf8mb4 成功！');
  } catch (err) {
    console.error('❌ 数据库连接失败：', err);
    // Railway 中延迟退出，给重试机会
    setTimeout(() => process.exit(1), 5000);
  }
}

// 启动服务（优化：显示真实的 Railway 公网地址）
async function startServer() {
  await testDBConnection();
  
  app.listen(PORT, '0.0.0.0', () => {
    // 显示 Railway 真实公网地址（而非 localhost）
    const publicUrl = process.env.RAILWAY_PUBLIC_DOMAIN 
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` 
      : `http://localhost:${PORT}`;
    console.log(`✅ 服务启动成功！端口：${PORT}，访问地址：${publicUrl}`);
    console.log(`✅ 上传目录：${UPLOAD_DIR}`);
    console.log(`✅ 运行环境：${process.env.RAILWAY_ENVIRONMENT || '本地开发'}`);
  });
}

// 启动服务
startServer();

// ======================
// 12. 优雅退出 & 异常捕获（Railway 适配，优化）
// ======================
// 捕获 SIGTERM（Railway 停止服务的信号）
process.on('SIGTERM', async () => {
  console.log('\n⚠️  收到停止信号，开始优雅退出');
  try {
    await dbPool.end();
    console.log('✅ 数据库连接池已关闭');
  } catch (err) {
    console.error('❌ 数据库连接池关闭失败：', err);
  }
  console.log('❌ 服务已停止');
  process.exit(0);
});

// 兼容 SIGINT（本地 Ctrl+C）
process.on('SIGINT', async () => {
  await dbPool.end().catch(err => console.error('❌ 数据库关闭失败：', err));
  console.log('\n❌ 服务已停止');
  process.exit();
});

// 捕获未处理异常（优化：不直接退出，记录后重启）
process.on('uncaughtException', (err) => {
  console.error('❌ 未捕获异常：', err);
  // Railway 会自动重启服务，无需手动退出
});

// 捕获未处理的 Promise 拒绝
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ 未处理的 Promise 拒绝：', reason, promise);
});