// ======================
// 1. 依赖导入（统一、去重）
// ======================
require('dotenv').config(); // 优先加载环境变量
const express = require('express');
const mysql = require('mysql2'); // 统一用 mysql2，兼容 callback/promise
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ======================
// 2. 全局配置（统一管理）
// ======================
const app = express();
// 端口：优先读环境变量（Render），本地默认3000
const PORT = process.env.PORT || 3000;
// 项目根目录（解决不同系统路径问题）
const ROOT_DIR = __dirname;
// 图片上传目录（动态拼接，兼容所有系统）
const UPLOAD_DIR = path.join(ROOT_DIR, 'uploads');

// ======================
// 3. 数据库连接配置（统一用环境变量）
// ======================
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '123456',
  database: process.env.DB_NAME || 'test_db',
  port: process.env.DB_PORT || 3306,
  charset: 'utf8mb4',
  authPlugin: 'mysql_native_password',
  // 连接池配置（优化性能，避免频繁创建连接）
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0
};

// 创建数据库连接（单例，全局复用）
const connection = mysql.createConnection(dbConfig);

// ======================
// 4. 中间件配置（顺序合理，适配生产/本地）
// ======================
// 解析 JSON 请求体
app.use(express.json());
// 解析 FormData 表单（支持文件上传）
app.use(express.urlencoded({ extended: true }));
// 托管静态文件（public 目录）
app.use(express.static('public'));
// 托管上传的图片（动态路径，兼容所有系统）
app.use('/uploads', express.static(UPLOAD_DIR));

// Session 配置（适配本地/生产环境）
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-123', // 环境变量配置密钥
  resave: false, // 优化：非必要不重新保存 session
  saveUninitialized: false, // 优化：未初始化的 session 不保存
  cookie: {
    secure: process.env.NODE_ENV === 'production', // 生产环境（Render）启用 HTTPS
    httpOnly: true, // 防止前端 JS 访问 cookie
    sameSite: 'lax', // 允许跨域请求携带 cookie
    maxAge: 24 * 60 * 60 * 1000 // 有效期 1 天
  }
}));

// ======================
// 5. 图片上传配置（动态路径，兼容所有系统）
// ======================
// 确保 uploads 文件夹存在（递归创建）
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// multer 存储配置
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    // 文件名：时间戳 + 随机字符串，避免重复
    const fileName = Date.now() + '-' + Math.random().toString(36).substr(2, 8) + ext;
    cb(null, fileName);
  }
});

// 图片格式过滤
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('只允许上传 jpg/png/gif/webp 格式的图片！'), false);
  }
};

// 初始化 multer（限制文件大小 5MB）
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ======================
// 6. 核心工具函数/中间件
// ======================
/**
 * 管理员权限校验中间件
 * @param {Request} req 
 * @param {Response} res 
 * @param {NextFunction} next 
 */
function checkAdmin(req, res, next) {
  // 1. 检查 Session 是否初始化
  if (!req.session) {
    return res.json({ code: -1, msg: 'Session 初始化失败，请重启服务' });
  }
  // 2. 检查是否登录
  if (!req.session.user) {
    return res.json({ code: -1, msg: '请先登录' });
  }
  // 3. 检查是否为管理员
  if (req.session.user.is_admin !== 1) {
    return res.json({ code: -1, msg: '无管理员权限' });
  }
  next();
}

/**
 * CSV 转义函数（解决中文/特殊字符乱码）
 * @param {string} str 
 * @returns {string}
 */
const escapeCsv = (str) => {
  if (typeof str !== 'string') str = String(str);
  str = str.replace(/"/g, '""'); // 转义双引号
  if (str.includes(',') || str.includes('\n') || str.includes('"')) {
    str = `"${str}"`; // 包含特殊字符则包裹双引号
  }
  return str;
};

// ======================
// 7. 业务接口（按功能分类，结构清晰）
// ======================
// ----------------------
// 健康检查接口（Render 保活用）
// ----------------------
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', time: new Date(), port: PORT });
});

// ----------------------
// 用户模块接口
// ----------------------
// 注册
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;

  // 参数校验
  if (!username || !password) {
    return res.json({ code: -1, msg: '用户名和密码不能为空' });
  }
  if (password.length < 6) {
    return res.json({ code: -1, msg: '密码长度不能少于6位' });
  }

  // 密码加密
  const salt = bcrypt.genSaltSync(10);
  const hashPassword = bcrypt.hashSync(password, salt);

  // 插入数据库
  const sql = 'INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, 0)';
  connection.query(sql, [username, hashPassword, email || ''], (err, results) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.json({ code: -1, msg: '用户名已存在' });
      }
      return res.json({ code: -1, msg: '注册失败：' + err.message });
    }
    res.json({ code: 0, msg: '注册成功' });
  });
});

// 登录
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // 参数校验
  if (!username || !password) {
    return res.json({ code: -1, msg: '用户名和密码不能为空' });
  }

  // 查询用户
  const sql = 'SELECT id, username, password, is_admin FROM users WHERE username = ?';
  connection.query(sql, [username], (err, results) => {
    if (err) {
      return res.json({ code: -1, msg: '登录失败：' + err.message });
    }
    if (results.length === 0) {
      return res.json({ code: -1, msg: '用户名或密码错误' });
    }

    // 验证密码
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
  });
});

// 获取当前用户信息
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
      return res.json({ code: -1, msg: '退出失败：' + err.message });
    }
    res.json({ code: 0, msg: '退出成功' });
  });
});

// ----------------------
// 数据项模块接口
// ----------------------
// 新增数据（带图片上传）
app.post('/api/data/add', upload.single('image'), (req, res) => {
  // 登录校验
  if (!req.session || !req.session.user) {
    return res.json({ code: -1, msg: '请先登录' });
  }

  // 参数获取&校验
  const title = req.body.title?.trim() || '';
  const content = req.body.content?.trim() || '';
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';

  if (!title || !content) {
    return res.json({ code: -1, msg: '标题和内容不能为空' });
  }

  // 插入数据库
  const sql = 'INSERT INTO data_items (title, content, user_id, image_url, createdAt) VALUES (?, ?, ?, ?, NOW())';
  connection.query(sql, [title, content, req.session.user.id, imageUrl], (err, results) => {
    if (err) {
      console.error('新增数据失败：', err);
      return res.json({ code: -1, msg: '新增数据失败：' + err.message });
    }
    res.json({ code: 0, msg: '新增成功', data: { id: results.insertId, image_url: imageUrl } });
  });
});

// 获取个人数据列表
app.get('/api/data/list', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ code: -1, msg: '请先登录' });
  }

  const sql = `
    SELECT id, title, content, image_url, createdAt 
    FROM data_items 
    WHERE user_id = ? 
    ORDER BY createdAt DESC
  `;
  connection.query(sql, [req.session.user.id], (err, results) => {
    if (err) {
      return res.json({ code: -1, msg: '获取数据失败：' + err.message });
    }
    res.json({ code: 0, data: results });
  });
});

// 删除个人数据（含图片文件）
app.delete('/api/data/delete/:id', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ code: -1, msg: '请先登录' });
  }

  const { id } = req.params;
  // 先查询数据，验证权限
  const checkSql = `SELECT id, image_url, user_id FROM data_items WHERE id = ?`;
  
  connection.query(checkSql, [id], (err, results) => {
    if (err || results.length === 0) {
      return res.json({ code: -1, msg: '数据不存在或无权限删除' });
    }

    const data = results[0];
    if (data.user_id !== req.session.user.id) {
      return res.json({ code: -1, msg: '无权限删除该数据' });
    }

    // 删除数据库记录
    const deleteSql = 'DELETE FROM data_items WHERE id = ?';
    connection.query(deleteSql, [id], (err) => {
      if (err) {
        return res.json({ code: -1, msg: '删除失败：' + err.message });
      }

      // 删除图片文件（如果有）
      if (data.image_url) {
        const imagePath = path.join(ROOT_DIR, data.image_url);
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }

      res.json({ code: 0, msg: '删除成功' });
    });
  });
});

// ----------------------
// 管理员模块接口
// ----------------------
// 获取所有用户
app.get('/api/admin/users', checkAdmin, (req, res) => {
  const sql = 'SELECT id, username, email, is_admin FROM users ORDER BY id DESC';
  connection.query(sql, (err, results) => {
    if (err) {
      return res.json({ code: -1, msg: '查询用户失败：' + err.message });
    }
    res.json({ code: 0, data: results });
  });
});

// 修改用户管理员权限
app.post('/api/admin/set-admin/:userId', checkAdmin, (req, res) => {
  const { userId } = req.params;
  const { is_admin } = req.body;

  // 参数校验
  if (is_admin !== 0 && is_admin !== 1) {
    return res.json({ code: -1, msg: '权限值必须是 0（普通用户）或 1（管理员）' });
  }

  const sql = 'UPDATE users SET is_admin = ? WHERE id = ?';
  connection.query(sql, [is_admin, userId], (err) => {
    if (err) {
      return res.json({ code: -1, msg: '修改权限失败：' + err.message });
    }
    res.json({ code: 0, msg: '权限修改成功' });
  });
});

// 获取所有数据（关联用户信息）
app.get('/api/admin/all-data', checkAdmin, (req, res) => {
  const sql = `
    SELECT d.id, d.title, d.content, d.image_url, d.createdAt, u.username 
    FROM data_items d
    LEFT JOIN users u ON d.user_id = u.id
    ORDER BY d.createdAt DESC
  `;
  connection.query(sql, (err, results) => {
    if (err) {
      return res.json({ code: -1, msg: '查询数据失败：' + err.message });
    }
    res.json({ code: 0, data: results });
  });
});

// 导出所有数据为 CSV（Excel 兼容）
app.get('/api/admin/export-excel', checkAdmin, (req, res) => {
  const sql = `
    SELECT d.title, d.content, d.image_url, d.createdAt, u.username 
    FROM data_items d
    LEFT JOIN users u ON d.user_id = u.id
  `;

  connection.query(sql, (err, results) => {
    if (err) {
      console.error('导出数据查询失败：', err);
      return res.json({ code: -1, msg: '导出失败：查询数据出错' });
    }

    if (!results || results.length === 0) {
      return res.json({ code: -1, msg: '导出失败：暂无数据可导出' });
    }

    try {
      // 文件名（编码解决中文乱码）
      const fileName = encodeURIComponent(`所有数据_${new Date().toLocaleDateString()}.csv`);
      // 响应头配置
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);

      // 构建 CSV 内容
      const header = `${escapeCsv('标题')},${escapeCsv('内容')},${escapeCsv('图片路径')},${escapeCsv('创建时间')},${escapeCsv('所属用户')}\n`;
      const rows = results.map(item => {
        const title = item.title || '';
        const content = item.content || '';
        const imageUrl = item.image_url || '';
        const createdAt = item.createdAt ? new Date(item.createdAt).toLocaleString() : '';
        const username = item.username || '未知用户';
        return `${escapeCsv(title)},${escapeCsv(content)},${escapeCsv(imageUrl)},${escapeCsv(createdAt)},${escapeCsv(username)}`;
      }).join('\n');

      // 加 BOM 解决 Excel 中文乱码
      const bom = '\uFEFF';
      res.send(bom + header + rows);

    } catch (error) {
      console.error('导出CSV格式处理失败：', error);
      res.json({ code: -1, msg: '导出失败：数据格式处理出错' });
    }
  });
});

// ======================
// 8. 数据库连接 & 服务启动
// ======================
// 连接数据库并配置编码
connection.connect((err) => {
  if (err) {
    console.error('❌ 数据库连接失败：', err);
    // 连接失败时退出进程，Render 会自动重启
    process.exit(1);
  }
  console.log('✅ 数据库连接成功！');

  // 配置数据库编码为 utf8mb4（解决中文乱码）
  connection.query('SET NAMES utf8mb4', (err) => {
    if (err) {
      console.log('⚠️  数据库编码配置失败：', err);
    } else {
      console.log('✅ 数据库编码配置为 utf8mb4 成功！');
    }
  });
});

// 启动服务（监听 0.0.0.0，适配 Render 部署）
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ 后端服务启动成功！访问地址：http://0.0.0.0:${PORT}`);
});

// ======================
// 9. 优雅退出（关闭数据库连接）
// ======================
process.on('SIGINT', () => {
  connection.end((err) => {
    if (err) console.error('❌ 数据库连接关闭失败：', err);
    else console.log('✅ 数据库连接已关闭');
  });
  console.log('\n❌ 后端服务已停止');
  process.exit();
});

// 捕获未处理的异常，避免服务崩溃
process.on('uncaughtException', (err) => {
  console.error('❌ 未捕获的异常：', err);
  connection.end();
  process.exit(1);
}); 