 /**
 * Node.js + MySQL CRUD 项目（Railway 适配版）
 * 修复：mysql2 异步语法、数据库连接、Session 存储、端口适配、文件上传
 */
// 基础依赖引入
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
require('dotenv').config();

// 引入 promise 版本的 mysql2（核心修复点）
const mysql = require('mysql2/promise');

// ========== 1. 基础配置 ==========
const app = express();
// 适配 Railway 动态端口（核心：不能硬编码 8080）
const PORT = process.env.PORT || 8080;
// 运行环境
const NODE_ENV = process.env.NODE_ENV || 'development';

// ========== 2. 中间件配置 ==========
// CORS 配置（允许所有跨域请求，生产可限定域名）
app.use(cors({
  origin: NODE_ENV === 'production' ? process.env.CORS_ORIGIN || '*' : '*',
  credentials: true // 允许携带 Cookie/Session
}));
// 解析 JSON 和表单数据
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========== 3. 数据库连接池配置（核心修复点） ==========
const dbConfig = {
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT || 3306,
  // 连接池配置（解决连接断开问题）
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // 超时配置
  connectTimeout: 15000,
  acquireTimeout: 15000,
  timeout: 15000,
  // 字符集和时区（解决乱码/时间不一致）
  charset: 'utf8mb4',
  timezone: '+08:00'
};

// 数据库连接池实例
let dbPool;

/**
 * 初始化数据库连接
 * @returns {Promise<mysql.Pool>} 数据库连接池
 */
async function initDatabase() {
  try {
    // 创建连接池
    dbPool = mysql.createPool(dbConfig);
    // 测试连接
    const [pingResult] = await dbPool.query('SELECT 1 AS ping');
    console.log('✅ 数据库连接成功！', pingResult);
    return dbPool;
  } catch (error) {
    console.error('❌ 数据库连接失败：', error.message);
    // 连接失败时退出进程，Railway 会自动重启
    process.exit(1);
  }
}

// ========== 4. Session 配置（修复内存存储警告） ==========
// Session 存储目录（Railway 需挂载卷，本地自动创建）
const sessionDir = path.join(__dirname, 'sessions');
if (!fs.existsSync(sessionDir)) {
  fs.mkdirSync(sessionDir, { recursive: true });
}

app.use(session({
  secret: process.env.SESSION_SECRET || 'railway-node-mysql-2026-secure',
  resave: false, // 禁止无修改时重新保存
  saveUninitialized: false, // 禁止保存未初始化的 Session
  store: new SQLiteStore({
    db: 'sessions.db',
    dir: sessionDir,
    table: 'sessions'
  }),
  cookie: {
    secure: NODE_ENV === 'production', // 生产环境启用 HTTPS
    httpOnly: true, // 禁止前端 JS 访问 Cookie
    maxAge: 24 * 60 * 60 * 1000, // Session 有效期 1 天
    sameSite: 'lax' // 跨站请求保护
  }
}));

// ========== 5. 文件上传配置（Railway 卷适配） ==========
// 上传目录（Railway 需挂载 /app/uploads 卷）
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// 上传配置
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // 生成唯一文件名，避免重复
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const filename = `${file.fieldname}-${uniqueSuffix}${ext}`;
    cb(null, filename);
  }
});

// 限制文件类型和大小
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 最大 5MB
  },
  fileFilter: (req, file, cb) => {
    // 允许的文件类型
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('仅允许上传 JPG/PNG/GIF/WEBP 格式的图片！'), false);
    }
  }
});

// ========== 6. 核心接口 ==========
/**
 * 健康检查接口（Railway 健康检查用）
 * GET /health
 */
app.get('/health', async (req, res) => {
  try {
    // 检查数据库连接
    const [dbCheck] = await dbPool.query('SELECT NOW() AS current_time');
    res.status(200).json({
      status: 'ok',
      service: 'node-mysql-crud',
      port: PORT,
      env: NODE_ENV,
      db: 'connected',
      current_time: dbCheck[0].current_time
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      service: 'node-mysql-crud',
      port: PORT,
      env: NODE_ENV,
      db: 'disconnected',
      error: error.message
    });
  }
});

/**
 * 根路径接口
 */
app.get('/', (req, res) => {
  res.send(`
    <h1>Node.js + MySQL CRUD 服务（Railway 部署）</h1>
    <p>健康检查：<a href="/health">/health</a></p>
    <p>接口文档：</p>
    <ul>
      <li>POST /api/register - 用户注册</li>
      <li>POST /api/login - 用户登录</li>
      <li>POST /api/data/add - 新增数据（支持图片上传）</li>
      <li>GET /api/data/list - 获取数据列表</li>
    </ul>
  `);
});

/**
 * 用户注册接口
 * POST /api/register
 * 参数：{ username, password, email }
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    // 参数校验
    if (!username || !password) {
      return res.json({
        code: 1,
        msg: '用户名和密码不能为空'
      });
    }

    // 检查用户名是否已存在
    const [existingUser] = await dbPool.query(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (existingUser.length > 0) {
      return res.json({
        code: 1,
        msg: '用户名已存在，请更换'
      });
    }

    // 密码加密（bcrypt）
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // 插入用户数据
    const [result] = await dbPool.query(
      'INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)',
      [username, hashedPassword, email || '', 0]
    );

    res.json({
      code: 0,
      msg: '注册成功',
      data: {
        userId: result.insertId,
        username: username
      }
    });
  } catch (error) {
    console.error('注册接口错误：', error);
    res.json({
      code: 500,
      msg: '服务器内部错误',
      error: NODE_ENV === 'development' ? error.message : ''
    });
  }
});

/**
 * 用户登录接口
 * POST /api/login
 * 参数：{ username, password }
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 参数校验
    if (!username || !password) {
      return res.json({
        code: 1,
        msg: '用户名和密码不能为空'
      });
    }

    // 查询用户
    const [userList] = await dbPool.query(
      'SELECT id, username, password, is_admin FROM users WHERE username = ?',
      [username]
    );

    if (userList.length === 0) {
      return res.json({
        code: 1,
        msg: '用户名或密码错误'
      });
    }

    const user = userList[0];

    // 验证密码
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.json({
        code: 1,
        msg: '用户名或密码错误'
      });
    }

    // 保存 Session
    req.session.user = {
      id: user.id,
      username: user.username,
      isAdmin: user.is_admin === 1
    };

    res.json({
      code: 0,
      msg: '登录成功',
      data: {
        userId: user.id,
        username: user.username,
        isAdmin: user.is_admin === 1
      }
    });
  } catch (error) {
    console.error('登录接口错误：', error);
    res.json({
      code: 500,
      msg: '服务器内部错误',
      error: NODE_ENV === 'development' ? error.message : ''
    });
  }
});

/**
 * 用户登出接口
 * GET /api/logout
 */
app.get('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.json({
        code: 1,
        msg: '登出失败'
      });
    }
    res.json({
      code: 0,
      msg: '登出成功'
    });
  });
});

/**
 * 新增数据接口（支持图片上传）
 * POST /api/data/add
 * 参数：{ title, content } + file (image)
 */
app.post('/api/data/add', upload.single('image'), async (req, res) => {
  try {
    // 检查登录状态
    if (!req.session.user) {
      return res.json({
        code: 1,
        msg: '请先登录'
      });
    }

    const { title, content } = req.body;
    const userId = req.session.user.id;

    // 参数校验
    if (!title || !content) {
      return res.json({
        code: 1,
        msg: '标题和内容不能为空'
      });
    }

    // 图片路径（无图片则为空）
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';

    // 插入数据
    const [result] = await dbPool.query(
      'INSERT INTO data_items (title, content, user_id, image_url) VALUES (?, ?, ?, ?)',
      [title, content, userId, imageUrl]
    );

    res.json({
      code: 0,
      msg: '数据新增成功',
      data: {
        id: result.insertId,
        title: title,
        content: content,
        imageUrl: imageUrl,
        userId: userId
      }
    });
  } catch (error) {
    console.error('新增数据接口错误：', error);
    res.json({
      code: 500,
      msg: '服务器内部错误',
      error: NODE_ENV === 'development' ? error.message : ''
    });
  }
});

/**
 * 获取数据列表接口
 * GET /api/data/list
 * 参数：?page=1&size=10
 */
app.get('/api/data/list', async (req, res) => {
  try {
    // 分页参数
    const page = parseInt(req.query.page) || 1;
    const size = parseInt(req.query.size) || 10;
    const offset = (page - 1) * size;

    // 查询总数
    const [countResult] = await dbPool.query('SELECT COUNT(*) AS total FROM data_items');
    const total = countResult[0].total;

    // 查询列表
    const [list] = await dbPool.query(`
      SELECT di.id, di.title, di.content, di.image_url, di.createdAt, u.username 
      FROM data_items di
      LEFT JOIN users u ON di.user_id = u.id
      ORDER BY di.createdAt DESC
      LIMIT ? OFFSET ?
    `, [size, offset]);

    res.json({
      code: 0,
      msg: '获取列表成功',
      data: {
        list: list.map(item => ({
          id: item.id,
          title: item.title,
          content: item.content,
          imageUrl: item.image_url,
          createdAt: item.createdAt,
          username: item.username
        })),
        pagination: {
          page: page,
          size: size,
          total: total,
          pages: Math.ceil(total / size)
        }
      }
    });
  } catch (error) {
    console.error('获取数据列表接口错误：', error);
    res.json({
      code: 500,
      msg: '服务器内部错误',
      error: NODE_ENV === 'development' ? error.message : ''
    });
  }
});

// ========== 7. 静态文件托管 ==========
// 托管上传的图片
app.use('/uploads', express.static(uploadDir));

// ========== 8. 全局错误处理 ==========
app.use((err, req, res, next) => {
  console.error('全局错误：', err);
  res.status(500).json({
    code: 500,
    msg: '服务器内部错误',
    error: NODE_ENV === 'development' ? err.message : ''
  });
});

// ========== 9. 启动服务 ==========
async function startServer() {
  try {
    // 先初始化数据库连接
    await initDatabase();

    // 启动 HTTP 服务
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ 服务启动成功！端口：${PORT}`);
      console.log(`✅ 运行环境：${NODE_ENV}`);
      console.log(`✅ 上传目录：${uploadDir}`);
      console.log(`✅ Session 目录：${sessionDir}`);
      console.log(`✅ 访问地址：http://0.0.0.0:${PORT}`);
    });
  } catch (error) {
    console.error('❌ 服务启动失败：', error.message);
    process.exit(1);
  }
}

// 启动服务
startServer();

// 暴露数据库连接池（供其他模块使用）
module.exports = {
  app,
  dbPool,
  initDatabase
};