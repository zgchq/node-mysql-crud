 // 导入所有依赖
const express = require('express');
const mysql = require('mysql');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// 初始化 Express 应用
const app = express();
const port = 3000;

// ======================
// 核心修复：正确配置中间件（顺序不能乱！）
// ======================
// 1. 解析 JSON 请求体
app.use(express.json());
// 2. 解析 FormData 表单（必须加，否则图片上传时 req.body 为空）
app.use(express.urlencoded({ extended: true }));
// 3. 托管静态文件（public + uploads）
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 4. 修复 Session 配置（解决 req.session 为 undefined 的核心问题）
app.use(session({
  secret: 'your-secret-key-123',
  resave: true,          // 修复：设为 true 避免 session 丢失
  saveUninitialized: true,
  cookie: {
    secure: false,       // 本地开发用 false
    httpOnly: true,      // 安全：防止前端 JS 访问 cookie
    sameSite: 'lax',     // 修复：允许跨域请求携带 cookie
    maxAge: 24 * 60 * 60 * 1000 // session 有效期 1 天
  }
}));

// ======================
// 配置图片上传（multer）
// ======================
// 确保 uploads 文件夹存在
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true }); // 递归创建，避免权限问题
}

// multer 存储配置
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const fileName = Date.now() + '-' + Math.random().toString(36).substr(2, 8) + ext;
    cb(null, fileName);
  }
});

// 图片过滤
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('只允许上传 jpg/png/gif/webp 格式的图片！'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB 限制
});

// ======================
// 数据库连接
// ======================
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '123456',
  database: 'login_system',
  port: 3306,
  authPlugin: 'mysql_native_password' // 兼容 MySQL 8.0 认证
});

// 连接数据库
connection.connect((err) => {
  if (err) {
    console.error('数据库连接失败：', err);
    return;
  }
  console.log('✅ 数据库连接成功！');

  // 配置编码
  connection.query('SET NAMES utf8mb4', (err) => {
    if (err) {
      console.log('编码配置失败：', err);
    } else {
      console.log('✅ 数据库编码配置为 utf8mb4 成功！');
    }
  });
});

// ======================
// 管理员权限中间件（修复：先判断 req.session 是否存在）
// ======================
function checkAdmin(req, res, next) {
  // 第一步：判断 req.session 是否存在
  if (!req.session) {
    return res.json({ code: -1, msg: 'Session 初始化失败，请重启服务' });
  }
  // 第二步：判断是否登录
  if (!req.session.user) {
    return res.json({ code: -1, msg: '请先登录' });
  }
  // 第三步：判断是否为管理员
  if (req.session.user.is_admin !== 1) {
    return res.json({ code: -1, msg: '无管理员权限' });
  }
  next();
}

// ======================
// 接口：用户注册
// ======================
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password) {
    return res.json({ code: -1, msg: '用户名和密码不能为空' });
  }
  if (password.length < 6) {
    return res.json({ code: -1, msg: '密码长度不能少于6位' });
  }

  const salt = bcrypt.genSaltSync(10);
  const hashPassword = bcrypt.hashSync(password, salt);

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

// ======================
// 接口：用户登录（核心：正确保存 session）
// ======================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ code: -1, msg: '用户名和密码不能为空' });
  }

  const sql = 'SELECT id, username, password, is_admin FROM users WHERE username = ?';
  connection.query(sql, [username], (err, results) => {
    if (err) {
      return res.json({ code: -1, msg: '登录失败：' + err.message });
    }
    if (results.length === 0) {
      return res.json({ code: -1, msg: '用户名或密码错误' });
    }

    const user = results[0];
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.json({ code: -1, msg: '用户名或密码错误' });
    }

    // 关键：保存用户信息到 session（确保 req.session 存在）
    req.session.user = {
      id: user.id,
      username: user.username,
      is_admin: user.is_admin
    };

    res.json({ code: 0, msg: '登录成功', data: { username: user.username } });
  });
});

// ======================
// 接口：获取用户信息
// ======================
app.get('/api/user/info', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ code: -1, msg: '未登录' });
  }
  res.json({
    code: 0,
    data: req.session.user
  });
});

// ======================
// 接口：退出登录
// ======================
app.post('/api/logout', (req, res) => {
  if (!req.session) {
    return res.json({ code: 0, msg: '退出成功' });
  }
  req.session.destroy((err) => {
    if (err) {
      return res.json({ code: -1, msg: '退出失败' });
    }
    res.json({ code: 0, msg: '退出成功' });
  });
});

// ======================
// 接口：新增数据（支持图片上传）
// ======================
app.post('/api/data/add', upload.single('image'), (req, res) => {
  // 1. 检查 session 和登录状态
  if (!req.session) {
    return res.json({ code: -1, msg: 'Session 异常，请重启服务' });
  }
  if (!req.session.user) {
    return res.json({ code: -1, msg: '请先登录' });
  }

  // 2. 获取参数
  const title = req.body.title?.trim() || '';
  const content = req.body.content?.trim() || '';
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';

  // 3. 验证参数
  if (!title || !content) {
    return res.json({ code: -1, msg: '标题和内容不能为空' });
  }

  // 4. 插入数据库
  const sql = 'INSERT INTO data_items (title, content, user_id, image_url) VALUES (?, ?, ?, ?)';
  connection.query(sql, [title, content, req.session.user.id, imageUrl], (err, results) => {
    if (err) {
      console.error('新增数据失败：', err);
      return res.json({ code: -1, msg: '新增数据失败：' + err.message });
    }
    if (results.affectedRows === 0) {
      return res.json({ code: -1, msg: '数据插入失败，无行受影响' });
    }
    res.json({ code: 0, msg: '新增成功', data: { id: results.insertId, image_url: imageUrl } });
  });
});

// ======================
// 接口：获取个人数据
// ======================
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

// ======================
// 接口：删除个人数据（含图片）
// ======================
// 必须要有这行，位置在 session 之前
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.delete('/api/data/delete/:id', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ code: -1, msg: '请先登录' });
  }

  const { id } = req.params;
  const checkSql = `SELECT id, image_url, user_id FROM data_items WHERE id = ?`;
  
  connection.query(checkSql, [id], (err, results) => {
    if (err || results.length === 0) {
      return res.json({ code: -1, msg: '无权限删除该数据' });
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

      // 删除图片文件
      if (data.image_url) {
        const imagePath = path.join(__dirname, data.image_url.replace('/uploads/', 'uploads/'));
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }

      res.json({ code: 0, msg: '删除成功' });
    });
  });
});

// ======================
// 管理员接口：获取所有用户
// ======================
app.get('/api/admin/users', checkAdmin, (req, res) => {
  const sql = 'SELECT id, username, email, is_admin FROM users ORDER BY id DESC';
  connection.query(sql, (err, results) => {
    if (err) {
      return res.json({ code: -1, msg: '查询用户失败：' + err.message });
    }
    res.json({ code: 0, data: results });
  });
});

// ======================
// 管理员接口：修改用户权限
// ======================
app.post('/api/admin/set-admin/:userId', checkAdmin, (req, res) => {
  const { userId } = req.params;
  const { is_admin } = req.body;

  const sql = 'UPDATE users SET is_admin = ? WHERE id = ?';
  connection.query(sql, [is_admin, userId], (err) => {
    if (err) {
      return res.json({ code: -1, msg: '修改权限失败：' + err.message });
    }
    res.json({ code: 0, msg: '权限修改成功' });
  });
});

// ======================
// 管理员接口：获取所有数据（含图片）
// ======================
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

// ======================
// 管理员接口：导出Excel（CSV）
// ======================
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
      const fileName = encodeURIComponent(`所有数据_${new Date().toLocaleDateString()}.csv`);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);

      // CSV 转义辅助函数
      const escapeCsv = (str) => {
        if (typeof str !== 'string') str = String(str);
        str = str.replace(/"/g, '""');
        if (str.includes(',') || str.includes('\n') || str.includes('"')) {
          str = `"${str}"`;
        }
        return str;
      };

      // 表头
      const header = `${escapeCsv('标题')},${escapeCsv('内容')},${escapeCsv('图片路径')},${escapeCsv('创建时间')},${escapeCsv('所属用户')}\n`;

      // 数据行
      const rows = results.map(item => {
        const title = item.title || '';
        const content = item.content || '';
        const imageUrl = item.image_url || '';
        const createdAt = item.createdAt ? new Date(item.createdAt).toLocaleString() : '';
        const username = item.username || '未知用户';
        
        return `${escapeCsv(title)},${escapeCsv(content)},${escapeCsv(imageUrl)},${escapeCsv(createdAt)},${escapeCsv(username)}`;
      }).join('\n');

      // 加 BOM 解决中文乱码
      const bom = '\uFEFF';
      res.send(bom + header + rows);

    } catch (error) {
      console.error('导出CSV格式处理失败：', error);
      res.json({ code: -1, msg: '导出失败：数据格式处理出错' });
    }
  });
});

// ======================
// 启动服务
// ======================
app.listen(port, () => {
  console.log(`✅ 后端服务启动成功！访问地址：http://localhost:${port}`);
});

// 优雅退出
process.on('SIGINT', () => {
  connection.end();
  console.log('\n❌ 数据库连接已关闭，服务停止');
  process.exit();
});