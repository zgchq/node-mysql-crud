 const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const ExcelJS = require('exceljs');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

// 中间件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 上传文件夹
const uploadDir = path.join(__dirname, 'uploads');
require('fs').mkdirSync(uploadDir, { recursive: true });

// 日志
app.use((req, res, next) => {
  const time = new Date().toLocaleString();
  console.log(`[${time}] ${req.method} ${req.originalUrl}`);
  next();
});

// 会话
app.use(session({
  secret: 'node-mysql-crud-2025-admin-upload-email',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// 数据库
const db = mysql.createConnection({
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: '123456',
  database: 'login_system'
});

db.connect(err => {
  if (err) { console.error('MySQL 连接失败', err); return; }
  console.log('MySQL 连接成功');

  // 用户表（增加 avatar / email / is_admin）
  db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      email VARCHAR(100) UNIQUE,
      avatar VARCHAR(255) DEFAULT '/uploads/default.png',
      is_admin TINYINT DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 数据项
  db.query(`
    CREATE TABLE IF NOT EXISTS data_items (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      title VARCHAR(255) NOT NULL,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // 邮箱验证码
  db.query(`
    CREATE TABLE IF NOT EXISTS email_codes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(100) NOT NULL,
      code VARCHAR(10) NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// ===================== 工具 =====================
const requireLogin = (req, res, next) => {
  if (!req.session.user) return res.json({ code: -1, msg: '请登录' });
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.is_admin !== 1) {
    return res.json({ code: -403, msg: '无管理员权限' });
  }
  next();
};

// 邮箱配置（自己换成你的QQ/163）
const transporter = nodemailer.createTransport({
  service: 'qq',
  auth: {
    user: '你的QQ邮箱',
    pass: '你的SMTP授权码'
  }
});

// 发送验证码
app.post('/api/email/code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ code: -1, msg: '邮箱不能为空' });

  const code = Math.random().toString().slice(2, 8);
  await transporter.sendMail({
    from: '个人系统 <你的QQ邮箱>',
    to: email,
    subject: '邮箱验证码',
    text: `您的验证码：${code}，5分钟内有效`
  });

  db.query('INSERT INTO email_codes (email,code) VALUES (?,?)', [email, code]);
  res.json({ code: 0, msg: '发送成功' });
});

// 上传配置
const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (_, file, cb) => {
    const name = Date.now() + path.extname(file.originalname);
    cb(null, name);
  }
});
const upload = multer({ storage });

// ===================== 用户 =====================
// 注册（带邮箱验证）
app.post('/api/register', (req, res) => {
  const { username, password, email, code } = req.body;
  if (!username || !password || !email || !code) {
    return res.json({ code: -1, msg: '信息不完整' });
  }

  db.query('SELECT * FROM email_codes WHERE email=? AND code=?',
    [email, code], (err, result) => {
      if (result.length === 0) return res.json({ code: -1, msg: '验证码错误' });

      db.query('SELECT * FROM users WHERE username=? OR email=?',
        [username, email], (e, r) => {
          if (r.length) return res.json({ code: -1, msg: '用户名/邮箱已存在' });

          const hash = bcrypt.hashSync(password, 10);
          db.query('INSERT INTO users (username,password,email) VALUES (?,?,?)',
            [username, hash, email], () => {
              res.json({ code: 0, msg: '注册成功' });
            });
        });
    });
});

// 登录
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username=?', [username], (err, r) => {
    if (r.length === 0 || !bcrypt.compareSync(password, r[0].password)) {
      return res.json({ code: -1, msg: '账号或密码错误' });
    }
    const u = r[0];
    req.session.user = {
      id: u.id, username: u.username, email: u.email,
      avatar: u.avatar, is_admin: u.is_admin
    };
    res.json({ code: 0, msg: '登录成功', data: req.session.user });
  });
});

// 头像上传
app.post('/api/user/avatar', requireLogin, upload.single('avatar'), (req, res) => {
  const url = '/uploads/' + req.file.filename;
  db.query('UPDATE users SET avatar=? WHERE id=?',
    [url, req.session.user.id], () => {
      req.session.user.avatar = url;
      res.json({ code: 0, msg: '上传成功', data: url });
    });
});

// 获取信息
app.get('/api/user/info', requireLogin, (req, res) => {
  res.json({ code: 0, data: req.session.user });
});

// 退出
app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ code: 0, msg: '退出成功' });
});

// ===================== 数据 =====================
app.get('/api/data/list', requireLogin, (req, res) => {
  const { page = 1, size = 10, keyword = '', order = 'desc' } = req.query;
  const offset = (page - 1) * size;
  let sql = `SELECT * FROM data_items WHERE user_id=?`;
  let params = [req.session.user.id];

  if (keyword) {
    sql += ` AND (title LIKE ? OR content LIKE ?)`;
    params.push(`%${keyword}%`, `%${keyword}%`);
  }
  sql += ` ORDER BY updated_at ${order} LIMIT ?,?`;
  params.push(offset, parseInt(size));

  db.query(sql, params, (err, list) => {
    db.query(
      `SELECT COUNT(*) as total FROM data_items WHERE user_id=?`,
      [req.session.user.id], (_, c) => {
        res.json({
          code: 0, data: {
            list,
            total: c[0].total,
            pages: Math.ceil(c[0].total / size)
          }
        });
      }
    );
  });
});

app.post('/api/data/add', requireLogin, (req, res) => {
  const { title, content } = req.body;
  if (!title) return res.json({ code: -1, msg: '标题不能为空' });
  db.query('INSERT INTO data_items (user_id,title,content) VALUES (?,?,?)',
    [req.session.user.id, title, content || ''], () => {
      res.json({ code: 0, msg: '添加成功' });
    });
});

app.post('/api/data/update', requireLogin, (req, res) => {
  const { id, title, content } = req.body;
  db.query(`UPDATE data_items SET title=?,content=? WHERE id=? AND user_id=?`,
    [title, content || '', id, req.session.user.id], (e, r) => {
      res.json(r.affectedRows ? { code: 0, msg: '修改成功' } : { code: -1 });
    });
});

app.post('/api/data/delete', requireLogin, (req, res) => {
  const { id } = req.body;
  db.query(`DELETE FROM data_items WHERE id=? AND user_id=?`,
    [id, req.session.user.id], (e, r) => {
      res.json(r.affectedRows ? { code: 0, msg: '删除成功' } : { code: -1 });
    });
});

// 导出Excel
app.get('/api/data/export', requireLogin, async (req, res) => {
  db.query(`SELECT * FROM data_items WHERE user_id=?`,
    [req.session.user.id], async (_, list) => {
      const wb = new ExcelJS.Workbook();
      const ws = wb.addWorksheet('数据列表');
      ws.columns = [
        { header: 'ID', key: 'id' },
        { header: '标题', key: 'title' },
        { header: '内容', key: 'content' },
        { header: '创建时间', key: 'created_at' }
      ];
      list.forEach(i => ws.addRow(i));
      res.setHeader('Content-Type', 'application/vnd.ms-excel');
      res.setHeader('Content-Disposition', 'attachment; filename=data.xlsx');
      await wb.xlsx.write(res);
      res.end();
    });
});

// ===================== 管理员 =====================
app.get('/api/admin/users', requireAdmin, (_, res) => {
  db.query('SELECT id,username,email,avatar,is_admin,created_at FROM users', (_, r) => {
    res.json({ code: 0, data: r });
  });
});

app.get('/api/admin/data', requireAdmin, (_, res) => {
  db.query(`
    SELECT d.*,u.username FROM data_items d
    LEFT JOIN users u ON d.user_id = u.id
    ORDER BY d.updated_at DESC
  `, (_, r) => {
    res.json({ code: 0, data: r });
  });
});

// ===================== 页面 =====================
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register', (_, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/admin', (_, res) => res.sendFile(path.join(__dirname, 'public/admin.html')));

app.listen(PORT, () => {
  console.log('启动：http://localhost:' + PORT);
});