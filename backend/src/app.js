const express = require('express');
const cors = require('cors');
const UserController = require('./controller/userController');

// 创建应用
const app = express();
const port = process.env.PORT || 3000;

// 中间件
app.use(cors()); // 跨域
app.use(express.json()); // 解析JSON请求

// 接口路由
app.get('/api/users', UserController.getUsers);
app.post('/api/users', UserController.addUser);

// 启动服务
app.listen(port, () => {
  console.log(`后端服务运行在：http://0.0.0.0:${port}`);
});