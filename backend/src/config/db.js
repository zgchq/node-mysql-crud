const mysql = require('mysql2/promise');

// 从环境变量获取配置
const config = {
  host: process.env.MYSQL_HOST || 'localhost',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PWD || '123456',
  database: process.env.MYSQL_DB || 'test_db',
  port: process.env.MYSQL_PORT || 3306,
  charset: 'utf8mb4'
};

// 创建数据库连接池
const pool = mysql.createPool(config);

// 测试连接
pool.getConnection()
  .then(conn => {
    console.log('MySQL连接成功');
    conn.release();
  })
  .catch(err => {
    console.error('MySQL连接失败：', err);
  });

module.exports = pool;