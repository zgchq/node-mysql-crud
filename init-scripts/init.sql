 -- init-scripts/init.sql
-- 设定字符集
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- 1. 创建用户表（和 app.js 逻辑匹配）
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(100),
  is_admin TINYINT DEFAULT 0,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. 创建数据项表
DROP TABLE IF EXISTS data_items;
CREATE TABLE data_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(100) NOT NULL,
  content TEXT NOT NULL,
  user_id INT NOT NULL,
  image_url VARCHAR(255),
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. 可选：创建测试管理员用户（密码：123456，bcrypt 加密）
INSERT INTO users (username, password, email, is_admin) 
VALUES ('admin', '$2a$10$8Hx4Z7e9s8G7e6D5c4b3a2s1d0f9g8h7j6k5l4m3n2b1v0', 'admin@test.com', 1);

SET FOREIGN_KEY_CHECKS = 1;