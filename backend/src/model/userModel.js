const pool = require('../config/db');

// 用户模型
class UserModel {
  // 获取所有用户
  static async getAllUsers() {
    const [rows] = await pool.query('SELECT * FROM user ORDER BY id DESC');
    return rows;
  }

  // 新增用户
  static async addUser(username) {
    const [result] = await pool.query(
      'INSERT INTO user (username) VALUES (?)',
      [username]
    );
    return result;
  }
}

module.exports = UserModel;