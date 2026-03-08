const UserService = require('../service/userService');

// 用户控制器
class UserController {
  // 获取用户列表
  static async getUsers(req, res) {
    try {
      const users = await UserService.getUsers();
      res.json({
        code: 200,
        msg: '获取成功',
        data: users
      });
    } catch (err) {
      res.status(500).json({
        code: 500,
        msg: '获取失败：' + err.message
      });
    }
  }

  // 新增用户
  static async addUser(req, res) {
    try {
      const { username } = req.body;
      await UserService.createUser(username);
      res.json({
        code: 200,
        msg: '新增成功'
      });
    } catch (err) {
      res.status(500).json({
        code: 500,
        msg: '新增失败：' + err.message
      });
    }
  }
}

module.exports = UserController;