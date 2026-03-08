const UserModel = require('../model/userModel');

// 用户服务
class UserService {
  // 获取用户列表
  static async getUsers() {
    return await UserModel.getAllUsers();
  }

  // 新增用户
  static async createUser(username) {
    if (!username) {
      throw new Error('用户名不能为空');
    }
    return await UserModel.addUser(username);
  }
}

module.exports = UserService;