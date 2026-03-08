# 基础镜像
FROM node:18-alpine

# 设置工作目录
WORKDIR /app/backend

# 复制依赖文件
COPY package*.json ./

# 安装生产依赖
RUN npm install --production

# 复制后端代码
COPY . .

# 暴露端口（你的 app.js 应该监听 3000 或其他端口，保持一致）
EXPOSE 3000

# 启动命令
CMD ["node", "app.js"]