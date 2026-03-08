# 使用 Node.js 18 Alpine 镜像（轻量且稳定）
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 复制 package.json 和 package-lock.json（优先复制，利用缓存）
COPY package*.json ./

# 安装依赖
RUN npm install --production

# 复制项目其余文件
COPY . .

# 暴露端口（根据你的项目实际端口修改，如 3000）
EXPOSE 3000

# 启动命令（根据你的 package.json 中的 scripts 调整）
CMD ["node", "app.js"]