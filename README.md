# Web2Term Chat

这是基于 [naledao/Web2Term](https://github.com/naledao/Web2Term) 改造的 ChatGPT 专用桌面客户端。

## 本分支功能

- 在桌面窗口中打开官方 ChatGPT 网站，使用 OpenAI 账号原生登录。
- 保留 ChatGPT 网页自身的文件上传、图片、附件和下载能力。
- 每台电脑独立保存 Web2Term 项目、会话索引和本地工作区数据。
- 支持 HTTP、HTTPS、SOCKS5 代理，可分别填写代理服务器地址和端口。
- 保留应用主题与应用更新功能。

## 数据与账号隔离

- Web2Term 的项目、会话索引和本地设置保存在当前电脑的 Electron userData 目录及 conversations.db 中，不上传、不在设备之间同步。
- ChatGPT 登录态保存在当前电脑的 persist:chatgpt 浏览器分区。每台电脑分别登录同一个 OpenAI 账号；本程序不会复制或同步 Cookie 文件。
- ChatGPT 网站的云端聊天历史仍由 OpenAI 账号管理。同一账号在不同设备打开 ChatGPT 网站时，OpenAI 自身的云端历史仍可能共享；本程序不会将它伪装成设备隔离。
- 代理配置只应用于 ChatGPT 嵌入网页，不改变系统代理，也不上传到服务器。

## 本分支不提供的功能

SSH、SFTP、本地终端命令执行、远程设备 Agent、Web2Term 后端设备连接、Computer Use、后台任务、定时任务、邮件通知及多模型切换均已从本分支的产品入口和运行路径关闭。

## 构建

需要 Node.js 22 或兼容版本。

```bash
npm ci
npm run build
```

npm run build 执行 TypeScript 检查并构建 Electron 主进程、预加载脚本和渲染界面。Windows/macOS 安装包请使用仓库配置的对应打包工作流。

## 上游项目

本仓库保留上游 Web2Term 的 MIT 许可与基础实现。原始多模型、终端和远程设备功能说明请查看 [上游项目文档](https://github.com/naledao/Web2Term)；这些功能不属于本分支的发行范围。

[executed on device: BWG (8d95c7ab-1c8e-462d-9b14-d6af2257a097)]