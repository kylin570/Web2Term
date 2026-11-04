# Web2Term Chat

这是基于 [naledao/Web2Term](https://github.com/naledao/Web2Term) 改造的 ChatGPT 专用桌面客户端。**本分支与原 Web2Term 使用不同的软件标识和本地数据目录，不会覆盖原程序及原会话库。**

## 用户功能

- 注册独立的客户端用户名和密码；**一个用户名只能绑定一台电脑**。注册成功后自动绑定；另一台电脑即使密码正确也会被服务器拒绝。
- 在当前电脑登录后才创建和加载 ChatGPT 页面。客户端账号和 ChatGPT/OpenAI 官方账号相互独立。
- 同电脑可以重新登录，退出账号不等于解绑；换机由管理员在服务端清除绑定，保留用户名和原密码。
- 在桌面窗口中打开官方 ChatGPT，使用原生登录、上传文件、图片、下载和模型网站提供的功能。
- 本地管理 ChatGPT 项目和聊天入口，支持 HTTP、HTTPS、SOCKS5 代理。代理仅对 ChatGPT 嵌入网页生效。
- 保留应用主题和更新功能；取消本地/远程终端、SSH、SFTP、web2term 设备连接、Computer Use 和多模型切换入口。

## 账户与本地数据

- 账号认证使用独立 HTTPS API：`https://auth.nvhai.de`。服务端只保存账号、加盐密码哈希、设备公钥以及经哈希处理的会话令牌；不会保存 ChatGPT Cookie。
- 客户端首次注册时生成 Ed25519 设备密钥，私钥和登录令牌优先放在操作系统安全存储中，渲染进程不接触这些凭据。服务器需要验证设备密钥签名才能登录或续验。
- 每台电脑的应用设置、项目及会话索引独立存放在 Electron `userData` 下的 SQLite 数据库；不会从软件上传到另一个设备。
- ChatGPT 网站的云端聊天记录仍受同一 OpenAI 账号管理，**不能**通过本地数据隔离阻止 OpenAI 自身同步。
- 此处的一机绑定是操作系统凭据保护下的单安装身份约束；任何软件式绑定都不能保证抵御管理员级篡改、完整磁盘克隆或二进制修改。部署和发行应使用代码签名。
- 账号服务器必须可访问；认证不可用时客户端会暂时关闭聊天工作区以防绕过校验。

## 构建

需要 Node.js 22：

```bash
npm ci
npm run typecheck
npm run build
```

Windows 安装包：`npm run dist:win`（在 Windows 构建机运行）；macOS Apple Silicon：`npm run dist:mac`。未签名或未公证的 macOS DMG 仍受 Gatekeeper 限制。

## 服务器管理

服务源码、HTTPS 反向代理建议、管理员解绑及测试命令见 [account-server/README.md](account-server/README.md)。实际服务器使用 `web2term-account.service` 和 `/var/lib/web2term-account/accounts.sqlite3`。

## 许可

继承上游 Web2Term 的 MIT 许可；第三方名称、商标和服务仍归各权利人所有。客户端仅封装官方 ChatGPT 网站，不构成 OpenAI 官方客户端。
