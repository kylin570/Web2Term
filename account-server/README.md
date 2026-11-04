# Web2Term Chat 独立认证服务

## 已部署环境

- 公共接口：`https://auth.nvhai.de`（Cloudflare DNS/HTTPS → BWG 宝塔 Nginx → `127.0.0.1:18791`）
- 程序：`/opt/web2term-auth/server.py`
- systemd 服务：`web2term-account.service`
- SQLite：`/var/lib/web2term-account/accounts.sqlite3`（独立无登录 Shell 的账号和 0700 数据目录）
- 服务器私有的账号列表、密码哈希、设备公钥和登录凭据哈希不提交 GitHub。

## API

| 方法 | 路由 | 说明 |
| --- | --- | --- |
| GET | `/health` | 无敏感数据的健康检查 |
| POST | `/v1/auth/challenge` | 一次性 90 秒随机挑战 |
| POST | `/v1/auth/register` | 首次注册，校验密码和设备签名后绑定设备公钥 |
| POST | `/v1/auth/login` | 密码+设备签名校验，一台电脑绑定 |
| POST | `/v1/auth/session` | 令牌和设备签名校验，默认 30 天会话 |
| POST | `/v1/auth/logout` | 撤销当前会话令牌 |

注册用户名只能由小写英文字母、数字和下划线组成，首字符是英文字母，长度 3–32；密码长度 10–128。服务端以随机盐 PBKDF2-HMAC-SHA256 进行存储（600,000 次），用 Ed25519 校验客户端拥有的设备私钥。挑战仅能使用一次，接口有限速和错误尝试锁定；用户密钥不发送到服务器。

## 安装与升级

要求 Python 3.10+、`cryptography` 包和 Nginx 提供有效 HTTPS 证书。服务应只监听 `127.0.0.1`，不可将 Python 端口直接暴露公网。

```bash
# 更新服务端源码后：
sudo install -m 644 account-server/server.py /opt/web2term-auth/server.py
sudo systemctl restart web2term-account
sudo systemctl status web2term-account
curl -f https://auth.nvhai.de/health
```

## 管理员操作（不暴露网页 API）

```bash
# 查看账户（不显示密码或令牌）
sudo -u web2term-auth env ACCOUNT_DB=/var/lib/web2term-account/accounts.sqlite3 python3 /opt/web2term-auth/server.py list

# 用户更换电脑前必须在服务器上手动解绑；会同时撤销旧会话
sudo -u web2term-auth env ACCOUNT_DB=/var/lib/web2term-account/accounts.sqlite3 python3 /opt/web2term-auth/server.py unbind 用户名

# 禁用/启用账户，禁用会撤销登录
sudo -u web2term-auth env ACCOUNT_DB=/var/lib/web2term-account/accounts.sqlite3 python3 /opt/web2term-auth/server.py disable 用户名
sudo -u web2term-auth env ACCOUNT_DB=/var/lib/web2term-account/accounts.sqlite3 python3 /opt/web2term-auth/server.py enable 用户名

# 永久删除账户（不可撤销，务必先备份）
sudo -u web2term-auth env ACCOUNT_DB=/var/lib/web2term-account/accounts.sqlite3 python3 /opt/web2term-auth/server.py delete 用户名
```

解绑保留用户名和原密码，下次在新电脑正确输入密码后自动重新绑定。**退出登录不解除设备绑定。**

## 测试和备份

```bash
cd account-server
python3 test_auth.py
# SQLite 在线备份必须使用 SQLite backup API，不能直接 cp 正在运行的 WAL 数据库。
python3 - <<'PY'
import sqlite3
src = sqlite3.connect('/var/lib/web2term-account/accounts.sqlite3')
dst = sqlite3.connect('/var/lib/web2term-account/accounts-backup.sqlite3')
with dst:
    src.backup(dst)
dst.close(); src.close()
PY
```

必须限制备份目录和备份文件权限，定期备份并验证恢复；建议只由服务用户运行备份命令。不要将真实用户数据库、令牌或密钥提交到仓库。
