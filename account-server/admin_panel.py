"""Password-protected browser administrator for Web2Term accounts.

Mounted by server.py on /admin; browser sessions are separate from desktop tokens.
Only the SQLite-backed administrator account can manage users.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, quote, urlsplit

COOKIE = '__Host-web2term-admin'
ADMIN_SESSION_SECONDS = 8 * 3600
BEIJING = timezone(timedelta(hours=8))
MAX_FORM_BYTES = 8192

STYLE = """
*{box-sizing:border-box}body{margin:0;background:#f4f6fa;color:#172238;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:#14243d;color:#fff;padding:18px max(24px,calc((100vw - 1140px)/2));display:flex;justify-content:space-between;align-items:center}
header strong{font-size:19px}main{max-width:1140px;margin:28px auto;padding:0 20px}
h1{font-size:24px;margin:0 0 16px}h2{font-size:18px;margin:0 0 16px}
.panel{background:#fff;border:1px solid #e4e8ef;border-radius:14px;padding:22px;margin-bottom:22px;box-shadow:0 5px 25px #1f344508}
form{display:flex;gap:10px;align-items:end;flex-wrap:wrap}label{display:flex;flex-direction:column;gap:5px;font-size:13px;color:#40516a}
input,button{font:inherit;border-radius:8px;padding:9px 11px}input{border:1px solid #cbd5e1;min-width:130px}input[type=password]{min-width:190px}
button{background:#2759c4;border:1px solid #2759c4;color:white;cursor:pointer}button:focus-visible,input:focus-visible{outline:2px solid #5689ff;outline-offset:2px}
button.secondary{background:#fff;color:#2759c4;border-color:#bacbea}button.danger{background:#fff;color:#a12828;border-color:#e2abab}
.note{color:#68768c;font-size:13px}.alert{background:#fff5e8;border:1px solid #e9c99b;border-radius:8px;padding:10px 14px;margin-bottom:15px}
.ok{color:#177050}.expired{color:#ba3737}.disabled{color:#6d7485}.tag{display:inline-block;padding:3px 9px;border-radius:20px;background:#edf1f9}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:850px}td,th{text-align:left;border-bottom:1px solid #ecf0f5;padding:12px 9px;vertical-align:middle}
th{color:#6d7889;font-weight:600;font-size:13px}td form{display:inline-flex;gap:7px;margin:3px 0}td input{width:190px;min-width:0}
.check{flex-direction:row;align-items:center}input[type=checkbox]{min-width:0}.login{max-width:420px;margin:9vh auto}
.login form{display:grid;align-items:stretch}.login label{font-size:14px}.login input{width:100%}
.summary{display:flex;gap:16px;flex-wrap:wrap}.metric{padding:12px 18px;background:#f2f5fb;border-radius:10px;min-width:120px}
.metric b{display:block;font-size:23px}
small{font-size:12px;color:#66768d}a{color:#2759c4}
"""

def initialize(db):
    columns = {row[1] for row in db.execute('PRAGMA table_info(users)')}
    if 'expires_at' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN expires_at INTEGER')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            salt BLOB NOT NULL, password_hash BLOB NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token_hash TEXT PRIMARY KEY,
            admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
            csrf TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS admin_session_expiry ON admin_sessions(expires_at);
    ''')

def bootstrap(db, password_digest, username, password):
    if not username or not username.isascii() or not (3 <= len(username) <= 32) or not all(c.isalnum() or c == '_' for c in username):
        raise ValueError('管理员用户名须为3—32位英文、数字或下划线')
    if len(password) < 14 or len(password) > 128:
        raise ValueError('管理员密码须为14—128个字符')
    if db.execute('SELECT COUNT(*) FROM admins').fetchone()[0]:
        raise ValueError('管理员已存在；请勿通过初始化覆盖原管理员密码')
    salt = secrets.token_bytes(16)
    db.execute('INSERT INTO admins(username,salt,password_hash) VALUES(?,?,?)',
               (username, salt, password_digest(password, salt)))

def escaped(value):
    return html.escape(str(value), quote=True)

def send_html(api, status, body, set_cookie=None):
    raw = ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           '<title>Web2Term Chat · 账号管理</title><style>' + STYLE +
           '</style></head><body><header><strong>Web2Term Chat · 管理后台</strong>'
           '<span>账号与到期时间管理</span></header>' + body + '</body></html>').encode('utf-8')
    api.send_response(status)
    api.send_header('Content-Type', 'text/html; charset=utf-8')
    api.send_header('Content-Length', str(len(raw)))
    api.send_header('Cache-Control', 'no-store')
    api.send_header('X-Content-Type-Options', 'nosniff')
    api.send_header('X-Frame-Options', 'DENY')
    api.send_header('Referrer-Policy', 'no-referrer')
    api.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    if set_cookie:
        api.send_header('Set-Cookie', set_cookie)
    api.end_headers()
    api.wfile.write(raw)

def redirect(api, code='saved', set_cookie=None):
    api.send_response(303)
    api.send_header('Location', '/admin/?notice=' + quote(code))
    api.send_header('Cache-Control', 'no-store')
    if set_cookie:
        api.send_header('Set-Cookie', set_cookie)
    api.send_header('Content-Length', '0')
    api.end_headers()

def _cookie(api):
    jar = SimpleCookie()
    try:
        jar.load(api.headers.get('Cookie', ''))
        return jar[COOKIE].value if COOKIE in jar else ''
    except Exception:
        return ''

def _session(db, api):
    token = _cookie(api)
    if len(token) < 40 or len(token) > 150:
        return None
    row = db.execute(
        'SELECT a.username,s.token_hash,s.csrf,s.expires_at '
        'FROM admin_sessions s JOIN admins a ON a.id=s.admin_id '
        'WHERE s.token_hash=?', (hashlib.sha256(token.encode('utf-8')).hexdigest(),)).fetchone()
    if row is None or row['expires_at'] <= int(time.time()):
        return None
    return row

def _form(api):
    length = int(api.headers.get('Content-Length', '0'))
    if not 0 < length <= MAX_FORM_BYTES:
        raise ValueError('表单长度不正确')
    payload = api.rfile.read(length).decode('utf-8', errors='strict')
    decoded = parse_qs(payload, keep_blank_values=True, max_num_fields=25)
    if any(len(values) != 1 for values in decoded.values()):
        raise ValueError('表单参数重复')
    return {key: value[0] for key, value in decoded.items()}

def _expiry(raw, *, required=False):
    if raw == '' and not required:
        return None
    if not raw:
        raise ValueError('请选择到期时间')
    try:
        date = datetime.strptime(raw, '%Y-%m-%dT%H:%M').replace(tzinfo=BEIJING)
        return int(date.timestamp())
    except ValueError as exc:
        raise ValueError('到期时间格式不正确') from exc

def _display_time(timestamp):
    return datetime.fromtimestamp(timestamp, BEIJING).strftime('%Y-%m-%dT%H:%M') if timestamp else ''

def _human_time(timestamp):
    return datetime.fromtimestamp(timestamp, BEIJING).strftime('%Y-%m-%d %H:%M') if timestamp else '永久有效'

def _message(code):
    return {'created':'账号新增成功。首次登录将绑定用户电脑。',
            'saved':'账号设置已保存，原登录会话已失效。',
            'unbound':'设备已解绑，下次成功登录将绑定新电脑。',
            'password':'密码已重置，请通知用户新密码。',
            'logged-out':'已退出管理员后台。',
            'invalid':'账号、密码或到期时间格式有误。',
            'exists':'用户名已存在。',
            'missing':'账号不存在。',
            'forbidden':'登录信息无效或权限不足。',
            'login-failed':'管理员账号或密码不正确。',
            'locked':'登录失败次数过多，请10分钟后重试。',
            'expired':'登录状态已过期，请重新登录。'
            }.get(code, '')

def _login_page(api, notice=''):
    message = _message(notice)
    body = '<main class="login"><section class="panel"><h1>管理员登录</h1><p class="note">仅供管理员使用，不影响普通用户聊天登录。</p>'
    if message:
        body += '<div class="alert" role="alert">' + escaped(message) + '</div>'
    body += (
        '<form method="post" action="/admin/login">'
        '<label>管理员用户名<input name="username" autocomplete="username" required maxlength="32"></label>'
        '<label>管理员密码<input name="password" type="password" autocomplete="current-password" required maxlength="128"></label>'
        '<button type="submit">进入账号管理</button></form></section></main>')
    send_html(api, 200, body)

def _dashboard(api, db, session, notice=''):
    now = int(time.time())
    users = db.execute('SELECT username,created_at,device_bound_at,disabled,expires_at '
                       'FROM users ORDER BY id DESC').fetchall()
    counts = {'total':len(users), 'active':0, 'expired':0}
    for u in users:
        if u['expires_at'] is not None and u['expires_at'] <= now:
            counts['expired'] += 1
        elif not u['disabled']:
            counts['active'] += 1
    csrf = escaped(session['csrf'])
    body = '<main><h1>账号管理</h1><div class="summary">'
    for label, value in [('全部账号',counts['total']),('可使用',counts['active']),('已到期',counts['expired'])]:
        body += '<div class="metric"><b>' + str(value) + '</b>' + label + '</div>'
    body += '</div><p class="note">当前管理员：' + escaped(session['username']) + ' · 到期时间均为北京时间（UTC+8）</p>'
    if _message(notice):
        body += '<div class="alert" role="status">' + escaped(_message(notice)) + '</div>'
    body += (
        '<section class="panel"><h2>新增账号</h2>'
        '<form method="post" action="/admin/create">'
        '<input name="csrf" type="hidden" value="' + csrf + '">'
        '<label>用户名<input name="username" required pattern="[a-z][a-z0-9_]{2,31}" maxlength="32" placeholder="英文小写/数字/下划线"></label>'
        '<label>初始密码<input type="password" name="password" required minlength="10" maxlength="128" autocomplete="new-password" placeholder="至少10位"></label>'
        '<label>到期时间（北京时间）<input type="datetime-local" name="expires_at" required></label>'
        '<button type="submit">新增账号</button></form>'
        '<p class="note">账户由管理员创建。用户首次登录时自动绑定电脑；一个账户只能使用一台电脑。</p></section>')
    body += ('<section class="panel"><h2>现有账号</h2><div class="table-wrap"><table>'
             '<thead><tr><th>用户名</th><th>状态</th><th>绑定设备</th><th>注册时间</th><th>到期时间 / 管理操作</th></tr></thead><tbody>')
    for user in users:
        name = escaped(user['username'])
        is_expired = user['expires_at'] is not None and user['expires_at'] <= now
        status = ('<span class="expired">已到期</span>' if is_expired else
                  '<span class="disabled">已停用</span>' if user['disabled'] else '<span class="ok">正常</span>')
        checked = ' checked' if user['disabled'] else ''
        expiry = escaped(_display_time(user['expires_at']))
        body += (
            '<tr><td><b>' + name + '</b></td><td>' + status + '</td><td>' +
            ('已绑定' if user['device_bound_at'] else '待首次登录') +
            '</td><td>' + escaped(_human_time(user['created_at'])) + '</td>'
            '<td><small>当前：' + escaped(_human_time(user['expires_at'])) + '</small>'
            '<form method="post" action="/admin/update">'
            '<input type="hidden" name="csrf" value="' + csrf + '">'
            '<input type="hidden" name="username" value="' + name + '">'
            '<label>到期时间<input name="expires_at" type="datetime-local" value="' + expiry + '"></label>'
            '<label class="check"><input name="disabled" type="checkbox" value="1"' + checked + '>停用</label>'
            '<button type="submit">保存</button></form>'
            '<form method="post" action="/admin/unbind">'
            '<input type="hidden" name="csrf" value="' + csrf + '">'
            '<input type="hidden" name="username" value="' + name + '">'
            '<button class="secondary" type="submit">解绑设备</button></form>'
            '<form method="post" action="/admin/password">'
            '<input type="hidden" name="csrf" value="' + csrf + '">'
            '<input type="hidden" name="username" value="' + name + '">'
            '<input name="password" type="password" minlength="10" maxlength="128" required placeholder="新密码">'
            '<button class="secondary" type="submit">重置密码</button></form>'
            '</td></tr>')
    body += ('</tbody></table></div><p class="note">清空到期时间并保存可设为永久有效。保存更改、重置密码或解绑设备会撤销该用户原有登录会话。</p></section>')
    body += ('<section class="panel"><form method="post" action="/admin/logout">'
             '<input type="hidden" name="csrf" value="' + csrf + '">'
             '<button class="secondary" type="submit">安全退出管理员后台</button></form></section></main>')
    send_html(api, 200, body)

def handle_get(api, connection):
    path = urlsplit(api.path)
    if path.path not in ('/admin','/admin/'):
        return False
    with connection() as db:
        session = _session(db, api)
        notice = parse_qs(path.query).get('notice',[''])[0]
        if session:
            _dashboard(api, db, session, notice)
        else:
            _login_page(api, notice)
    return True

def handle_post(api, connection, password_digest, token_hash, rate_ok):
    path = urlsplit(api.path).path
    if path not in ('/admin/login','/admin/create','/admin/update','/admin/unbind','/admin/password','/admin/logout'):
        return False
    # The reverse proxy is the only trusted source of a client's real IP.
    ip = api.headers.get('X-Real-IP', api.client_address[0]) if api.client_address[0] in ('127.0.0.1','::1') else api.client_address[0]
    if not rate_ok(ip, 'admin:'+path, 10 if path == '/admin/login' else 90, 600):
        redirect(api, 'locked')
        return True
    try:
        form = _form(api)
    except (ValueError, UnicodeError):
        redirect(api, 'invalid')
        return True
    now = int(time.time())
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        if path == '/admin/login':
            username = form.get('username','').strip()
            password = form.get('password','')
            admin = db.execute('SELECT * FROM admins WHERE username=?', (username,)).fetchone()
            salt = admin['salt'] if admin is not None else b'\0'*16
            digest = password_digest(password[:129], salt)
            if admin is None or not hmac.compare_digest(digest, admin['password_hash']):
                if admin is not None:
                    count = admin['failed_attempts']+1
                    lock = now+600 if count >= 5 else 0
                    db.execute('UPDATE admins SET failed_attempts=?,locked_until=? WHERE id=?',
                               (0 if lock else count, lock, admin['id']))
                result = 'login-failed'
            elif admin['locked_until'] > now:
                result = 'locked'
            else:
                db.execute('UPDATE admins SET failed_attempts=0,locked_until=0 WHERE id=?', (admin['id'],))
                token = secrets.token_urlsafe(48)
                csrf = secrets.token_urlsafe(32)
                db.execute('DELETE FROM admin_sessions WHERE admin_id=? OR expires_at<=?', (admin['id'],now))
                db.execute('INSERT INTO admin_sessions(token_hash,admin_id,csrf,expires_at) VALUES(?,?,?,?)',
                           (token_hash(token),admin['id'],csrf,now+ADMIN_SESSION_SECONDS))
                result = 'created-session'
        else:
            session = _session(db, api)
            if session is None or not hmac.compare_digest(form.get('csrf',''), session['csrf']):
                result = 'forbidden'
            elif path == '/admin/logout':
                db.execute('DELETE FROM admin_sessions WHERE token_hash=?',(session['token_hash'],))
                result = 'logged-out'
            else:
                username = form.get('username','').strip()
                if not username or not username.isascii() or not (3 <= len(username) <= 32) or not username[0].islower() or not all(ch.islower() or ch.isdigit() or ch == '_' for ch in username):
                    result = 'invalid'
                elif path == '/admin/create':
                    password = form.get('password','')
                    if not 10 <= len(password) <= 128 or '\0' in password:
                        result = 'invalid'
                    else:
                        try:
                            expires_at = _expiry(form.get('expires_at',''), required=True)
                            salt = secrets.token_bytes(16)
                            db.execute('INSERT INTO users(username,salt,password_hash,device_public,created_at,device_bound_at,expires_at) '
                                       'VALUES(?,?,?,NULL,?,0,?)', (username,salt,password_digest(password,salt),now,expires_at))
                            result = 'created'
                        except ValueError:
                            result = 'invalid'
                        except sqlite3.IntegrityError:
                            result = 'exists'
                else:
                    row = db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()
                    if row is None:
                        result = 'missing'
                    elif path == '/admin/update':
                        try:
                            expiry = _expiry(form.get('expires_at',''))
                            disabled = 1 if form.get('disabled','') == '1' else 0
                            db.execute('UPDATE users SET expires_at=?,disabled=? WHERE id=?',(expiry,disabled,row['id']))
                            db.execute('DELETE FROM sessions WHERE user_id=?',(row['id'],))
                            result = 'saved'
                        except ValueError:
                            result = 'invalid'
                    elif path == '/admin/unbind':
                        db.execute('UPDATE users SET device_public=NULL,device_bound_at=0 WHERE id=?',(row['id'],))
                        db.execute('DELETE FROM sessions WHERE user_id=?',(row['id'],))
                        result = 'unbound'
                    else:
                        password = form.get('password','')
                        if not 10 <= len(password) <= 128 or '\0' in password:
                            result = 'invalid'
                        else:
                            salt = secrets.token_bytes(16)
                            db.execute('UPDATE users SET salt=?,password_hash=?,failed_attempts=0,locked_until=0 WHERE id=?',
                                       (salt,password_digest(password,salt),row['id']))
                            db.execute('DELETE FROM sessions WHERE user_id=?',(row['id'],))
                            result = 'password'
    if result == 'created-session':
        redirect(api, 'saved', COOKIE+'='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age='+str(ADMIN_SESSION_SECONDS))
    elif result == 'logged-out':
        redirect(api, result, COOKIE+'=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0')
    else:
        redirect(api, result)
    return True
