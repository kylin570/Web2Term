#!/usr/bin/env python3
"""Web2Term Chat account authority: registration, 1-device binding, signed sessions.

Runs only on loopback behind an HTTPS reverse proxy. No browser-accessible admin endpoint.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import admin_panel

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DB_PATH = Path(os.environ.get('ACCOUNT_DB', '/var/lib/web2term-account/accounts.sqlite3'))
HOST = os.environ.get('ACCOUNT_HOST', '127.0.0.1')
PORT = int(os.environ.get('ACCOUNT_PORT', '18791'))
ALLOW_REGISTRATION = os.environ.get('ACCOUNT_ALLOW_REGISTRATION', '0') == '1'
CHALLENGE_SECONDS = 90
SESSION_SECONDS = 30 * 24 * 3600
MAX_BYTES = 4096
USERNAME = re.compile(r'^[a-z][a-z0-9_]{2,31}$')
SALT_SIZE = 16
ITERATIONS = 600_000
RATE_LOCK = threading.Lock()
ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def device_key(value: object) -> bytes:
    if not isinstance(value, str) or len(value) > 200:
        raise ValueError('INVALID_DEVICE')
    raw = decode(value)
    if len(raw) != 32:
        raise ValueError('INVALID_DEVICE')
    Ed25519PublicKey.from_public_bytes(raw)
    return raw


def verified(key: bytes, message: str, signature: object) -> bool:
    if not isinstance(signature, str) or len(signature) > 180:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(decode(signature), message.encode('utf-8'))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=10000')
    db.execute('PRAGMA foreign_keys=ON')
    return db


def initialize():
    with connection() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            salt BLOB NOT NULL, password_hash BLOB NOT NULL,
            device_public BLOB,
            created_at INTEGER NOT NULL,
            device_bound_at INTEGER NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0
          );
          CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
          CREATE TABLE IF NOT EXISTS challenges (
            nonce_hash TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
          );
        ''')
        admin_panel.initialize(db)
    try:
        DB_PATH.chmod(0o600)
    except PermissionError:
        pass


def rate_ok(ip: str, category: str, quota: int, duration: int) -> bool:
    now = time.monotonic()
    key = category + ':' + ip
    with RATE_LOCK:
        attempts = ATTEMPTS[key]
        while attempts and attempts[0] < now - duration:
            attempts.popleft()
        if len(attempts) >= quota:
            return False
        attempts.append(now)
        # Avoid unbounded growth from unsolicited unique addresses.
        if len(ATTEMPTS) > 30000:
            for item in list(ATTEMPTS.keys())[:5000]:
                if not ATTEMPTS[item] or ATTEMPTS[item][-1] < now - duration:
                    del ATTEMPTS[item]
        return True


class API(BaseHTTPRequestHandler):
    server_version = 'AccountService/1.0'
    sys_version = ''

    def log_message(self, format, *args):
        # Do not log request bodies, cookies, passwords, tokens or signing material.
        print('auth', self.client_address[0], format % args, file=sys.stderr, flush=True)

    def json(self, code: int, body: dict):
        raw = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        self.wfile.write(raw)

    def fail(self, code: int, error: str):
        self.json(code, {'ok': False, 'code': error})

    def body(self) -> dict:
        try:
            n = int(self.headers.get('Content-Length', '-1'))
            if n < 2 or n > MAX_BYTES:
                raise ValueError
            result = json.loads(self.rfile.read(n))
            if not isinstance(result, dict):
                raise ValueError
            return result
        except (ValueError, UnicodeError, json.JSONDecodeError):
            raise ValueError('BAD_REQUEST')

    def do_GET(self):
        if admin_panel.handle_get(self, connection):
            return
        if self.path == '/health':
            self.json(200, {'ok': True})
        else:
            self.fail(404, 'NOT_FOUND')

    def do_POST(self):
        if admin_panel.handle_post(self, connection, password_digest, token_hash, rate_ok):
            return
        path = urlsplit(self.path).path
        if path not in ('/v1/auth/challenge', '/v1/auth/register', '/v1/auth/login', '/v1/auth/session', '/v1/auth/logout'):
            return self.fail(404, 'NOT_FOUND')
        # Only nginx should connect to loopback; do not trust arbitrary client-supplied forwarding headers.
        ip = self.headers.get('X-Real-IP', self.client_address[0]) if self.client_address[0] in ('127.0.0.1', '::1') else self.client_address[0]
        quota = 20 if path in ('/v1/auth/login', '/v1/auth/register') else 120
        if not rate_ok(ip, path, quota, 60):
            return self.fail(429, 'TOO_MANY_REQUESTS')
        try:
            data = self.body()
        except ValueError:
            return self.fail(400, 'BAD_REQUEST')
        try:
            if path == '/v1/auth/challenge':
                return self.challenge()
            if path in ('/v1/auth/register', '/v1/auth/login'):
                return self.credentials(path.endswith('register'), data)
            return self.session(path.endswith('logout'), data)
        except (sqlite3.Error, OSError):
            self.log_error('storage error')
            return self.fail(503, 'SERVICE_UNAVAILABLE')

    def challenge(self):
        nonce = secrets.token_urlsafe(32)
        now = int(time.time())
        with connection() as db:
            db.execute('DELETE FROM challenges WHERE expires_at < ?', (now,))
            db.execute('INSERT INTO challenges(nonce_hash, expires_at) VALUES (?, ?)', (token_hash(nonce), now + CHALLENGE_SECONDS))
        self.json(200, {'ok': True, 'nonce': nonce, 'expiresInSeconds': CHALLENGE_SECONDS})

    def credentials(self, register: bool, data: dict):
        username = data.get('username', '')
        password = data.get('password', '')
        nonce = data.get('nonce', '')
        if not isinstance(username, str) or not USERNAME.fullmatch(username) or username != username.lower():
            return self.fail(400, 'INVALID_USERNAME')
        if not isinstance(password, str) or len(password) < 10 or len(password) > 128 or '\x00' in password:
            return self.fail(400, 'INVALID_PASSWORD')
        if not isinstance(nonce, str) or not 24 <= len(nonce) <= 100:
            return self.fail(400, 'INVALID_CHALLENGE')
        try:
            key = device_key(data.get('devicePublic'))
        except (ValueError, TypeError):
            return self.fail(400, 'INVALID_DEVICE')
        action = 'register' if register else 'login'
        if not verified(key, 'web2term-auth-v1\n' + action + '\n' + username + '\n' + nonce, data.get('signature')):
            return self.fail(401, 'INVALID_SIGNATURE')
        now = int(time.time())
        failure = None
        token = None
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            # Consume the challenge even on a rejected login. All account mutations
            # must commit before returning an HTTP error or a success response.
            taken = db.execute('DELETE FROM challenges WHERE nonce_hash=? AND expires_at>=?', (token_hash(nonce), now))
            if taken.rowcount != 1:
                failure = (401, 'CHALLENGE_EXPIRED')
            else:
                user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
                user_id = None
                if register:
                    if not ALLOW_REGISTRATION:
                        failure = (403, 'REGISTRATION_DISABLED')
                    elif user:
                        failure = (409, 'USERNAME_TAKEN')
                    else:
                        salt = secrets.token_bytes(SALT_SIZE)
                        hashed = password_digest(password, salt)
                        cursor = db.execute(
                            'INSERT INTO users (username,salt,password_hash,device_public,created_at,device_bound_at) VALUES (?,?,?,?,?,?)',
                            (username, salt, hashed, key, now, now))
                        user_id = cursor.lastrowid
                elif user and user['locked_until'] > now:
                    failure = (429, 'ACCOUNT_LOCKED')
                else:
                    # Uniform costly password check also for unknown users.
                    salt = user['salt'] if user else b'\0' * SALT_SIZE
                    hashed = password_digest(password, salt)
                    if user is None or not hmac.compare_digest(hashed, user['password_hash']) or user['disabled']:
                        if user:
                            count = user['failed_attempts'] + 1
                            lock = now + 600 if count >= 5 else 0
                            db.execute('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?',
                                       (0 if lock else count, lock, user['id']))
                        failure = (401, 'INVALID_CREDENTIALS')
                    elif user['expires_at'] is not None and user['expires_at'] <= now:
                        failure = (403, 'ACCOUNT_EXPIRED')
                    elif user['device_public'] is not None and not hmac.compare_digest(user['device_public'], key):
                        failure = (403, 'DEVICE_BOUND')
                    else:
                        db.execute('UPDATE users SET failed_attempts=0,locked_until=0,device_public=?,device_bound_at=? WHERE id=?',
                                   (key, now if user['device_public'] is None else user['device_bound_at'], user['id']))
                        user_id = user['id']
                if user_id is not None and failure is None:
                    token = secrets.token_urlsafe(48)
                    db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
                    db.execute('INSERT INTO sessions(token_hash,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)',
                               (token_hash(token), user_id, now, now + SESSION_SECONDS, now))
        if failure is not None:
            return self.fail(*failure)
        assert token is not None
        self.json(200, {'ok': True, 'username': username, 'token': token, 'expiresAt': now + SESSION_SECONDS})

    def session(self, logout: bool, data: dict):
        authorization = self.headers.get('Authorization', '')
        token = authorization.removeprefix('Bearer ') if authorization.startswith('Bearer ') else ''
        issued = data.get('timestamp')
        signature = data.get('signature')
        now = int(time.time())
        if len(token) < 45 or not isinstance(issued, int) or abs(now - issued) > 120:
            return self.fail(401, 'SESSION_EXPIRED')
        with connection() as db:
            row = db.execute('SELECT s.*,u.username,u.device_public,u.disabled,u.expires_at AS account_expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?', (token_hash(token),)).fetchone()
            if row is None or row['expires_at'] < now or row['disabled']:
                return self.fail(401, 'SESSION_EXPIRED')
            if row['account_expires_at'] is not None and row['account_expires_at'] <= now:
                return self.fail(403, 'ACCOUNT_EXPIRED')
            path = '/v1/auth/logout' if logout else '/v1/auth/session'
            if not verified(row['device_public'], 'web2term-session-v1\n' + path + '\n' + str(issued) + '\n' + token, signature):
                return self.fail(401, 'INVALID_SIGNATURE')
            if logout:
                db.execute('DELETE FROM sessions WHERE token_hash=?', (token_hash(token),))
            else:
                db.execute('UPDATE sessions SET last_seen_at=? WHERE token_hash=?', (now, token_hash(token)))
        # Return success only AFTER SQLite has committed the revocation.
        self.json(200, {'ok': True} if logout else {'ok': True, 'username': row['username'], 'expiresAt': row['expires_at']})


def admin_action(args):
    with connection() as db:
        if args.command == 'list':
            for row in db.execute('SELECT username,datetime(created_at,"unixepoch") registered,datetime(device_bound_at,"unixepoch") bound,disabled FROM users ORDER BY id'):
                print(row['username'], row['registered'], row['bound'], 'disabled' if row['disabled'] else 'active')
        elif args.command == 'unbind':
            row = db.execute('SELECT id FROM users WHERE username=?', (args.username,)).fetchone()
            if not row:
                raise SystemExit('Username not found')
            db.execute('UPDATE users SET device_public=NULL,device_bound_at=0 WHERE id=?', (row['id'],))
            db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
            print('Device binding cleared; the next correct password login binds a new computer.')
        elif args.command == 'delete':
            result = db.execute('DELETE FROM users WHERE username=?', (args.username,))
            if result.rowcount == 0:
                raise SystemExit('Username not found')
            print('Account and all sessions permanently removed.')
        elif args.command in ('disable', 'enable'):
            status = 1 if args.command == 'disable' else 0
            result = db.execute('UPDATE users SET disabled=? WHERE username=?', (status, args.username))
            db.execute('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=?)', (args.username,))
            if result.rowcount == 0:
                raise SystemExit('Username not found')
            print('Account status updated and all sessions revoked.')


def main():
    parser = argparse.ArgumentParser(description='One-device Web2Term account service')
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('serve')
    sub.add_parser('list')
    bootstrap = sub.add_parser('admin-init')
    bootstrap.add_argument('username')
    bootstrap.add_argument('--password-stdin', action='store_true')
    for cmd in ('unbind', 'disable', 'enable', 'delete'):
        sub.add_parser(cmd).add_argument('username')
    args = parser.parse_args()
    initialize()
    if args.command == 'admin-init':
        if not args.password_stdin:
            raise SystemExit('Use --password-stdin; never pass admin passwords as command arguments')
        password = sys.stdin.readline().rstrip('\n')
        with connection() as db:
            admin_panel.bootstrap(db, password_digest, args.username, password)
        print('Administrator initialized')
        return
    if args.command not in (None, 'serve'):
        return admin_action(args)
    if HOST not in ('127.0.0.1', '::1'):
        raise SystemExit('Refusing to listen on public interfaces; terminate TLS at nginx.')
    server = ThreadingHTTPServer((HOST, PORT), API)
    print('Web2Term account service listening on', HOST, PORT, flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()