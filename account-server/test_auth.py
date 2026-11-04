"""End-to-end tests with real SQLite and signed Ed25519 client requests."""
import base64
import importlib
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

with tempfile.TemporaryDirectory(prefix='account-test-') as _test_bootstrap:
    pass
import server


def public(private):
    return base64.b64encode(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def signed(private, message):
    return base64.b64encode(private.sign(message.encode())).decode()


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.TemporaryDirectory(prefix='account-suite-')
        server.DB_PATH = Path(cls.root.name) / 'users.db'
        server.initialize()
        cls.httpd = server.ThreadingHTTPServer(('127.0.0.1', 0), server.API)
        cls.origin = 'http://127.0.0.1:' + str(cls.httpd.server_address[1])
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.root.cleanup()

    def post(self, path, value, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = Request(self.origin + path, data=json.dumps(value).encode(), headers=headers, method='POST')
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as response:
            return response.code, json.load(response)

    def credentials(self, action, user, password, key):
        status, ch = self.post('/v1/auth/challenge', {})
        self.assertEqual(status, 200)
        nonce = ch['nonce']
        return self.post('/v1/auth/' + action, {
            'username': user,
            'password': password,
            'devicePublic': public(key),
            'nonce': nonce,
            'signature': signed(key, 'web2term-auth-v1\n' + action + '\n' + user + '\n' + nonce)
        })

    def session(self, action, token, key):
        path = '/v1/auth/' + action
        timestamp = int(time.time())
        return self.post(path, {
            'timestamp': timestamp,
            'signature': signed(key, 'web2term-session-v1\n' + path + '\n' + str(timestamp) + '\n' + token)
        }, token)

    def test_single_computer_then_admin_rebind(self):
        one = Ed25519PrivateKey.generate()
        two = Ed25519PrivateKey.generate()
        status, first = self.credentials('register', 'unitdevice', 'a-secure-password-123', one)
        self.assertEqual(status, 200)
        self.assertEqual(first['username'], 'unitdevice')
        status, data = self.credentials('register', 'unitdevice', 'a-secure-password-123', two)
        self.assertEqual((status, data['code']), (409, 'USERNAME_TAKEN'))
        status, data = self.credentials('login', 'unitdevice', 'a-secure-password-123', two)
        self.assertEqual((status, data['code']), (403, 'DEVICE_BOUND'))
        status, result = self.session('session', first['token'], one)
        self.assertEqual((status, result['username']), (200, 'unitdevice'))
        status, data = self.session('session', first['token'], two)
        self.assertEqual((status, data['code']), (401, 'INVALID_SIGNATURE'))
        status, second = self.credentials('login', 'unitdevice', 'a-secure-password-123', one)
        self.assertEqual(status, 200)
        status, data = self.session('session', first['token'], one)
        self.assertEqual((status, data['code']), (401, 'SESSION_EXPIRED'))
        status, _ = self.session('logout', second['token'], one)
        self.assertEqual(status, 200)
        status, data = self.session('session', second['token'], one)
        self.assertEqual((status, data['code']), (401, 'SESSION_EXPIRED'))
        server.admin_action(type('Arguments', (), {'command': 'unbind', 'username': 'unitdevice'})())
        status, bound = self.credentials('login', 'unitdevice', 'a-secure-password-123', two)
        self.assertEqual(status, 200)
        status, data = self.credentials('login', 'unitdevice', 'a-secure-password-123', one)
        self.assertEqual((status, data['code']), (403, 'DEVICE_BOUND'))
        status, result = self.session('session', bound['token'], two)
        self.assertEqual((status, result['username']), (200, 'unitdevice'))

    def test_wrong_password_locks_account_and_challenge_consumed(self):
        key = Ed25519PrivateKey.generate()
        status, first = self.credentials('register', 'unitlock', 'strong-password-1234', key)
        self.assertEqual(status, 200)
        status, challenge = self.post('/v1/auth/challenge', {})
        nonce = challenge['nonce']
        bad = {'username': 'unitlock', 'password': 'incorrect-password',
               'devicePublic': public(key), 'nonce': nonce,
               'signature': signed(key, 'web2term-auth-v1\nlogin\nunitlock\n' + nonce)}
        status, error = self.post('/v1/auth/login', bad)
        self.assertEqual((status, error['code']), (401, 'INVALID_CREDENTIALS'))
        status, error = self.post('/v1/auth/login', bad)
        self.assertEqual((status, error['code']), (401, 'CHALLENGE_EXPIRED'))
        for _ in range(4):
            status, error = self.credentials('login', 'unitlock', 'incorrect-password', key)
            self.assertEqual((status, error['code']), (401, 'INVALID_CREDENTIALS'))
        status, error = self.credentials('login', 'unitlock', 'strong-password-1234', key)
        self.assertEqual((status, error['code']), (429, 'ACCOUNT_LOCKED'))
        with server.connection() as db:
            row = db.execute('SELECT locked_until FROM users WHERE username=?', ('unitlock',)).fetchone()
            self.assertGreater(row['locked_until'], int(time.time()))
        # Admin reset lock is separately controlled from the device key.
        with server.connection() as db:
            db.execute('UPDATE users SET locked_until=0 WHERE username=?', ('unitlock',))
        status, fresh = self.credentials('login', 'unitlock', 'strong-password-1234', key)
        self.assertEqual(status, 200)
        self.assertNotEqual(fresh['token'], first['token'])

    def test_password_rules_and_duplicate_challenge(self):
        key = Ed25519PrivateKey.generate()
        status, error = self.credentials('register', 'unitweak', 'weak', key)
        self.assertEqual((status, error['code']), (400, 'INVALID_PASSWORD'))
        status, ch = self.post('/v1/auth/challenge', {})
        self.assertEqual(status, 200)
        payload = {
            'username': 'unitreplay', 'password': 'strong-secret-password', 'devicePublic': public(key),
            'nonce': ch['nonce'], 'signature': signed(key, 'web2term-auth-v1\nregister\nunitreplay\n' + ch['nonce'])
        }
        status, _ = self.post('/v1/auth/register', payload)
        self.assertEqual(status, 200)
        status, data = self.post('/v1/auth/register', payload)
        self.assertEqual((status, data['code']), (401, 'CHALLENGE_EXPIRED'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
