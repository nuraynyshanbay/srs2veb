"""Student 3: seventeen security checks; no external dependencies."""
import http.client
import importlib.util
import os
import re
import sqlite3
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

from authlab.authentication import create_user, authenticate, verify_password
from authlab.sessions import new_session, get_session
from authlab.authorization import get_own_note

ROOT = os.path.dirname(os.path.dirname(__file__))
spec = importlib.util.spec_from_file_location('authlab_main', os.path.join(ROOT, 'authlab.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class AuthLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
        tmp.close()
        cls.db_file = tmp.name
        app.DB_PATH = cls.db_file
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        with app.open_db() as db:
            create_user(db, 'alice', 'alicepass123')
            create_user(db, 'bob', 'bobpass123')
            create_user(db, 'teacher', 'teacherpass123', 'teacher')
            db.execute("INSERT INTO notes(owner_id,body) VALUES(1,'<script>alert(1)</script>')")
            db.commit()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        os.unlink(cls.db_file)

    def request(self, method, path, data=None, cookie=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {}
        if cookie:
            headers['Cookie'] = cookie
        if data is not None:
            data = urlencode(data)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        body = response.read().decode('utf-8')
        result = (response.status, response.headers, body)
        conn.close()
        return result

    def login(self, username='alice', password='alicepass123'):
        status, headers, body = self.request('GET', '/login')
        self.assertEqual(status, 200)
        pre = headers.get('Set-Cookie').split(';')[0]
        csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
        result = self.request('POST', '/login', {'username': username, 'password': password, 'csrf': csrf}, pre)
        session_cookie = result[1].get_all('Set-Cookie')[0].split(';')[0] if result[0] == 303 else ''
        return result, session_cookie, pre, csrf

    def csrf(self, cookie):
        status, _, body = self.request('GET', '/dashboard', cookie=cookie)
        self.assertEqual(status, 200)
        return re.search(r'name="csrf" value="([^"]+)"', body).group(1)

    def test_01_anonymous_dashboard(self):
        self.assertEqual(self.request('GET', '/dashboard')[0:1], (303,))

    def test_02_password_hash_pbkdf2(self):
        with app.open_db() as db:
            row = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
            self.assertTrue(row['password_hash'].startswith('pbkdf2_sha256$'))
            self.assertTrue(verify_password('alicepass123', row['password_hash']))

    def test_03_wrong_password(self):
        self.assertEqual(self.login(password='incorrect')[0][0], 401)

    def test_04_login_without_csrf(self):
        self.assertEqual(self.request('POST', '/login', {'username':'alice','password':'alicepass123'})[0], 403)

    def test_05_cookie_flags(self):
        r, _, _, _ = self.login()
        value = r[1].get_all('Set-Cookie')[0]
        self.assertIn('HttpOnly', value)
        self.assertIn('SameSite=Lax', value)

    def test_06_session_fixation(self):
        _, new_cookie, pre, _ = self.login()
        self.assertNotEqual(pre, new_cookie)
        self.assertEqual(self.request('GET','/dashboard',cookie=pre)[0],303)

    def test_07_role_admin(self):
        _, student, _, _ = self.login()
        _, teacher, _, _ = self.login('teacher','teacherpass123')
        self.assertEqual(self.request('GET','/admin/users',cookie=student)[0],403)
        self.assertEqual(self.request('GET','/admin/users',cookie=teacher)[0],200)

    def test_08_idor_other_note(self):
        _, bob, _, _ = self.login('bob','bobpass123')
        self.assertEqual(self.request('GET','/notes/1',cookie=bob)[0],404)

    def test_09_note_csrf_required(self):
        _, cookie, _, _ = self.login()
        self.assertEqual(self.request('POST','/notes', {'body':'hello'},cookie)[0],403)
        self.assertEqual(self.request('POST','/notes', {'body':'hello','csrf':self.csrf(cookie)},cookie)[0],303)

    def test_10_logout_revokes_session(self):
        _, cookie, _, _ = self.login()
        self.assertEqual(self.request('POST','/logout', {'csrf':self.csrf(cookie)},cookie)[0],303)
        self.assertEqual(self.request('GET','/dashboard',cookie=cookie)[0],303)

    def test_11_idle_timeout(self):
        with app.open_db() as db:
            t,_ = new_session(db,1,now=1000)
            self.assertIsNone(get_session(db,t,now=2200))

    def test_12_absolute_timeout(self):
        with app.open_db() as db:
            t,_ = new_session(db,1,now=1000)
            db.execute('UPDATE sessions SET last_seen=? WHERE token_hash=(SELECT token_hash FROM sessions WHERE user_id=1 ORDER BY created_at DESC LIMIT 1)',(15000,))
            db.commit()
            self.assertIsNone(get_session(db,t,now=15400))

    def test_13_xss_html_escaped(self):
        _, cookie, _, _ = self.login()
        status, _, body = self.request('GET','/notes/1',cookie=cookie)
        self.assertEqual(status,200)
        self.assertIn('&lt;script&gt;',body)
        self.assertNotIn('<script>',body)

    def test_14_five_failures_lock(self):
        with app.open_db() as db:
            for _ in range(5):
                self.assertIsNone(authenticate(db,'bob','badpassword',now=100))
            self.assertIsNone(authenticate(db,'bob','bobpass123',now=101))
            self.assertIsNotNone(authenticate(db,'bob','bobpass123',now=401))

    def test_15_sql_injection_login(self):
        r, _, _, _ = self.login("alice' OR '1'='1",'bad')
        self.assertEqual(r[0],401)

    def test_16_security_headers(self):
        _, h, _ = self.request('GET','/login')
        self.assertIn('Content-Security-Policy',h)
        self.assertEqual(h.get('Cache-Control'),'no-store')
        self.assertEqual(h.get('X-Content-Type-Options'),'nosniff')

    def test_17_secure_cookie_https_mode(self):
        from authlab.sessions import cookie
        result = cookie('session','test',https=True)
        self.assertIn('Secure',result)
        self.assertIn('__Host-session=',result)


if __name__ == '__main__':
    unittest.main()
