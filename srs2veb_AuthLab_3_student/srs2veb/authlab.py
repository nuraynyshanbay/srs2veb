"""Run: python authlab.py init | add-user ... | serve"""
import argparse
import getpass
import html
import os
import sqlite3
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from authlab.authentication import create_user, authenticate
from authlab.sessions import (new_prelogin, use_prelogin, new_session, get_session,
                              check_csrf, logout, cookie)
from authlab.authorization import can_view_admin, list_own_notes, get_own_note, add_own_note

DB_PATH = os.getenv('AUTHLAB_DB', 'authlab.sqlite3')
HTTPS = os.getenv('AUTHLAB_HTTPS', '0') == '1'
SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student','teacher')));
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
 csrf_hash TEXT NOT NULL, csrf_token TEXT NOT NULL, created_at REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS prelogins (token_hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS login_failures (username TEXT PRIMARY KEY, count INTEGER NOT NULL,
 locked_until REAL NOT NULL);
'''


class LabConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def open_db(path=None):
    db = sqlite3.connect(path or DB_PATH, timeout=10, factory=LabConnection)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


def page(body):
    return ('<!doctype html><html lang="kk"><meta charset="utf-8">'
            '<title>AuthLab</title><body><h1>AuthLab</h1>' + body + '</body></html>')


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body='', headers=None):
        data = page(body).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        for key, value in (headers or []):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, path, headers=None):
        self.respond(303, 'Redirecting', [('Location', path)] + (headers or []))

    def token(self, name):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie', ''))
        except Exception:
            return ''
        key = ('__Host-' if HTTPS else '') + name
        return jar[key].value if key in jar else ''

    def form(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return {}
        if size < 0 or size > 10000:
            return {}
        return {key: values[0] for key, values in parse_qs(self.rfile.read(size).decode('utf-8', errors='replace'), keep_blank_values=True).items()}

    def do_GET(self):
        path = urlparse(self.path).path
        with open_db() as db:
            session = get_session(db, self.token('session'))
            if path in ('/', '/login'):
                if session:
                    return self.redirect('/dashboard')
                pre, csrf = new_prelogin(db)
                body = ('<form method="POST" action="/login"><input name="username" placeholder="Login">'
                        '<input type="password" name="password" placeholder="Password">'
                        f'<input type="hidden" name="csrf" value="{csrf}">'
                        '<button>Кіру</button></form>')
                return self.respond(200, body, [('Set-Cookie', cookie('prelogin', pre, HTTPS))])
            if not session:
                return self.redirect('/login')
            csrf = self.csrf_for(db, session)
            if path == '/dashboard':
                notes = ''.join(f'<li><a href="/notes/{r["id"]}">Note {r["id"]}</a>: {html.escape(r["body"])}</li>'
                                for r in list_own_notes(db, session['user_id']))
                body = (f'<p>Сәлем, {html.escape(session["username"])} ({html.escape(session["role"])})</p>'
                        f'<ul>{notes}</ul><form method="POST" action="/notes">'
                        f'<textarea name="body"></textarea><input type="hidden" name="csrf" value="{csrf}">'
                        '<button>Жазба қосу</button></form>'
                        f'<form method="POST" action="/logout"><input type="hidden" name="csrf" value="{csrf}">'
                        '<button>Шығу</button></form>')
                return self.respond(200, body)
            if path == '/admin/users':
                if not can_view_admin(session):
                    return self.respond(403, '403 Forbidden')
                users = ''.join('<li>'+html.escape(r['username'])+'</li>' for r in db.execute('SELECT username FROM users'))
                return self.respond(200, '<h2>Пайдаланушылар</h2><ul>'+users+'</ul>')
            if path.startswith('/notes/'):
                try:
                    note_id = int(path.split('/')[2])
                except (ValueError, IndexError):
                    return self.respond(404, '404 Not Found')
                note = get_own_note(db, session['user_id'], note_id)
                return self.respond(200, '<p>'+html.escape(note['body'])+'</p>') if note else self.respond(404, '404 Not Found')
            return self.respond(404, '404 Not Found')

    @staticmethod
    def csrf_for(db, session):
        # A random CSRF value is rendered only inside authenticated forms.
        return session['csrf_token']

    def do_POST(self):
        path = urlparse(self.path).path
        form = self.form()
        with open_db() as db:
            if path == '/login':
                if not use_prelogin(db, self.token('prelogin'), form.get('csrf', '')):
                    return self.respond(403, '403 CSRF')
                user = authenticate(db, form.get('username', ''), form.get('password', ''))
                if not user:
                    return self.respond(401, 'Логин немесе құпиясөз дұрыс емес')
                token, csrf = new_session(db, user['id'])
                return self.redirect('/dashboard', [('Set-Cookie', cookie('session', token, HTTPS)),
                                                    ('Set-Cookie', cookie('prelogin', '', HTTPS, clear=True))])
            token = self.token('session')
            session = get_session(db, token)
            if not session:
                return self.redirect('/login')
            if not check_csrf(session, form.get('csrf', '')):
                return self.respond(403, '403 CSRF')
            if path == '/logout':
                logout(db, token)
                return self.redirect('/login', [('Set-Cookie', cookie('session', '', HTTPS, clear=True))])
            if path == '/notes':
                try:
                    add_own_note(db, session['user_id'], form.get('body', ''))
                except ValueError:
                    return self.respond(400, 'Invalid note')
                return self.redirect('/dashboard')
            return self.respond(404, '404 Not Found')


def main():
    parser = argparse.ArgumentParser(description='AuthLab local security demo')
    parser.add_argument('command', choices=['init', 'add-user', 'serve'])
    parser.add_argument('--username')
    parser.add_argument('--role', choices=['student','teacher'], default='student')
    args = parser.parse_args()
    if args.command == 'init':
        with open_db() as db: pass
        print('Database initialized:', DB_PATH)
    elif args.command == 'add-user':
        if not args.username:
            parser.error('--username required')
        password = getpass.getpass('Password (8+ chars): ')
        with open_db() as db:
            create_user(db, args.username, password, args.role)
        print('User added:', args.username)
    else:
        print('Open http://127.0.0.1:8000/login')
        ThreadingHTTPServer(('127.0.0.1', 8000), Handler).serve_forever()


if __name__ == '__main__':
    main()
