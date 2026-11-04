"""Student 2: server sessions, cookie policy and CSRF protections."""
import hashlib
import hmac
import secrets
import time

IDLE_LIMIT = 20 * 60
ABSOLUTE_LIMIT = 4 * 60 * 60
PRELOGIN_LIMIT = 10 * 60


def digest(token):
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def new_token():
    return secrets.token_urlsafe(32)


def new_prelogin(conn, now=None):
    now = time.time() if now is None else now
    token, csrf = new_token(), new_token()
    conn.execute('INSERT INTO prelogins(token_hash, csrf_hash, created_at) VALUES(?,?,?)',
                 (digest(token), digest(csrf), now))
    conn.commit()
    return token, csrf


def use_prelogin(conn, token, csrf, now=None):
    now = time.time() if now is None else now
    row = conn.execute('SELECT * FROM prelogins WHERE token_hash=?', (digest(token),)).fetchone() if token else None
    if not row or now-row['created_at'] > PRELOGIN_LIMIT or not hmac.compare_digest(row['csrf_hash'], digest(csrf)):
        return False
    conn.execute('DELETE FROM prelogins WHERE token_hash=?', (digest(token),))
    conn.commit()
    return True


def new_session(conn, user_id, now=None):
    now = time.time() if now is None else now
    token, csrf = new_token(), new_token()
    conn.execute('INSERT INTO sessions(token_hash, user_id, csrf_hash, csrf_token, created_at, last_seen) VALUES(?,?,?,?,?,?)',
                 (digest(token), user_id, digest(csrf), csrf, now, now))
    conn.commit()
    return token, csrf


def get_session(conn, token, now=None):
    if not token:
        return None
    now = time.time() if now is None else now
    row = conn.execute('SELECT sessions.*, users.username, users.role FROM sessions JOIN users '
                       'ON users.id=sessions.user_id WHERE token_hash=?', (digest(token),)).fetchone()
    if not row:
        return None
    if now-row['last_seen'] >= IDLE_LIMIT or now-row['created_at'] >= ABSOLUTE_LIMIT:
        conn.execute('DELETE FROM sessions WHERE token_hash=?', (digest(token),))
        conn.commit()
        return None
    conn.execute('UPDATE sessions SET last_seen=? WHERE token_hash=?', (now, digest(token)))
    conn.commit()
    return row


def check_csrf(session, csrf):
    return bool(session and csrf and hmac.compare_digest(session['csrf_hash'], digest(csrf)))


def logout(conn, token):
    conn.execute('DELETE FROM sessions WHERE token_hash=?', (digest(token),))
    conn.commit()


def cookie(name, value, https=False, clear=False):
    prefix = '__Host-' if https else ''
    parts = [f'{prefix}{name}={value}', 'Path=/', 'HttpOnly', 'SameSite=Lax']
    if https:
        parts.append('Secure')
    if clear:
        parts.append('Max-Age=0')
    return '; '.join(parts)
