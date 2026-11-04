"""Student 1: authentication, password hashing, login throttling."""
import hashlib
import hmac
import os
import time

ITERATIONS = int(os.getenv('AUTHLAB_PBKDF2_ITERATIONS', '600000'))


def hash_password(password, iterations=None):
    count = ITERATIONS if iterations is None else iterations
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, count)
    return f'pbkdf2_sha256${count}${salt.hex()}${digest.hex()}'


def verify_password(password, encoded):
    try:
        scheme, iterations, salt_hex, hashed_hex = encoded.split('$')
        if scheme != 'pbkdf2_sha256':
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(actual, bytes.fromhex(hashed_hex))
    except (ValueError, TypeError):
        return False


def create_user(conn, username, password, role='student'):
    if role not in ('student', 'teacher'):
        raise ValueError('Invalid role')
    if not username or len(username) > 60 or len(password) < 8:
        raise ValueError('Username required and password must have 8+ characters')
    conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                 (username, hash_password(password), role))
    conn.commit()


def authenticate(conn, username, password, now=None):
    now = time.time() if now is None else now
    row = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    failure = conn.execute('SELECT count, locked_until FROM login_failures WHERE username=?', (username,)).fetchone()
    if failure and failure['locked_until'] > now:
        return None
    # Apply the same PBKDF2 algorithm even for an unknown login.
    dummy = f'pbkdf2_sha256${ITERATIONS}$' + '00'*16 + '$' + hashlib.pbkdf2_hmac('sha256', b'dummy', bytes(16), ITERATIONS).hex()
    valid = verify_password(password, row['password_hash'] if row else dummy)
    if row and valid:
        conn.execute('DELETE FROM login_failures WHERE username=?', (username,))
        conn.commit()
        return row
    count = (failure['count'] if failure else 0) + 1
    locked = now + 300 if count >= 5 else 0
    conn.execute('INSERT INTO login_failures(username,count,locked_until) VALUES(?,?,?) '
                 'ON CONFLICT(username) DO UPDATE SET count=excluded.count, locked_until=excluded.locked_until',
                 (username, count, locked))
    conn.commit()
    return None
