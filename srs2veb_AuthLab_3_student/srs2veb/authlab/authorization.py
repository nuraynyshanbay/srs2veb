"""Student 3: role and ownership checks preventing privilege escalation and IDOR."""


def can_view_admin(session):
    return bool(session and session['role'] == 'teacher')


def list_own_notes(conn, user_id):
    return conn.execute('SELECT id, body FROM notes WHERE owner_id=? ORDER BY id', (user_id,)).fetchall()


def get_own_note(conn, user_id, note_id):
    # ID and owner are BOTH checked on the server, not just in the browser.
    return conn.execute('SELECT id, body FROM notes WHERE id=? AND owner_id=?', (note_id, user_id)).fetchone()


def add_own_note(conn, user_id, body):
    if not body.strip() or len(body) > 2000:
        raise ValueError('Note must have 1..2000 characters')
    conn.execute('INSERT INTO notes(owner_id,body) VALUES(?,?)', (user_id, body))
    conn.commit()
