import functools

from flask import (
        Blueprint, flash, g, redirect, render_template, request, session, url_for
        )
from werkzeug.security import check_password_hash, generate_password_hash

from SshGuard.db import get_db

from datetime import datetime

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM guard WHERE id = ?', (user_id,)
        ).fetchone()

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        sshuser = request.form['sshuser']
        allowed = 0
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not sshuser:
            error = 'sshuser is required.'
        elif db.execute(
                'SELECT id FROM guard WHERE username = ?', (username,)
                ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute(
                    'INSERT INTO guard (username, sshuser, allowed, activated) VALUES (?, ?, ?, ?)',
                    (username, sshuser, allowed,datetime.now())
                    )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM guard WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']

            allowed = 99 
            _ret = db.execute("UPDATE guard SET allowed = ? WHERE id = ?", (allowed, user['id']))
            db.commit()
            _ret = db.execute("UPDATE guard SET activated = ? WHERE id = ?", (datetime.now(), user['id']))
            db.commit()

            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/login.html')

@bp.route('/logout')
def logout():

    db = get_db()
    error = None
    user_id = str(session.get('user_id'))
    user = db.execute(
        'SELECT * FROM guard WHERE username = ?', (user_id)
    ).fetchone()

    if user is None:
        error = 'Incorrect username.'

    if error is None:
        session.clear()
        allowed = 0
        _ret = db.execute("UPDATE guard SET allowed = ? WHERE id = ?", (allowed, user['id']))
        db.commit()

    return redirect(url_for('index'))

@bp.route('/status')
def status():
    db = get_db()
    error = None
    _status = db.execute("SELECT * FROM guard")
    db.commit()

    return render_template('auth/status.html')

