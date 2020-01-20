import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.before_app_request
def load_loggied_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        c_password = request.form['password']

        db = get_db()
        error = None

        if not username:
            error = "User name should not be empty!"
        elif len(username)<4:
            error = "User name must be above 4 characters long!"
        elif not password:
            error = "Password should not be empty!"
        elif password!=c_password:
            error = "Password not matched!"
        elif db.execute('SELECT id FROM user WHERE username = ?', (username,)).fetchone() is not None:
            error = "Name {} already taken".format(username)

        if error is None:
            import random
            ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            chars = []
            for i in range(16):
                chars.append(random.choice(ALPHABET))
            salt = "".join(chars)

            from flask_bcrypt import Bcrypt
            bcrypt = Bcrypt()
            password = bcrypt.generate_password_hash(password+salt)

            db.execute('INSERT INTO user(username, password, salt) VALUES (?, ?, ?)', (username, password, salt))
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    from flask_bcrypt import Bcrypt
    bcrypt = Bcrypt()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not bcrypt.check_password_hash(user['password'], password+user['salt']):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))