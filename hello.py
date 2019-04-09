import os
import datetime
import hashlib
import bcrypt
import sys
from flask import Flask, flash, redirect, render_template, request, session, abort
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

engine = create_engine(os.getenv('DATABASE_URL'))
db = scoped_session(sessionmaker(bind=engine))

app = Flask(__name__)

def libhasher(password_string):
    libhashed_pw = hashlib.md5(password_string.encode()).hexdigest().encode()
    return libhashed_pw

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        print(str(type(session['username'])), file=sys.stderr)
        print(str(session['username']), file=sys.stderr)
        print(str(type(session['nickname'])), file=sys.stderr)
        print(str(session['nickname']), file=sys.stderr)
        return render_template('user_panel.html')


@app.route('/register', methods=['POST'])
def register():
    form_username = request.form['username']
    form_password = request.form['password']
    confirm_password = request.form['confirm_password']
    if db.execute('SELECT * FROM users WHERE user_name = :username', {'username': form_username}).rowcount >= 1:
        return "Username alread taken, please go back and choose a different user name"
    if len(form_password) < 4:
        return "Password too short.  Please use at least 4 characters"
    if form_password != confirm_password:
        return "Passwords do not match.  Please go back and try again."
    pwhash = bcrypt.hashpw(libhasher(form_password), bcrypt.gensalt()).decode()
    db.execute('INSERT INTO users (user_name, password) VALUES (:name, :pass)', {'name': form_username, 'pass': pwhash})
    db.commit()
    return "Registration successful"

@app.route('/login', methods=['POST'])
def login():
    form_username = request.form['username']
    form_password = request.form['password']
    user = db.execute('SELECT * FROM users WHERE user_name = :username', {'username': form_username}).fetchone()
    if user is None:
        return "User name not found.  Please go back and try again."
    db_pass = user.password.encode()
    if bcrypt.checkpw(libhasher(form_password), db_pass):
        session['logged_in'] = True
        session['username'] = user.user_name
        session['nickname'] = user.nickname
        return home()
    else:
        return "Wrong credentials.  Please go back and try again."

@app.route('/update', methods=['POST'])
def update():
    form_nickname = request.form['nickname']
    db.execute('UPDATE users SET nickname = :nickname WHERE user_name = :session_username', {'nickname': form_nickname, 'session_username': session["username"]})
    db.commit()
    session['nickname'] = db.execute('SELECT nickname FROM users WHERE user_name = :session_username', {'session_username': session["username"]}).first()['nickname']
    return home()

@app.route('/logout')
def logout():
    session['logged_in'] = False
    return home()

if __name__ == '__main__':
    app.secret_key = os.urandom(12)
    app.run()