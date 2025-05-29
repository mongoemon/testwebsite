from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
    conn.commit()
    conn.close()

@app.route('/', methods=['GET', 'POST'])
def login():
    # 🔁 Redirect logged-in users or guests straight to dashboard
    if 'username' in session:
        return redirect(url_for('dashboard'))

    error = None
    if request.method == 'POST':
        if 'guest' in request.form:
            session['username'] = 'Guest'
            session['is_guest'] = True
            return redirect(url_for('dashboard'))
        else:
            username = request.form['username']
            password = request.form['password']
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('SELECT password FROM users WHERE username=?', (username,))
            result = c.fetchone()
            conn.close()
            if result and check_password_hash(result[0], password):
                session['username'] = username
                session['is_guest'] = False
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid username or password"

    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "Username already exists"
    return render_template('register.html', error=error)

@app.route('/dashboard')
def dashboard():
    # Ensure user has come through login or guest login
    if not session.get('username') or not ('is_guest' in session or session.get('is_guest') is False):
        return render_template('blocked.html')
    return render_template(
        'dashboard.html',
        username=session['username'],
        is_guest=session.get('is_guest', False)
    )


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
