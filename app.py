# Import necessary libraries
from flask import Flask, request, render_template, redirect, url_for, jsonify, flash
import pyotp
import sqlite3
from two_factor_auth import TwoFactorAuth
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = 'your_secret_key'

# Initialize TwoFactorAuth instance
tfa = TwoFactorAuth()

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            secret_key TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Define routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = generate_password_hash(request.form['password'])

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, password))
        conn.commit()
        flash('Signup successful!', 'success')
    except sqlite3.IntegrityError:
        flash('Username or email already exists!', 'error')
    finally:
        conn.close()

    return redirect(url_for('index'))

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[3], password):
        if not user[4]:  # Check if the user has a secret key (2FA enabled)
            return redirect(url_for('setup_2fa', account_name=username))
        else:
            return redirect(url_for('verify_2fa', account_name=username))
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))

@app.route("/setup_2fa/<account_name>")
def setup_2fa(account_name):
    secret_key = pyotp.random_base32()
    qr_code_url = tfa.generate_qr_code(account_name, secret_key)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET secret_key = ? WHERE username = ?', (secret_key, account_name))
    conn.commit()
    conn.close()

    return render_template("setup_2fa.html", qr_code_url=qr_code_url, secret_key=secret_key)

@app.route("/verify_2fa/<account_name>", methods=["GET", "POST"])
def verify_2fa(account_name):
    if request.method == "POST":
        otp = request.form['otp']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT secret_key FROM users WHERE username = ?', (account_name,))
        user = c.fetchone()
        conn.close()

        if user and tfa.verify_otp(user[0], otp):
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid OTP', 'error')

    return render_template("verify_otp.html", account_name=account_name)

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    secret_key = data.get("secret_key", "")
    otp = data.get("otp", "")

    is_valid = tfa.verify_otp(secret_key, otp)
    return jsonify({"is_valid": is_valid})

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
