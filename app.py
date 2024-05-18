# Import necessary libraries
from flask import Flask, request, render_template, redirect, url_for, jsonify
import pyotp
from two_factor_auth import TwoFactorAuth

# Initialize Flask app
app = Flask(__name__, template_folder='templates')

# Initialize TwoFactorAuth instance
tfa = TwoFactorAuth()

# Define routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    # Get username and password from form
    username = request.form.get("username")
    password = request.form.get("password")

    # Here you would validate the username and password with your database
    # For simplicity, let's assume the user is valid and redirect to 2FA setup

    # Check if the user is logging in for the first time and enable 2FA
    # For demonstration, let's assume it's the first login and redirect to 2FA setup

    return redirect(url_for('setup_2fa', account_name=username))

@app.route("/setup_2fa/<account_name>")
def setup_2fa(account_name):
    # Generate a random secret key
    secret_key = pyotp.random_base32()

    # Generate QR code URL using TwoFactorAuth
    qr_code_url = tfa.generate_qr_code(account_name, secret_key)

    # Render a template to show the QR code to the user
    return render_template("setup_2fa.html", qr_code_url=qr_code_url, secret_key=secret_key)

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    # Get secret key and OTP from request data
    data = request.get_json()
    secret_key = data.get("secret_key", "")
    otp = data.get("otp", "")

    # Verify OTP using TwoFactorAuth
    is_valid = tfa.verify_otp(secret_key, otp)

    # Return OTP verification result as JSON response
    return jsonify({"is_valid": is_valid})

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
