# Import necessary libraries
from flask import Flask, request, jsonify, render_template
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

@app.route("/generate_qr_code", methods=["POST"])
def generate_qr_code():
    # Get account name from request data
    data = request.get_json()
    account_name = data.get("account_name", "")

    # Generate a random secret key
    secret_key = pyotp.random_base32()

    # Generate QR code URL using TwoFactorAuth
    qr_code_url = tfa.generate_qr_code(account_name, secret_key)

    # Return QR code URL and secret key as JSON response
    return jsonify({"qr_code_url": qr_code_url, "secret_key": secret_key})

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
