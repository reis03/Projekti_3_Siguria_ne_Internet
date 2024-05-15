import pyotp

class TwoFactorAuth:
    @staticmethod
    def generate_otp(secret_key):
        totp = pyotp.TOTP(secret_key)
        return totp.now()

    @staticmethod
    def generate_qr_code(account_name, secret_key):
        totp = pyotp.TOTP(secret_key)
        return totp.provisioning_uri(name=account_name, issuer_name="YourApp")

    @staticmethod
    def verify_otp(secret_key, otp):
        totp = pyotp.TOTP(secret_key)
        return totp.verify(otp)
