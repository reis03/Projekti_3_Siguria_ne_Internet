import pyotp


class TwoFactorAuth:
    def generate_qr_code(self, account_name, secret_key):
        otp_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=account_name, issuer_name="Super app")
        return otp_uri

    def verify_otp(self, secret_key, otp):
        totp = pyotp.TOTP(secret_key)
        return totp.verify(otp)
