import random

# Store OTPs in this format: { email: {"otp": ..., "type": "mfa" or "reset"} }
otp_store = {}

# 1. Generate a 6-digit OTP with purpose (mfa or reset)
def generate_otp(email, purpose):
    otp = str(random.randint(100000, 999999))
    otp_store[email] = {
        "otp": otp,
        "type": purpose
    }
    return otp

# 2. Verify OTP by email, entered OTP, and expected purpose
def verify_otp(email, otp, expected_purpose):
    entry = otp_store.get(email)
    if entry and entry["otp"] == otp and entry["type"] == expected_purpose:
        del otp_store[email]  # Clean up after successful match
        return True
    return False
