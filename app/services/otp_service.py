import random

otp_store = {}

def generate_otp(email, purpose):
    if isinstance(email, dict):  # ✅ Handle dict email too
        email = email.get('email', '')
    otp = str(random.randint(100000, 999999))
    otp_store[email] = {
        "otp": otp,
        "type": purpose
    }
    return otp

def verify_otp(email, otp, expected_purpose):
    if isinstance(email, dict):  # ✅ Handle dict email too
        email = email.get('email', '')
    entry = otp_store.get(email)
    if entry and entry["otp"] == otp and entry["type"] == expected_purpose:
        del otp_store[email]
        return True
    return False
