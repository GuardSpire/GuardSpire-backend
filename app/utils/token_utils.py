import jwt
import datetime
import os

def create_token(email):
    payload = {
        "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)  # 7 days expiry
    }
    token = jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm="HS256")
    return token
