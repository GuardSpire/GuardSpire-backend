import jwt
import datetime
import os

# Function to generate a JWT token
def generate_jwt(email):
    payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm="HS256")

# Function to decode and verify a JWT token
def decode_jwt(token):
    try:
        return jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
