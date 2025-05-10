import jwt
import datetime
import os

# Function to generate a JWT token
def generate_jwt(data):
    payload = {
        'email': data["email"],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm="HS256")
    # PyJWT sometimes returns bytes in old versions; decode if needed
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

# Function to decode and verify a JWT token
def decode_jwt(token):
    try:
        return jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
