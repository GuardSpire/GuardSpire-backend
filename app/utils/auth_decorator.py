from functools import wraps
from flask import request, jsonify
import jwt
import os

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Step 1: Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({"error": "Missing Authorization header"}), 401

        try:
            # Step 2: Decode token using your JWT secret key
            decoded_token = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
            current_user_email = decoded_token["email"]

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            return jsonify({"error": str(e)}), 401

        # Step 3: Pass user email as dictionary to the route
        return f({"email": current_user_email}, *args, **kwargs)

    return decorated
