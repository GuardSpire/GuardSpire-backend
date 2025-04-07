from flask import Blueprint, request, jsonify
from app.services.firebase_service import auth
from app.services.jwt_service import generate_jwt
from app.services.otp_service import generate_otp, verify_otp

auth_bp = Blueprint('auth', __name__)

#-------------------Signup--------------------#
@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    try:
        # 1. Create user in Firebase using email + password
        auth.create_user_with_email_and_password(data['email'], data['password'])

        # 2. Generate an OTP for email verification (purpose = "mfa" or "verify")
        otp = generate_otp(data['email'], "mfa")

        # 3. Return a success message (in real world, email the OTP)
        return jsonify({
            'message': 'User registered. Verify OTP.',
            'otp': otp
        }), 201

    except Exception as e:
        # Handle Firebase errors
        return jsonify({'error': str(e)}), 400
    

#-------------------SignIn--------------------#
@auth_bp.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()

    try:
        # 1. Try to sign in with Firebase
        auth.sign_in_with_email_and_password(data['email'], data['password'])

        # 2. If credentials are correct, generate OTP for 2FA
        otp = generate_otp(data['email'], "mfa")

        # 3. Return response
        return jsonify({
            'message': 'Login successful. Enter OTP to continue.',
            'otp': otp
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 401

#-------------------Verify OTP & JWT--------------------#
@auth_bp.route('/verify-otp', methods=['POST'])
def verify():
    data = request.get_json()

    email = data.get('email')
    otp = data.get('otp')

    # Check OTP and purpose (MFA login)
    if verify_otp(email, otp, "mfa"):
        token = generate_jwt(email)
        return jsonify({
            'message': 'OTP verified successfully.',
            'token': token
        }), 200
    else:
        return jsonify({
            'error': 'Invalid OTP or purpose.'
        }), 403
