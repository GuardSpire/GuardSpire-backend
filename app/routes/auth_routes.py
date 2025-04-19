from flask import Blueprint, request, jsonify
from app.services.firebase_service import db
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

        # 2. Save the username in user_info
        email = data['email']
        username = data.get('username', '')
        email_key = email.replace('.', '_').replace('@', '_')
        db.child("user_info").child(email_key).set({
            "email": email,
            "username": username
        })

        # 3. Generate an OTP for email verification
        otp = generate_otp(email, "mfa")

        # 4. Return success response
        return jsonify({
            'message': 'User registered. Verify OTP.',
            'otp': otp
        }), 201

    except Exception as e:
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

#-------------------Foregt Password-------------------#
@auth_bp.route('/forgot-password/request', methods=['POST'])
def forgot_password_request():
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"error": "Email is required"}), 400

        otp = generate_otp(email, "forgot")
        return jsonify({"message": "OTP sent for password reset", "otp": otp}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@auth_bp.route('/forgot-password/reset', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        email = data.get("email")
        otp = data.get("otp")
        new_password = data.get("newPassword")
        confirm_password = data.get("confirmPassword")

        if not all([email, otp, new_password, confirm_password]):
            return jsonify({"error": "All fields are required"}), 400

        if new_password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        # ✅ Verify OTP
        if not verify_otp(email, otp, "forgot"):
            return jsonify({"error": "Invalid OTP"}), 403

        email_key = email.replace(".", "_").replace("@", "_")

        # ✅ Update password in Realtime DB
        db.child("user_info").child(email_key).update({"password": new_password})

        return jsonify({"message": "Password reset successful"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
