from flask import Blueprint, request, jsonify
from app.services.firebase_service import db
from app.services.firebase_service import auth
from app.services.jwt_service import generate_jwt
from app.utils.auth_decorator import token_required
from app.services.otp_service import generate_otp, verify_otp

auth_bp = Blueprint('auth', __name__)

# ------------------ Signup ------------------ #
@auth_bp.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data['email']
        username = data['username']
        password = data['password']

        email_key = email.replace('.', '_').replace('@', '_')

        # Save user data into Realtime Database
        db.child("user_info").child(email_key).set({
            "username": username,
            "email": email,
            "password": password
        })

        # ✅ Generate OTP for signup
        otp = generate_otp(email, "signup")

        return jsonify({"message": "Signup successful. OTP sent", "otp": otp}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------ SignIn ------------------ #
@auth_bp.route('/signin', methods=['POST'])
def signin():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        email_key = email.replace('.', '_').replace('@', '_')

        user_record = db.child("user_info").child(email_key).get().val()

        if not user_record:
            return jsonify({"error": "User not found"}), 404

        if user_record.get("password") != password:
            return jsonify({"error": "Incorrect password"}), 403

        # ✅ Generate OTP for login
        otp = generate_otp(email, "login")

        return jsonify({"message": "Sign in successful", "otp": otp}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------ OTP Verification ------------------ #
@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    try:
        data = request.get_json()
        email = data['email']
        otp = data['otp']
        purpose = data.get('purpose')  # ✅ now expecting purpose too!

        if not all([email, otp, purpose]):
            return jsonify({"error": "Missing fields"}), 400

        verified = verify_otp(email, otp, purpose)

        if not verified:
            return jsonify({"error": "Invalid OTP or purpose."}), 403

        # ✅ Correct: generate JWT token
        token = generate_jwt({"email": email})

        return jsonify({"message": "OTP verified successfully", "token": token}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
