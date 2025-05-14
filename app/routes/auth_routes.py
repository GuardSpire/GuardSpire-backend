from flask import Blueprint, request, jsonify
from app.services.firebase_service import db
from app.services.firebase_service import auth
from app.services.jwt_service import generate_jwt
from app.utils.auth_decorator import token_required
from app.services.otp_service import generate_otp, verify_otp
import re

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

        # ✅ Save TEMP user data in Firebase (not actual users yet)
        db.child("temp_users").child(email_key).set({
            "username": username,
            "email": email,
            "password": password
        })

        # ✅ Generate OTP for signup
        otp = generate_otp(email, "signup")

        print(f"🔥[DEBUG] OTP for {email}: {otp}🔥")

        return jsonify({"message": "Signup initiated. OTP sent", "otp": otp}), 201

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

        print(f"🔥[DEBUG] OTP for {email}: {otp}🔥")

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
        purpose = data.get('purpose')

        print(f"[DEBUG] Verifying OTP for: {email}, OTP: {otp}, Purpose: {purpose}")

        if not all([email, otp, purpose]):
            return jsonify({"error": "Missing fields"}), 400

        verified = verify_otp(email, otp, purpose)

        if not verified:
            print("[DEBUG] OTP verification failed.")
            return jsonify({"error": "Invalid OTP or purpose."}), 403

        email_key = email.replace('.', '_').replace('@', '_')

        # ✅ If it's signup, transfer temp user to permanent storage
        if purpose == "signup":
            temp_user = db.child("temp_users").child(email_key).get().val()

            if not temp_user:
                return jsonify({"error": "No temporary signup data found."}), 404

            # Save to actual user_info
            db.child("user_info").child(email_key).set(temp_user)

            # Cleanup temp data
            db.child("temp_users").child(email_key).remove()

        # ✅ Issue JWT token (login or signup)
        token = generate_jwt({"email": email})

        return jsonify({"message": "OTP verified successfully", "token": token}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------- Forgot Password: Request OTP ------------------- #
@auth_bp.route('/forgot-password/request', methods=['POST'])
def forgot_password_request():
    try:
        data = request.get_json()
        email = data.get("email")

        # ✅ Validate email format
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({"error": "A valid email is required"}), 400

        email_key = email.replace(".", "_").replace("@", "_")
        user_data = db.child("user_info").child(email_key).get().val()

        # ✅ Check if email exists
        if not user_data:
            return jsonify({"error": "Email not found"}), 404

        otp = generate_otp(email, "forgot")
        print(f"🔥Generated OTP for forgot password request: {otp}🔥")

        return jsonify({"message": "OTP sent for password reset", "otp": otp}), 200

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500


# ------------------- Forgot Password: Verify OTP ------------------- #
@auth_bp.route('/forgot-password/verify-otp', methods=['POST'])
def verify_forgot_password_otp():
    try:
        data = request.get_json()
        email = data.get("email")
        otp = data.get("otp")

        if not email or not otp:
            return jsonify({"error": "Email and OTP are required"}), 400

        # Print the OTP for debugging
        print(f"🔥 Verifying OTP for email: {email}, OTP: {otp}")

        if not verify_otp(email, otp, "forgot"):
            print(f"❌ Invalid OTP provided: {otp}")
            return jsonify({"error": "Invalid OTP"}), 403

        print(f"✅ OTP verified successfully for email: {email}")
        return jsonify({"message": "OTP verified"}), 200

    except Exception as e:
        print(f"❌ Exception occurred during OTP verification: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


# ------------------- Forgot Password: Reset Password ------------------- #
@auth_bp.route('/forgot-password/reset', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        email = data.get("email")
        new_password = data.get("newPassword")
        confirm_password = data.get("confirmPassword")

        if not all([email, new_password, confirm_password]):
            return jsonify({"error": "All fields are required"}), 400

        if new_password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        # 🔍 Search under user_info to find the correct key
        all_users = db.child("user_info").get().val()
        matched_key = None

        for key, value in all_users.items():
            if value.get("email") == email:
                matched_key = key
                break

        if not matched_key:
            return jsonify({"error": "User not found"}), 404

        # ✅ Update password under the correct node
        db.child("user_info").child(matched_key).update({"password": new_password})

        return jsonify({"message": "Password reset successful"}), 200

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
