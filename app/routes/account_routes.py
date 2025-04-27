from flask import Blueprint, request, jsonify
from app.services.firebase_service import db, auth
from app.utils.auth_decorator import token_required
from app.services.otp_service import generate_otp, verify_otp

account_bp = Blueprint('account', __name__)

# ----------- Update Username (No OTP) -----------
@account_bp.route('/update-info', methods=['PUT'])
@token_required
def update_user_info(current_user):
    try:
        email = current_user["email"]
        
        # Fix: If current_user is wrongly passed as dict with {"email": {"email": ...}}
        if isinstance(email, dict) and "email" in email:
            email = email["email"]

        email_key = email.replace(".", "_").replace("@", "_")
        
        data = request.get_json()
        current_username = data.get("currentUsername")
        new_username = data.get("newUsername")

        if not current_username or not new_username:
            return jsonify({"error": "Current and new usernames are required."}), 400

        # Fetch existing user data correctly
        user_info = db.child("user_info").child(email_key).get().val()
        if not user_info:
            return jsonify({"error": "User not found"}), 404

        stored_username = user_info.get("username")
        if current_username != stored_username:
            return jsonify({"error": "Current username is incorrect"}), 403

        # Update only inside user node
        db.child("user_info").child(email_key).update({
            "username": new_username
        })

        return jsonify({"message": "Username updated successfully."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

# ----------- Request OTP for Email/Password Update -----------
@account_bp.route('/request-otp-update', methods=['POST'])
@token_required
def request_otp_for_update(current_user):
    try:
        email = current_user['email']
        if isinstance(email, dict):  # ✅ FIX added
            email = email.get('email', '')

        data = request.get_json()
        update_type = data.get("type")  # "email" or "password"

        if update_type not in ["email", "password"]:
            return jsonify({"error": "Invalid update type"}), 400

        otp = generate_otp(email, update_type)
        return jsonify({
            "message": f"OTP sent for {update_type} update",
            "otp": otp
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------- Verify OTP and Apply Email/Password Update -----------
@account_bp.route('/verify-update-otp', methods=['POST'])
@token_required
def verify_update_otp(current_user):
    try:
        email = current_user["email"]

        # Fix if email dict issue
        if isinstance(email, dict) and "email" in email:
            email = email["email"]

        data = request.get_json()

        otp = data.get("otp")
        update_type = data.get("type")

        if not verify_otp(email, otp, update_type):
            return jsonify({"error": "Invalid OTP"}), 403

        email_key = email.replace(".", "_").replace("@", "_")
        
        if update_type == "email":
            current_email = data.get("currentEmail")
            new_email = data.get("newEmail")

            if not current_email or not new_email:
                return jsonify({"error": "Both current and new emails are required"}), 400

            if email != current_email:
                return jsonify({"error": "Current email does not match the logged-in user"}), 400

            new_email_key = new_email.replace(".", "_").replace("@", "_")

            # Fetch current user data
            user_data = db.child("user_info").child(email_key).get().val()
            if not user_data:
                return jsonify({"error": "User profile not found"}), 404

            # Update email inside user info
            user_data["email"] = new_email

            # Create new node and delete old one
            db.child("user_info").child(new_email_key).set(user_data)
            db.child("user_info").child(email_key).remove()

            return jsonify({"message": "Email updated successfully"}), 200

        elif update_type == "password":
            current_password = data.get("currentPassword")
            new_password = data.get("newPassword")

            if not current_password or not new_password:
                return jsonify({"error": "Both current and new passwords are required"}), 400

            # Verify password manually from database (Firebase auth removed)
            user_data = db.child("user_info").child(email_key).get().val()
            if not user_data:
                return jsonify({"error": "User profile not found"}), 404

            if user_data.get("password") != current_password:
                return jsonify({"error": "Current password is incorrect"}), 403

            # Update password
            db.child("user_info").child(email_key).update({"password": new_password})
            return jsonify({"message": "Password updated successfully"}), 200

        return jsonify({"error": "Unsupported update type"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# ----------- Notification Settings, Priority, Auto Detection -----------
@account_bp.route('/preferences', methods=['PUT'])
@token_required
def update_preferences(current_user):
    try:
        email = current_user['email']
        email_key = email.replace(".", "_").replace("@", "_")
        preferences = request.get_json()

        db.child("preferences").child(email_key).update(preferences)

        return jsonify({"message": "Preferences updated successfully."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


