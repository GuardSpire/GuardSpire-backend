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
        print("Request OTP endpoint hit")  # Debug print

        email = current_user['email']
        if isinstance(email, dict):  # ✅ FIX added
            email = email.get('email', '')

        data = request.get_json()
        update_type = data.get("type")  # "email" or "password"

        if update_type not in ["email", "password"]:
            return jsonify({"error": "Invalid update type"}), 400

        otp = generate_otp(email, update_type)
        
        # Print the OTP to the terminal
        print(f"🔥Generated OTP for {update_type} update: {otp}🔥")

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

        # Fix nested email dict
        if isinstance(email, dict) and "email" in email:
            email = email["email"]

        data = request.get_json()
        otp = data.get("otp")
        update_type = data.get("type")

        if not otp or not update_type:
            return jsonify({"error": "OTP and update type are required"}), 400

        if not verify_otp(email, otp, update_type):
            return jsonify({"error": "Invalid OTP"}), 403

        email_key = email.replace(".", "_").replace("@", "_")

        # ------------- EMAIL UPDATE -------------
        if update_type == "email":
            current_email = data.get("currentEmail")
            new_email = data.get("newEmail")

            if not current_email or not new_email:
                return jsonify({"error": "Both current and new emails are required"}), 400

            if email != current_email:
                return jsonify({"error": "Current email does not match the logged-in user"}), 400

            new_email_key = new_email.replace(".", "_").replace("@", "_")

            # Fetch existing user data
            user_data = db.child("user_info").child(email_key).get().val()
            if not user_data:
                return jsonify({"error": "User profile not found"}), 404

            # Update email in profile
            user_data["email"] = new_email
            db.child("user_info").child(new_email_key).set(user_data)

            # Migrate scans
            scans_data = db.child("scans").child(email_key).get().val()
            if scans_data:
                db.child("scans").child(new_email_key).set(scans_data)
                db.child("scans").child(email_key).remove()

            # Optional: migrate other data
            # history_data = db.child("history").child(email_key).get().val()
            # if history_data:
            #     db.child("history").child(new_email_key).set(history_data)
            #     db.child("history").child(email_key).remove()

            # Remove old user_info
            db.child("user_info").child(email_key).remove()

            return jsonify({"message": "Email updated successfully"}), 200

        # ------------- PASSWORD UPDATE -------------
        elif update_type == "password":
            current_password = data.get("currentPassword")
            new_password = data.get("newPassword")
            current_email_param = data.get("currentEmail", email)

            if not current_password or not new_password:
                return jsonify({"error": "Both current and new passwords are required"}), 400

            possible_paths = [
                f"user_info/{email_key}",
                f"users/{email_key}",
                f"user_data/{email_key}",
                f"accounts/{email_key}"
            ]

            user_data = None
            actual_path = None

            for path in possible_paths:
                user_data = db.child(path).get().val()
                if user_data:
                    actual_path = path
                    break

            if not user_data:
                return jsonify({"error": "User profile not found"}), 404

            stored_password = user_data.get("password")
            if not stored_password:
                return jsonify({"error": "Password not found in user profile"}), 404

            if stored_password != current_password:
                return jsonify({"error": "Current password is incorrect"}), 403

            # Update password
            db.child(actual_path).update({"password": new_password})

            return jsonify({"message": "Password updated successfully"}), 200

        # ------------- UNSUPPORTED TYPE -------------
        return jsonify({"error": "Unsupported update type"}), 400

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

    
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


