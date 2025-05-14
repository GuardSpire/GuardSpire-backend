from flask import Blueprint, request, jsonify
from app.services.firebase_service import db, auth
from app.services.otp_service import generate_otp, verify_otp
from app.utils.auth_decorator import token_required

delete_bp = Blueprint('delete', __name__)

#--------------Save Delete Reason------------------------
@delete_bp.route('/reason', methods=['POST'])
@token_required
def save_delete_reason(current_user):
    try:
        email = current_user["email"]
        if isinstance(email, dict) and "email" in email:
            email = email["email"]

        email_key = email.replace(".", "_").replace("@", "_")
        data = request.get_json()
        reason = data.get("reason")

        if not reason:
            print("❌ No reason provided")
            return jsonify({"error": "Reason is required"}), 400

        print(f"📌 Saving delete reason for {email_key}: {reason}")
        db.child("user_info").child(email_key).update({"delete_reason": {"reason": reason}})

        return jsonify({"message": "Reason saved successfully"}), 200

    except Exception as e:
        print(f"❌ Error saving delete reason: {e}")
        return jsonify({"error": str(e)}), 500

#-----------------Confirm Password-------------------
@delete_bp.route('/confirm-password', methods=['POST'])
@token_required
def confirm_password(current_user):
    try:
        email = current_user["email"]
        if isinstance(email, dict) and "email" in email:
            email = email["email"]

        data = request.get_json()
        raw_password = data.get("password")
        print(f"🔐 Received password: {raw_password}")

        if not raw_password:
            return jsonify({"error": "Password required"}), 400

        email_key = email.replace('.', '_').replace('@', '_')
        user_data = db.child("user_info").child(email_key).get().val()
        print(f"📋 User data from DB: {user_data}")

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        stored_password = user_data.get("password")
        print(f"🔒 Stored password: {stored_password}")

        if stored_password != raw_password:
            print("❌ Password mismatch")
            return jsonify({"error": "Incorrect password"}), 403

        print("✅ Password matched")
        return jsonify({"message": "Password correct"}), 200

    except Exception as e:
        print(f"❌ Error during password confirmation: {e}")
        return jsonify({"error": str(e)}), 500

#------------------------Send OTP-----------------------
@delete_bp.route('/send-otp', methods=['POST'])
@token_required
def send_otp(current_user):
    try:
        email = current_user["email"]
        print(f"📨 Request received to send OTP for: {email}")

        otp = generate_otp(email, "delete")
        print(f"🔥 OTP generated for delete: {otp}")

        return jsonify({
            "message": "OTP sent successfully",
            "otp": otp  # You might hide this in prod
        }), 200

    except Exception as e:
        print(f"❌ Error sending OTP: {e}")
        return jsonify({"error": str(e)}), 500

#---------------------Verify OTP-------------------
@delete_bp.route('/verify-otp', methods=['POST'])
@token_required
def verify_delete_otp(current_user):
    try:
        data = request.get_json()
        email = current_user["email"]
        otp = data.get("otp")

        print(f"📥 Received OTP to verify: {otp} for {email}")

        if not otp:
            print("❌ OTP missing in request")
            return jsonify({"error": "OTP is required"}), 400

        result = verify_otp(email, otp, "delete")
        print(f"✅ OTP verification result: {result}")

        if not result:
            return jsonify({"error": "Invalid OTP"}), 403

        return jsonify({"message": "OTP verified"}), 200

    except Exception as e:
        print(f"❌ OTP verification error: {e}")
        return jsonify({"error": str(e)}), 500

#---------------------Set New Password-------------------
@delete_bp.route('/set-password', methods=['POST'])
@token_required
def set_new_password(current_user):
    try:
        data = request.get_json()
        new_password = data.get("newPassword")

        if not new_password:
            return jsonify({"error": "New password is required"}), 400

        email = current_user["email"]
        email_key = email.replace(".", "_").replace("@", "_")

        print(f"🔁 Updating password in DB for {email_key}")
        db.child("user_info").child(email_key).update({"password": new_password})

        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        print(f"❌ Error updating password: {e}")
        return jsonify({"error": str(e)}), 500

#---------------------Final Delete Account-------------------
@delete_bp.route('/final', methods=['DELETE'])
@token_required
def delete_account(current_user):
    try:
        email = current_user["email"]
        if isinstance(email, dict) and "email" in email:
            email = email["email"]

        email_key = email.replace(".", "_").replace("@", "_")
        print(f"🧨 Deleting account and data for {email_key}")

        db.child("scans").child(email_key).remove()
        db.child("manual_scans").child(email_key).remove()
        db.child("scam_records").child(email_key).remove()
        db.child("user_info").child(email_key).remove()

        print(f"✅ Account and all data deleted for {email_key}")
        return jsonify({"message": "Account deleted successfully"}), 200

    except Exception as e:
        print(f"❌ Error during final deletion: {e}")
        return jsonify({"error": str(e)}), 500
