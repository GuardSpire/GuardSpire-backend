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
        email_key = email.replace(".", "_").replace("@", "_")
        data = request.get_json()

        reason = data.get("reason")
        if not reason:
            return jsonify({"error": "Reason is required"}), 400

        db.child("delete_reasons").child(email_key).set({"reason": reason})
        return jsonify({"message": "Reason saved successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#-----------------Confirm Password (2 attempts)-------------------
@delete_bp.route('/confirm-password', methods=['POST'])
@token_required
def confirm_password(current_user):
    try:
        email = current_user["email"]
        data = request.get_json()
        raw_password = data.get("password")

        if not raw_password:
            return jsonify({"error": "Password required"}), 400

        auth.sign_in_with_email_and_password(email, raw_password)
        return jsonify({"message": "Password correct"}), 200

    except Exception:
        return jsonify({"error": "Incorrect password"}), 401

#------------------------Send OTP-----------------------
@delete_bp.route('/send-otp', methods=['POST'])
@token_required
def send_otp(current_user):
    try:
        email = current_user["email"]
        otp = generate_otp(email, "delete")
        return jsonify({
            "message": "OTP sent successfully",
            "otp": otp
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#-------------Verify OTP------------------
@delete_bp.route('/verify-otp', methods=['POST'])
@token_required
def verify_otp_for_delete(current_user):
    try:
        email = current_user["email"]
        data = request.get_json()
        otp = data.get("otp")

        if not verify_otp(email, otp, "delete"):
            return jsonify({"error": "Invalid OTP"}), 403

        return jsonify({"message": "OTP verified"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

#---------------------New password-------------------

@delete_bp.route('/set-password', methods=['POST'])
@token_required
def set_new_password(current_user):
    try:
        data = request.get_json()
        new_password = data.get("newPassword")
        if not new_password:
            return jsonify({"error": "New password is required"}), 400

        email = current_user["email"]
        # You may need to ask user to re-login to get fresh idToken
        user = auth.sign_in_with_email_and_password(email, new_password)  # Optional auth check
        auth.update_user_password(user['idToken'], new_password)

        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


#---------------------Final Delete Account-------------------
@delete_bp.route('/final', methods=['DELETE'])
@token_required
def delete_account(current_user):
    try:
        email = current_user["email"]
        email_key = email.replace(".", "_").replace("@", "_")

        db.child("scans").child(email_key).remove()
        db.child("manual_scans").child(email_key).remove()
        db.child("scam_records").child(email_key).remove()
        db.child("user_info").child(email_key).remove()
        db.child("delete_reasons").child(email_key).remove()

        return jsonify({"message": "Account deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#---------------------Delete Account -------------------
@delete_bp.route('', methods=['DELETE'])
@token_required
def delete_user_account(current_user):
    try:
        email = current_user["email"]
        email_key = email.replace('.', '_').replace('@', '_')

        db.child("scans").child(email_key).remove()
        db.child("manual_scans").child(email_key).remove()
        db.child("scam_records").child(email_key).remove()
        db.child("user_info").child(email_key).remove()

        return jsonify({"message": "Account and data deleted"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
