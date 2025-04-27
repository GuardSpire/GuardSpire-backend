from flask import Blueprint, request, jsonify
from app.services.firebase_service import db
from app.utils.auth_decorator import token_required
import datetime

scan_bp = Blueprint('scan', __name__)

#-------------------Create Manual Scan Record--------------------#
@scan_bp.route('/manual', methods=['POST'])
@token_required
def manual_scan_create(current_user):
    try:
        email = current_user['email']
        email_key = email.replace(".", "_").replace("@", "_")

        data = request.json
        input_text = data.get('inputText', '').strip()

        if not input_text:
            return jsonify({"error": "Input text is required"}), 400

        # ✅ Correct Scan Record (with alertType placeholder)
        scan_record = {
            "input": input_text,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "status": "pending",
            "matched": None,
            "platform": None,
            "threatLevel": None,
            "description": None,
            "alertType": None  # Placeholder, will be filled later
        }

        all_data = db.get("manual_scans")
        db_root = all_data.val() or {}

        if "manual_scans" not in db_root:
            db_root["manual_scans"] = {}

        if email_key not in db_root["manual_scans"]:
            db_root["manual_scans"][email_key] = {}

        db.child("manual_scans").child(email_key).push(scan_record)

        return jsonify({"message": "Scan recorded successfully", "data": scan_record}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


#-------------------Report Latest Scam--------------------#
@scan_bp.route('/manual/report/latest', methods=['GET'])
@token_required
def get_manual_report_latest(current_user):
    try:
        email = current_user["email"]
        email_key = email.replace(".", "_").replace("@", "_")

        all_data = db.get("manual_scans")
        user_scans = all_data.val().get("manual_scans", {}).get(email_key)

        if not user_scans:
            return jsonify({"message": "No manual scan records found"}), 404

        if isinstance(user_scans, list):
            user_scans = {str(i): scan for i, scan in enumerate(user_scans)}

        latest_key = max(user_scans.keys(), key=lambda x: int(x))
        latest_entry = user_scans[latest_key]

        full_report = {
            "type": latest_entry.get("type", "Unknown"),
            "platform": latest_entry.get("platform", "Unspecified Platform"),
            "url": latest_entry.get("url", "Unknown"),
            "threatLevel": latest_entry.get("status", "Unknown").capitalize(),  # ✅ status: critical → Critical
            "description": latest_entry.get("description", "No description available."),
            "indicators": [
                "URL does not match official site.",
                "Request for personal/banking info.",
                "Too-good-to-be-true discounts.",
                "Pop-ups or suspicious design."
            ],
            "actions": [
                "Avoid entering any personal data.",
                "Close the page immediately.",
                "Report this scam to authorities.",
                "Change passwords and monitor accounts."
            ],
            "threatPercentage": latest_entry.get("threatPercentage", 1)  # ✅ Dynamic
        }

        return jsonify(full_report), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#-------------------History--------------------#
@scan_bp.route('/history', methods=['GET'])
@token_required
def get_history(current_user):
    try:
        email = current_user['email']
        email_key = email.replace(".", "_").replace("@", "_")

        all_data = db.get("manual_scans")
        all_scans = all_data.val().get("manual_scans", {})

        user_scans = all_scans.get(email_key, {})

        if isinstance(user_scans, list):
            user_scans = {str(i): scan for i, scan in enumerate(user_scans)}

        history = []
        for key, record in user_scans.items():
            history.append({
                "type": record.get("type"),
                "input": record.get("input"),
                "status": record.get("status"),
                "platform": record.get("platform"),
                "threatLevel": record.get("threatLevel"),
                "timestamp": record.get("timestamp"),
                "description": record.get("description"),
            })

        return jsonify({"email": email, "history": history}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
