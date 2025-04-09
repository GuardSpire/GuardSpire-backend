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

        scan_record = {
            "input": input_text,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "status": "pending",
            "matched": None,
            "platform": None,
            "threatLevel": None,
            "description": None
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
