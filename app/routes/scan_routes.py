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


#-------------------Get Manual Scan Records--------------------#
@scan_bp.route('/manual/latest', methods=['GET'])
@token_required
def get_latest_manual_scan(current_user):
    try:
        email = current_user['email']
        email_key = email.replace('.', '_').replace('@', '_')

        # Get full database snapshot
        all_data = db.get()

        # Safely access manual_scans for the current user
        all_manual_scans = all_data.val().get("manual_scans", {})
        user_scans_dict = all_manual_scans.get(email_key)

        if not user_scans_dict:
            return jsonify({
                "email": email,
                "latestScan": {}
            }), 200

        # Ensure user_scans_dict is a dictionary
        if isinstance(user_scans_dict, list):
            user_scans_dict = {str(i): scan for i, scan in enumerate(user_scans_dict)}

        # Convert to list of scan records (values only)
        scans_list = list(user_scans_dict.values())

        # Sort by timestamp in descending order
        sorted_scans = sorted(scans_list, key=lambda x: x.get("timestamp", ""), reverse=True)

        # Return the most recent scan
        latest_scan = sorted_scans[0] if sorted_scans else {}

        return jsonify({
            "email": email,
            "latestScan": latest_scan
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


#-------------------Report Scams--------------------#

@scan_bp.route('/manual/report/latest', methods=['GET'])
@token_required
def get_manual_report_latest(current_user):
    try:
        email = current_user["email"]
        email_key = email.replace(".", "_").replace("@", "_")

        # Get scan records
        all_data = db.get("scam_records")
        user_scans = all_data.val().get("scam_records", {}).get(email_key)

        if not user_scans:
            return jsonify({"message": "No scam records found"}), 404

        # Ensure user_scans is a dictionary
        if isinstance(user_scans, list):
            user_scans = {str(i): scan for i, scan in enumerate(user_scans)}

        # Get latest record based on highest key
        latest_key = max(user_scans.keys(), key=lambda x: int(x))
        latest_entry = user_scans[latest_key]

        # Simulate or return extended report details
        full_report = {
            "type": latest_entry.get("type", "Unknown"),
            "platform": latest_entry.get("platform", "Unspecified Platform"),
            "url": latest_entry.get("url", "Unknown"),
            "threatLevel": latest_entry.get("category", "Unknown"),
            "description": latest_entry.get("message", "No description available."),
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
            "threatPercentage": 1  # Simulated 100%
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

        # Fetch all data under 'manual_scans'
        all_data = db.get("manual_scans")
        all_scans = all_data.val().get("manual_scans", {})

        user_scans = all_scans.get(email_key, {})  # Get current user's scans

        # Ensure user_scans is a dictionary
        if isinstance(user_scans, list):
            user_scans = {str(i): scan for i, scan in enumerate(user_scans)}

        history = []
        for key, record in user_scans.items():
            history.append({
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
