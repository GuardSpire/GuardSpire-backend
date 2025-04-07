from flask import Blueprint, request, jsonify
from app.services.firebase_service import db
from app.services.jwt_service import decode_jwt
from app.utils.auth_decorator import token_required

dashboard_bp = Blueprint('dashboard', __name__)

#-------------------Quick Scan--------------------#
@dashboard_bp.route('/dashboard/quick-scan', methods=['GET'])
def quick_scan():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Missing Authorization header"}), 401

        token = auth_header.split(" ")[1]
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Invalid token"}), 401

        user_email = payload["email"]
        email_key = user_email.replace(".", "_")

        user_scans = db.child("scans").child(email_key).get()
        scan_dict = user_scans.val()

        scan_data = list(scan_dict.values()) if isinstance(scan_dict, dict) else []

        total = len(scan_data)
        scams = sum(1 for item in scan_data if item.get("status") in ["scam", "suspicious"])

        protection = 100 if total == 0 else round((1 - scams / total) * 100)

        return jsonify({
            "email": user_email,
            "totalScanned": total,
            "scamsDetected": scams,
            "protectionPercent": protection
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#-------------------Security Model--------------------#
@dashboard_bp.route('/security-model', methods=['GET'])
@token_required
def security_model(current_user):
    try:
        email = current_user['email']
        email_key = email.replace(".", "_")

        records = db.child("scam_records").child(email_key).get()
        scam_dict = records.val()

        scam_data = list(scam_dict.values()) if isinstance(scam_dict, dict) else []

        stable = suspicious = critical = total = 0

        for item in scam_data:
            category = item.get('category')
            if category == 'stable':
                stable += 1
            elif category == 'suspicious':
                suspicious += 1
            elif category == 'critical':
                critical += 1
            total += 1

        if total == 0:
            return jsonify({
                'stable': 0,
                'suspicious': 0,
                'critical': 0
            }), 200

        return jsonify({
            'stable': round((stable / total) * 100),
            'suspicious': round((suspicious / total) * 100),
            'critical': round((critical / total) * 100)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

#-------------------Recent Alerts--------------------#
@dashboard_bp.route('/recent-alerts', methods=['GET'])
@token_required
def recent_alerts(current_user):
    try:
        user_email = current_user['email']
        email_key = user_email.replace(".", "_")

        records = db.child("scam_records").child(email_key).get()
        record_dict = records.val()
        

        alerts = list(record_dict.values()) if isinstance(record_dict, dict) else []

        alerts_sorted = sorted(
            alerts, key=lambda x: x.get("timestamp", ""), reverse=True
        )
        recent = alerts_sorted[:5]

        return jsonify({
            "email": user_email,
            "recentAlerts": recent
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
