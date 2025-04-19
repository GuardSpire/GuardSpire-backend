from flask import Blueprint, request, jsonify
from app.services.firebase_service import db
from app.services.jwt_service import decode_jwt
from app.utils.auth_decorator import token_required

dashboard_bp = Blueprint('dashboard', __name__)

#-------------------Quick Scan--------------------#
@dashboard_bp.route('/dashboard/quick-scan', methods=['GET'])
@token_required
def quick_scan(current_user):
    try:
        email = current_user['email']
        email_key = email.replace('.', '_').replace('@', '_')

        # Get full data once
        all_data = db.get()
        user_scans = all_data.val().get("scans", {}).get(email_key, {})

        # Ensure it's a dict
        if not isinstance(user_scans, dict):
            user_scans = {}

        total = len(user_scans)
        scam_count = sum(
            1 for scan in user_scans.values()
            if scan.get("status") in ["scam", "suspicious"]
        )

        protection = 100 if total == 0 else round((1 - scam_count / total) * 100)

        return jsonify({
            "email": email,
            "totalScanned": total,
            "scamsDetected": scam_count,
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
        email_key = email.replace(".", "_").replace("@", "_")

        all_data = db.get("scam_records")

        scam_data = all_data.val()["scam_records"][email_key]

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
        email = current_user['email']
        email_key = email.replace(".", "_").replace("@", "_")

        all_data = db.get("scam_records")
        alerts = all_data.val()["scam_records"].get(email_key, {})

        alerts_sorted = sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)
        recent = alerts_sorted[:5]

        return jsonify({
            "email": email,
            "recentAlerts": recent
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
