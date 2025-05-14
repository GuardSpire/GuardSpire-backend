from flask import Blueprint, request, jsonify
from app.services.firebase_service import db
from app.services.jwt_service import decode_jwt
from app.utils.auth_decorator import token_required

dashboard_bp = Blueprint('dashboard', __name__)

# -------------------Quick Scan-------------------- #
@dashboard_bp.route('/quick-scan', methods=['GET'])
@token_required
def quick_scan(current_user):
    try:
        email = current_user['email']
        email_key = email.replace('.', '_').replace('@', '_')
        user_scans_raw = db.child("scans").child(email_key).get().val()

        if not user_scans_raw:
            return jsonify({
                "email": email,
                "totalScanned": 0,
                "scamsDetected": 0,
                "protectionPercent": 100
            }), 200

        # Filter out reported scans
        filtered_scans = [
            scan for scan in user_scans_raw.values()
            if isinstance(scan, dict) and not scan.get("reported")
        ]

        total = len(filtered_scans)
        scam_count = sum(
            1 for scan in filtered_scans
            if (
                scan.get("combined_threat") and scan["combined_threat"].get("category") in ["Critical", "Suspicious"]
            ) or (
                scan.get("text_analysis") and scan["text_analysis"].get("category") in ["Critical", "Suspicious"]
            )
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

# -------------------Security Model-------------------- #
@dashboard_bp.route('/security-model', methods=['GET'])
@token_required
def security_model(current_user):
    try:
        import json  # in case not already at top
        email = current_user['email']
        email_key = email.replace(".", "_").replace("@", "_")
        user_scans_raw = db.child("scans").child(email_key).get().val()

        if not user_scans_raw:
            return jsonify({'stable': 0, 'suspicious': 0, 'critical': 0}), 200

        filtered_scans = [
            scan for scan in user_scans_raw.values()
            if isinstance(scan, dict) and not scan.get("reported")
        ]

        stable = suspicious = critical = unknown = 0

        for scan in filtered_scans:
            category = None

            # Prefer combined_threat
            if isinstance(scan.get("combined_threat"), dict):
                category = scan["combined_threat"].get("category")
            # Fall back to text_analysis
            if not category and isinstance(scan.get("text_analysis"), dict):
                category = scan["text_analysis"].get("category")

            # ✅ Normalize category
            if category:
                category = category.strip().lower()

            # ✅ Map Legitimate to Stable
            if category in ["legitimate", "stable"]:
                stable += 1
            elif category == "suspicious":
                suspicious += 1
            elif category == "critical":
                critical += 1
            else:
                unknown += 1

        total = stable + suspicious + critical

        print(f"[DEBUG] Total: {total}, Stable: {stable}, Suspicious: {suspicious}, Critical: {critical}, Unknown: {unknown}")

        if total == 0:
            return jsonify({'stable': 0, 'suspicious': 0, 'critical': 0}), 200

        return jsonify({
            'stable': round((stable / total) * 100),
            'suspicious': round((suspicious / total) * 100),
            'critical': round((critical / total) * 100)
        }), 200

    except Exception as e:
        print(f"[ERROR] security_model(): {str(e)}")
        return jsonify({'error': str(e)}), 500

# -------------------Recent Alerts-------------------- #
@dashboard_bp.route('/recent-alerts', methods=['GET'])
@token_required
def recent_alerts(current_user):
    try:
        email = current_user['email']
        email_key = email.replace(".", "_").replace("@", "_")

        # Fetch user's scan history
        user_scans_raw = db.child("scans").child(email_key).get().val()

        if not user_scans_raw:
            return jsonify({"email": email, "recentAlerts": []}), 200

        # Filter out reported items
        filtered_scans = [
            scan for scan in user_scans_raw.values()
            if isinstance(scan, dict) and not scan.get("reported")
        ]

        # Sort by timestamp descending
        sorted_alerts = sorted(
            filtered_scans,
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )

        # Format alerts to match dashboard UI expectations
        formatted_alerts = []
        for scan in sorted_alerts[:5]:
            threat = scan.get("combined_threat") or scan.get("text_analysis") or {}
            raw_conf = threat.get("confidence", "0%")

            try:
                confidence = float(str(raw_conf).replace("%", ""))
            except ValueError:
                confidence = 0

            threat_category = threat.get("category", "Stable")
            threat_level = (
                "critical" if threat_category == "Critical" else
                "suspicious" if threat_category == "Suspicious" else
                "stable"
            )

            platform_label = (
                "Scam Alert" if threat_category == "Critical" else
                "Potential Threat" if threat_category == "Suspicious" else
                "Legitimate"
            )

            formatted_alerts.append({
                "platform": platform_label,
                "threatLevel": threat_level,
                "threatPercentage": confidence,
                "scan_id": scan.get("scan_id"),
                "timestamp": scan.get("timestamp"),
                "input": scan.get("input", "")
            })

        return jsonify({
            "email": email,
            "recentAlerts": formatted_alerts
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
