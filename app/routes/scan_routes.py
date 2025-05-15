from flask import Blueprint, request, jsonify, current_app
import datetime
import requests
import uuid
from app.services.firebase_service import db
from app.utils.auth_decorator import token_required
from app.services.url_scanner import URLScanner

scan_bp = Blueprint('scan_bp', __name__)
NLP_SERVICE_URL = "http://localhost:5001/analyze"

#-------------------Manual Scan--------------------#
@scan_bp.route('/manual', methods=['POST'])
@token_required
def manual_scan_create(current_user):
    try:
        url_scanner = URLScanner(current_app._get_current_object())
        data = request.get_json()
        input_text = data.get('input', data.get('inputText', '')).strip()
        user_email = current_user['email']

        if not input_text:
            return jsonify({"error": "Input text is required"}), 400

        scan_id = str(uuid.uuid4())

        urls = url_scanner.extract_urls(input_text)
        url_analysis = []
        max_url_threat = 0.0
        url_threat_details = {}

        if urls:
            for url in urls:
                try:
                    analysis = url_scanner.analyze_url(url)
                    url_analysis.append(analysis)
                    if analysis['threat_score'] > max_url_threat:
                        max_url_threat = analysis['threat_score']
                        url_threat_details = {
                            'category': analysis['category'],
                            'confidence': analysis['confidence'],
                            'source': 'url_scan',
                            'details': analysis.get('details', {})
                        }
                except Exception as e:
                    current_app.logger.error(f"URL analysis failed for {url}: {str(e)}")
                    url_analysis.append({
                        'url': url,
                        'error': str(e),
                        'threat_score': 0,
                        'category': 'Stable',
                        'confidence': '0%'
                    })

        response = {
            "scan_id": scan_id,
            "input": input_text,
            "user": user_email,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "contains_urls": bool(urls),
            "url_analysis": url_analysis if urls else None,
            "warnings": []
        }

        if not urls or max_url_threat < 4:
            try:
                nlp_response = requests.post(NLP_SERVICE_URL, json={'text': input_text}, timeout=10)
                nlp_response.raise_for_status()
                nlp_data = nlp_response.json()

                confidence = float(nlp_data['confidence'].strip('%')) / 100
                threat_level = float(nlp_data.get('threat_level', 0))

                response['text_analysis'] = {
                    "is_scam": nlp_data['label'] == "SCAM",
                    "confidence": confidence,
                    "threat_level": threat_level,
                    "category": (
                        "Critical" if confidence >= 0.75 else
                        "Suspicious" if confidence >= 0.5 else
                        "Stable"
                    ) if nlp_data['label'] == "SCAM" else "Legitimate",
                    "description": f"Classified as {nlp_data['label']} (Confidence: {nlp_data['confidence']})"
                }

                if not urls:
                    response['combined_threat'] = {
                        "score": threat_level,
                        "category": response['text_analysis']['category'],
                        "confidence": nlp_data['confidence'],
                        "source": "text_analysis"
                    }

            except Exception as e:
                response['warnings'].append(f"NLP analysis failed: {str(e)}")
                current_app.logger.error(f"NLP analysis error: {str(e)}")

        if urls and max_url_threat >= 4:
            response['combined_threat'] = {
                "score": max_url_threat,
                "category": url_threat_details.get('category', 'Suspicious'),
                "confidence": url_threat_details.get('confidence', '0%'),
                "source": "url_scan",
                "details": url_threat_details.get('details', {})
            }

        try:
            email_key = user_email.replace(".", "_").replace("@", "_")
            db.child("scans").child(email_key).child(scan_id).set({
                **response,
                "status": "completed"
            })
        except Exception as e:
            error_msg = f"Firebase save failed: {str(e)}"
            response['warnings'].append(error_msg)
            current_app.logger.error(error_msg)

        return jsonify(response), 200

    except Exception as e:
        current_app.logger.error(f"Scan failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Scan failed", "details": str(e)}), 500
    
#-------------------Get Scan Report--------------------#
@scan_bp.route('/manual/report/<scan_id>', methods=['GET'])
@token_required
def get_manual_report(current_user, scan_id):
    try:
        email = current_user["email"]
        email_key = email.replace(".", "_").replace("@", "_")
        current_app.logger.info(f"Looking for scan {scan_id} for user {email_key}")

        scan = db.child("scans").child(email_key).child(scan_id).get()
        if scan.val():
            current_app.logger.info("Found scan by direct key access")
            found_scan = scan.val()
        else:
            current_app.logger.error(f"Scan {scan_id} not found in database")
            return jsonify({"message": "Scan record not found"}), 404

        # Prefer combined_threat, fall back to text_analysis
        threat_data = found_scan.get('combined_threat') or found_scan.get('text_analysis') or {}

        # Try to get confidence (as float)
        confidence_raw = threat_data.get('confidence') or found_scan.get('text_analysis', {}).get('confidence', 0)
        try:
            threat_percentage = float(str(confidence_raw).strip('%')) if isinstance(confidence_raw, str) else float(confidence_raw)
        except ValueError:
            threat_percentage = 0

        # Use category from analysis if available
        threat_category = threat_data.get('category') or found_scan.get('text_analysis', {}).get('category') or 'Legitimate'

        # Map threat category to internal alert type
        category_map = {
            "critical": "phishing",
            "suspicious": "phishing",
            "legitimate": "legit",
            "stable": "legit"
        }
        alert_type = category_map.get(threat_category.lower(), "legit")

        # Use description from threat_data or fallback
        description = (
            threat_data.get('description') or
            found_scan.get('text_analysis', {}).get('description') or
            'No description available.'
        )

        full_report = {
            "scanId": scan_id,
            "type": threat_category.capitalize(),
            "input": found_scan.get('input', ''),
            "timestamp": found_scan.get('timestamp', ''),
            "threatLevel": threat_data.get('score', threat_data.get('threat_level', 0)),
            "threatPercentage": threat_percentage / 100 if threat_percentage > 1 else threat_percentage,
            "threatCategory": threat_category,
            "description": description,
            "indicators": get_indicators(alert_type),
            "actions": get_recommended_actions(alert_type),
            "status": found_scan.get('status', 'completed'),
            "source": threat_data.get('source', 'unknown'),
            "containsUrls": found_scan.get('contains_urls', False),
            "urlAnalysis": found_scan.get('url_analysis', None),
            "warnings": found_scan.get('warnings', [])
        }

        return jsonify(full_report), 200

    except Exception as e:
        current_app.logger.error(f"Error retrieving scan report: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve scan report", "details": str(e)}), 500


def get_indicators(alert_type):
    if alert_type == "phishing":
        return [
            "Content matches known scam patterns",
            "Request for personal/banking info detected",
            "Suspicious language patterns identified",
            "High probability of malicious intent"
        ]
    return [
        "No immediate threats detected",
        "Content appears legitimate",
        "Low risk indicators present"
    ]

def get_recommended_actions(alert_type):
    if alert_type == "phishing":
        return [
            "Do not respond to or interact with this content",
            "Report this content to authorities if applicable",
            "Change passwords if any credentials were shared",
            "Monitor accounts for suspicious activity"
        ]
    return [
        "No immediate action required",
        "Remain vigilant for suspicious content",
        "Report any suspicious variations of this content"
    ]

#-------------------Block & Report--------------------#
@scan_bp.route('/manual/report/<scan_id>/report', methods=['POST'])
@token_required
def block_and_report_scan(current_user, scan_id):
    try:
        email = current_user["email"]
        email_key = email.replace(".", "_").replace("@", "_")

        # Reference the exact scan location
        scan_ref = db.child("scans").child(email_key).child(scan_id)
        scan_snapshot = scan_ref.get()

        if not scan_snapshot.val():
            return jsonify({"error": "Scan not found"}), 404

        scan_data = scan_snapshot.val()

        # Save to reports
        report_id = str(uuid.uuid4())
        db.child("reports").child(report_id).set({
            "reported_by": email,
            "scan_id": scan_id,
            "input": scan_data.get("input"),
            "combined_threat": scan_data.get("combined_threat"),
            "timestamp": datetime.datetime.utcnow().isoformat(),
        })

        # ✅ SOFT DELETE only that scan
        db.child("scans").child(email_key).child(scan_id).update({
            "reported": True,
            "deleted": True
        })

        return jsonify({"message": "Scan flagged as reported and marked deleted"}), 200

    except Exception as e:
        current_app.logger.error(f"Block & Report failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to report scan"}), 500

#------------------------------Allow Scan-------------------------------------------#
@scan_bp.route('/manual/report/<scan_id>/allow', methods=['POST'])
@token_required
def allow_scan(current_user, scan_id):
    try:
        email = current_user["email"]
        email_key = email.replace(".", "_").replace("@", "_")

        scan_ref = db.child("scans").child(email_key).child(scan_id)
        scan_snapshot = scan_ref.get()

        if not scan_snapshot.val():
            return jsonify({"error": "Scan not found"}), 404

        # ✅ Update scan with 'allowed' status
        scan_ref.update({
            "allowed": True,
            "allowed_timestamp": datetime.datetime.utcnow().isoformat()
        })

        return jsonify({"message": "Scan marked as allowed"}), 200

    except Exception as e:
        current_app.logger.error(f"Allow scan failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to allow scan"}), 500


#-------------------Scan Feedback--------------------#
@scan_bp.route('/manual/feedback/<scan_id>', methods=['POST'])
@token_required
def submit_feedback(current_user, scan_id):
    try:
        email = current_user["email"]
        feedback = request.json.get("feedback")
        input_text = request.json.get("input", "")
        original_category = request.json.get("original_category", "")

        if feedback is None:
            return jsonify({"error": "Missing feedback value"}), 400

        feedback_id = str(uuid.uuid4())

        db.child("feedback").child(feedback_id).set({
            "scan_id": scan_id,
            "user": email,
            "feedback": feedback,  # true or false
            "original_category": original_category,
            "input": input_text,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })

        return jsonify({"message": "Feedback received"}), 200

    except Exception as e:
        current_app.logger.error(f"Feedback submission failed: {str(e)}")
        return jsonify({"error": "Server error"}), 500

    
#-------------------Real-time Notification Scan--------------------#
@scan_bp.route('/notification/scan', methods=['POST'])
@token_required
def notification_realtime_scan(current_user):
    try:
        url_scanner = URLScanner(current_app._get_current_object())
        data = request.get_json()

        input_text = data.get('text', '').strip()
        urls = data.get('urls', [])
        user_email = current_user.get('email')

        if not input_text and not urls:
            return jsonify({"error": "No input data"}), 400

        scan_id = str(uuid.uuid4())
        timestamp = datetime.datetime.utcnow().isoformat()
        url_analysis = []
        max_url_threat = 0.0
        url_threat_details = {}

        # ---- URL Analysis ----
        if urls:
            for url in urls:
                try:
                    analysis = url_scanner.analyze_url(url)
                    url_analysis.append(analysis)
                    if analysis['threat_score'] > max_url_threat:
                        max_url_threat = analysis['threat_score']
                        url_threat_details = {
                            'category': analysis['category'],
                            'confidence': analysis['confidence'],
                            'source': 'url_scan',
                            'details': analysis.get('details', {})
                        }
                except Exception as e:
                    current_app.logger.warning(f"URL analysis failed for {url}: {str(e)}")
                    url_analysis.append({
                        'url': url,
                        'error': str(e),
                        'threat_score': 0,
                        'category': 'Stable',
                        'confidence': '0%'
                    })

        response = {
            "scan_id": scan_id,
            "input": input_text,
            "user": user_email,
            "timestamp": timestamp,
            "contains_urls": bool(urls),
            "url_analysis": url_analysis if urls else None,
            "warnings": []
        }

        # ---- NLP Analysis if safe URLs ----
        if not urls or max_url_threat < 4:
            try:
                nlp_response = requests.post(NLP_SERVICE_URL, json={'text': input_text}, timeout=10)
                nlp_response.raise_for_status()
                nlp_data = nlp_response.json()

                confidence = float(nlp_data['confidence'].strip('%')) / 100
                threat_level = float(nlp_data.get('threat_level', 0))

                response['text_analysis'] = {
                    "is_scam": nlp_data['label'] == "SCAM",
                    "confidence": confidence,
                    "threat_level": threat_level,
                    "category": (
                        "Critical" if confidence >= 0.75 else
                        "Suspicious" if confidence >= 0.5 else
                        "Stable"
                    ) if nlp_data['label'] == "SCAM" else "Stable",
                    "description": f"Classified as {nlp_data['label']} (Confidence: {nlp_data['confidence']})"
                }

                if not urls:
                    response['combined_threat'] = {
                        "score": threat_level,
                        "category": response['text_analysis']['category'],
                        "confidence": nlp_data['confidence'],
                        "source": "text_analysis"
                    }

            except Exception as e:
                response['warnings'].append(f"NLP analysis failed: {str(e)}")
                current_app.logger.error(f"NLP analysis error: {str(e)}")

        # ---- Combined Threat from URL if High Threat ----
        if urls and max_url_threat >= 4:
            response['combined_threat'] = {
                "score": max_url_threat,
                "category": url_threat_details.get('category', 'Suspicious'),
                "confidence": url_threat_details.get('confidence', '0%'),
                "source": "url_scan",
                "details": url_threat_details.get('details', {})
            }

        # ---- Save to Firebase ----
        try:
            email_key = user_email.replace(".", "_").replace("@", "_")
            db.child("scans").child(email_key).child(scan_id).set({
                **response,
                "status": "completed"
            })
        except Exception as e:
            error_msg = f"Firebase save failed: {str(e)}"
            response['warnings'].append(error_msg)
            current_app.logger.error(error_msg)

        # ---- Add show_warning for client popup
        threat_data = response.get('combined_threat') or response.get('text_analysis') or {}
        score = threat_data.get('score') or threat_data.get('threat_level', 0)
        response['show_warning'] = score >= 0.5

        return jsonify(response), 200

    except Exception as e:
        current_app.logger.error(f"/notification/scan failed: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


#-------------------History--------------------#
@scan_bp.route('/history', methods=['GET'])
@token_required
def get_history(current_user):
    try:
        email = current_user['email']
        email_key = email.replace(".", "_").replace("@", "_")

        user_scans_raw = db.child("scans").child(email_key).get().val()
        if not user_scans_raw:
            return jsonify({"email": email, "history": []}), 200

        history = []
        for scan_id, scan in user_scans_raw.items():
            if not isinstance(scan, dict) or scan.get("reported"):
                continue

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

            timestamp = scan.get("timestamp", "")

            history.append({
                "scan_id": scan_id,  # ✅ Fix added
                "type": threat.get("source", "manual").capitalize(),
                "input": scan.get("input", ""),
                "status": scan.get("status", "completed"),
                "platform": platform_label,
                "threatLevel": threat_level,
                "timestamp": timestamp,
                "description": threat.get("description", "No description available."),
                "confidence": confidence
            })

        history = sorted(history, key=lambda x: str(x.get("timestamp") or ""), reverse=True)

        return jsonify({"email": email, "history": history}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
