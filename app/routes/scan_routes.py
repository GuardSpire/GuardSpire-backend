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
        # Initialize scanner with current app context
        url_scanner = URLScanner(current_app._get_current_object())
        
        data = request.get_json()
        input_text = data.get('input', data.get('inputText', '')).strip()
        user_email = current_user['email']
        
        if not input_text:
            return jsonify({"error": "Input text is required"}), 400

        # URL analysis
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
            "scan_id": str(uuid.uuid4()),
            "input": input_text,
            "user": user_email,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "contains_urls": bool(urls),
            "url_analysis": url_analysis if urls else None,
            "warnings": []
        }

        # NLP analysis only if URLs are safe
        if not urls or max_url_threat < 4:
            try:
                nlp_response = requests.post(
                    NLP_SERVICE_URL,
                    json={'text': input_text},
                    timeout=10
                )
                nlp_response.raise_for_status()
                nlp_data = nlp_response.json()
                
                try:
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

                except (KeyError, ValueError) as e:
                    response['warnings'].append(f"NLP response parsing failed: {str(e)}")
                    current_app.logger.warning(f"NLP response parsing error: {str(e)}")

            except requests.exceptions.RequestException as e:
                response['warnings'].append(f"NLP service unavailable: {str(e)}")
                current_app.logger.error(f"NLP service error: {str(e)}")
            except Exception as e:
                response['warnings'].append(f"Unexpected NLP error: {str(e)}")
                current_app.logger.error(f"Unexpected NLP error: {str(e)}")

        # Set combined threat if dangerous URLs found
        if urls and max_url_threat >= 4:
            response['combined_threat'] = {
                "score": max_url_threat,
                "category": url_threat_details.get('category', 'Suspicious'),
                "confidence": url_threat_details.get('confidence', '0%'),
                "source": "url_scan",
                "details": url_threat_details.get('details', {})
            }

        # Save to Firebase
        try:
            email_key = user_email.replace(".", "_").replace("@", "_")
            db.child("scans").child(email_key).push({
                **response,
                "status": "completed"
            })
        except Exception as e:
            error_msg = f"Firebase save failed: {str(e)}"
            response['warnings'].append(error_msg)
            current_app.logger.error(error_msg)

        return jsonify(response), 200
        
    except Exception as e:
        current_app.logger.error(f"Scan failed: {str(e)}")
        return jsonify({
            "error": "Scan failed",
            "details": str(e)
        }), 500
    
#-------------------Get Scan Report--------------------#
@scan_bp.route('/manual/report/<scan_id>', methods=['GET'])
@token_required
def get_manual_report(current_user, scan_id):
    try:
        email = current_user["email"]
        email_key = email.replace(".", "_").replace("@", "_")

        scan_data = db.child("manual_scans").child(email_key).child(scan_id).get().val()

        if not scan_data:
            return jsonify({"message": "Scan record not found"}), 404

        # Determine threat category based on percentage
        threat_percentage = scan_data.get('threatPercentage', 0)
        if threat_percentage >= 0.75:
            threat_category = "Critical"
        elif threat_percentage >= 0.5:
            threat_category = "Suspicious"
        else:
            threat_category = "Stable"

        full_report = {
            "scanId": scan_id,
            "type": scan_data.get('alertType', 'Unknown').capitalize(),
            "input": scan_data.get('input', ''),
            "timestamp": scan_data.get('timestamp', ''),
            "threatLevel": scan_data.get('threatLevel', 'Unknown'),
            "threatPercentage": threat_percentage,
            "threatCategory": threat_category,
            "description": scan_data.get('description', 'No description available.'),
            "indicators": get_indicators(scan_data.get('alertType')),
            "actions": get_recommended_actions(scan_data.get('alertType')),
            "status": scan_data.get('status', 'unknown')
        }

        return jsonify(full_report), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
