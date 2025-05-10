import re
import requests
import logging

class URLScanner:
    def __init__(self, app=None):
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .-]*/?'
        )
        self.logger = logging.getLogger(__name__)
        self.app = app

    def extract_urls(self, text):
        """Extract unique URLs from text"""
        return list(set(self.url_pattern.findall(text)))

    def scan_with_virustotal(self, url):
        """Properly submit and scan URL with VirusTotal"""
        try:
            api_key = self.app.config.get('VIRUSTOTAL_API_KEY')
            if not api_key:
                self.logger.warning("VirusTotal API key is missing")
                return None

            # Submit URL for scanning (required for new URLs)
            submit_response = requests.post(
                'https://www.virustotal.com/vtapi/v2/url/scan',
                data={'apikey': api_key, 'url': url},
                timeout=10
            )
            submit_response.raise_for_status()

            # Fetch report
            params = {'apikey': api_key, 'resource': url}
            report_response = requests.get(
                'https://www.virustotal.com/vtapi/v2/url/report',
                params=params,
                timeout=10
            )
            report_response.raise_for_status()
            result = report_response.json()

            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                total = max(result.get('total', 1), 1)
                score = (positives / total) * 9.5
                return {
                    'positives': positives,
                    'total': total,
                    'score': round(score, 1),
                    'scans': result.get('scans', {})
                }
            return None
        except Exception as e:
            self.logger.error(f"VirusTotal scan failed: {str(e)}")
            return None

    def scan_with_google_safe_browsing(self, url):
        """Scan URL with Google Safe Browsing API v4"""
        try:
            api_key = self.app.config.get('GOOGLE_SAFE_BROWSING_API_KEY')
            if not api_key:
                self.logger.warning("Google Safe Browsing API key is missing")
                return {'matches': [], 'score': 0}

            payload = {
                'client': {
                    'clientId': "GuardSpire",
                    'clientVersion': "1.0"
                },
                'threatInfo': {
                    'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    'platformTypes': ["ANY_PLATFORM"],
                    'threatEntryTypes': ["URL"],
                    'threatEntries': [{"url": url}]
                }
            }

            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            threat_weights = {
                'MALWARE': 1.0,
                'SOCIAL_ENGINEERING': 1.0,
                'UNWANTED_SOFTWARE': 0.8
            }
            score = sum(
                threat_weights.get(match['threatType'], 0.5)
                for match in data.get('matches', [])
            ) * (9.5 / 2)

            return {
                'matches': data.get('matches', []),
                'score': min(round(score, 1), 9.5)
            }
        except Exception as e:
            self.logger.error(f"Google Safe Browsing scan failed: {str(e)}")
            return {'matches': [], 'score': 0}

    def analyze_url(self, url):
        """Full URL analysis combining both services"""
        vt_result = self.scan_with_virustotal(url)
        gsb_result = self.scan_with_google_safe_browsing(url)

        threat_score = max(
            vt_result['score'] if vt_result else 0,
            gsb_result['score']
        )

        return {
            'url': url,
            'threat_score': threat_score,
            'category': self._get_threat_category(threat_score),
            'confidence': f"{min(threat_score * 10, 100):.1f}%",
            'is_malicious': threat_score >= 4,
            'details': {
                'virustotal': vt_result,
                'google_safe_browsing': gsb_result
            }
        }

    def _get_threat_category(self, score):
        """Convert threat score to category"""
        if score >= 7: return "Critical"
        if score >= 4: return "Suspicious"
        return "Stable"
