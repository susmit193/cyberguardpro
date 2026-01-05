from dotenv import load_dotenv, find_dotenv
import os

# Load .env reliably from the project tree (falls back to cwd)
dotenv_path = find_dotenv()
if dotenv_path:
    load_dotenv(dotenv_path)
else:
    load_dotenv()
from flask import Flask, render_template, request, jsonify, send_file
import psutil
import requests
from datetime import datetime
import whois
from tld import get_tld
import re
import socket
import ssl
from urllib.parse import urlparse
import os
import time
import sys
import platform
import google.generativeai as genai  
import shutil

# Add ML folder to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'ML'))
from url_analyzer import URLAnalyzer
from gemini_integration import try_gemini_api  # auto-inserted

app = Flask(__name__, template_folder='static/templates', static_folder='static')
app.config['DEBUG'] = True
app.config['TESTING'] = False

# Initialize ML model
try:
    url_analyzer = URLAnalyzer()
    print("ML model initialized successfully!")
except Exception as e:
    print(f"Error initializing ML model: {e}")
    url_analyzer = None
# Keywords used to decide whether a user prompt is cybersecurity-related.
CYBER_KEYWORDS = [
    'phish', 'phishing', 'password', '2fa', 'two-factor', 'two factor', 'authenticator', 'auth',
    'malware', 'virus', 'ransom', 'ransomware', 'breach', 'hacked', 'leak', 'vuln', 'vulnerability',
    'ssl', 'tls', 'certificate', 'encrypt', 'encryption', 'firewall', 'ddos', 'dos', 'csrf', 'xss',
    'sql injection', 'injection', 'credentials', 'spoof', 'spoofing', 'social engineering', 'scam',
    'botnet', 'spyware', 'adware', 'cve', 'ip', 'dns', 'domain', 'ports', 'open port'
]
def is_cyber_prompt(prompt: str) -> bool:
    """Return True if the prompt appears to be cybersecurity-related.

    This is a conservative keyword check to avoid sending non-cyber prompts to the API.
    """
    if not prompt:
        return False
    p = prompt.lower()
    # check for any keyword presence
    return any(kw in p for kw in CYBER_KEYWORDS)

def chatbot_reply_ai(prompt: str) -> str:
    """
    Enhanced chatbot using Google Gemini API for better cybersecurity responses.
    Falls back to simple responses if API fails.
    """
    if not prompt or len(prompt.strip()) < 3:
        return "Please ask a specific cybersecurity question. I can help with phishing, passwords, 2FA, breaches, and more!"

    # Only handle cybersecurity-related prompts. Avoid calling the API for off-topic requests.
    if not is_cyber_prompt(prompt):
        return "I only assist with cybersecurity-related questions. Please ask a cybersecurity question (phishing, passwords, 2FA, breaches, malware, etc.)."

    # Try AI-powered response first
    try:
        ai_response = get_ai_chatbot_response(prompt)
        if ai_response and len(ai_response.strip()) > 10:
            return ai_response
    except Exception as e:
        print(f"AI chatbot error: {e}")

    # Fallback to simple responses
    return chatbot_reply_simple(prompt)


def get_ai_chatbot_response(prompt: str) -> str:
    """
    Get AI response using Google Gemini API.
    Tries Gemini first, then simple fallback.
    """
    try:
        response = try_gemini_api(prompt)
        if response:
            return response
        return None
    except Exception as e:
        print(f"AI API error: {e}")
        return None
def chatbot_reply_simple(prompt: str) -> str:
    """Fallback simple responses for common cybersecurity questions"""
    p = (prompt or '').lower()
    
    if any(word in p for word in ['password', 'change password', 'reset password']):
        return "Password Security: Use unique, strong passwords (12+ chars, mix of letters/numbers/symbols). Enable 2FA, use a password manager, and never reuse passwords across sites. Change passwords immediately if you suspect a breach."
    
    if any(word in p for word in ['2fa', 'two factor', 'two-factor', 'authenticator']):
        return "Two-Factor Authentication (2FA): Adds an extra security layer beyond passwords. Use authenticator apps (Google Authenticator, Authy) instead of SMS when possible. Enable 2FA on all important accounts like email, banking, and social media."
    
    if any(word in p for word in ['phishing', 'suspicious email', 'fake website', 'scam']):
        return "Phishing Protection: Never click links in suspicious emails. Check sender addresses carefully, look for spelling errors, and verify urgent requests by contacting the company directly. Use our URL analyzer above to check suspicious links."
    
    if any(word in p for word in ['breach', 'hacked', 'pwned', 'data leak']):
        return "Data Breach Response: Check if your accounts were compromised using our Website Breach Check tool. Change passwords immediately for affected accounts, enable 2FA, monitor bank statements, and consider credit monitoring services."
    
    if any(word in p for word in ['wifi', 'wi-fi', 'network security', 'router']):
        return "Wi-Fi Security: Use WPA3 encryption, change default router passwords, disable WPS, update firmware regularly, hide SSID, and use a VPN on public networks. Never connect to unsecured public Wi-Fi for sensitive activities."
    
    if any(word in p for word in ['malware', 'virus', 'antivirus', 'scan']):
        return "Malware Protection: Keep your OS and software updated, use reputable antivirus software, avoid suspicious downloads, don't open unexpected attachments, and regularly scan your system. Consider using Windows Defender or Malwarebytes."
    
    if any(word in p for word in ['device health', 'cpu', 'memory', 'performance']):
        return "Device Health: Use our Device Health tool to monitor CPU, memory, and disk usage. Keep your system updated, close unnecessary programs, run regular scans, and ensure adequate storage space for optimal performance."
    
    if any(word in p for word in ['password manager', 'bitwarden', '1password', 'keepass']):
        return "Password Managers: Essential for security! Generate unique passwords, store them securely, and sync across devices. Popular options: Bitwarden (free), 1Password, LastPass, or KeePass. Always use a strong master password and enable 2FA."
    
    if any(word in p for word in ['report', 'report phishing', 'report scam']):
        return "Reporting Security Issues: Report phishing to PhishTank, your email provider, and the Anti-Phishing Working Group. Use browser reporting features, contact your national CERT, and report to the FTC if you're a victim of fraud."
    
    if any(word in p for word in ['safe', 'secure', 'check', 'verify']):
        return "Security Verification: Use our URL analyzer to check suspicious links, verify SSL certificates, check domain age, and review threat intelligence. When in doubt, don't click or enter personal information. Trust your instincts!"
    
    return "I'm your cybersecurity assistant! I can help with: phishing detection, password security, 2FA setup, data breaches, Wi-Fi security, malware protection, and more. Ask me anything specific about cybersecurity!"

USER_AGENT = "CyberAssistant/1.0 (contact@example.com)"
HIBP_API_KEY = os.environ.get("HIBP_API_KEY")

# Removed legacy password-breach k-anonymity helper; we now focus on website breaches

def check_website_breaches(domain):
    """
    Check if a website/domain has been involved in data breaches
    This is a simplified implementation that checks against known breach databases
    """
    # Known major breaches by domain (simplified database)
    known_breaches = {
        'yahoo.com': [
            {'Name': 'Yahoo Data Breach 2013-2014', 'Date': '2013-08-01', 'PwnCount': 3000000000, 'Description': 'All 3 billion accounts compromised'},
            {'Name': 'Yahoo Data Breach 2014', 'Date': '2014-01-01', 'PwnCount': 500000000, 'Description': '500 million accounts compromised'}
        ],
        'linkedin.com': [
            {'Name': 'LinkedIn Data Breach 2012', 'Date': '2012-05-05', 'PwnCount': 164000000, 'Description': '164 million email addresses and passwords'}
        ],
        'adobe.com': [
            {'Name': 'Adobe Data Breach 2013', 'Date': '2013-10-01', 'PwnCount': 153000000, 'Description': '153 million user records'}
        ],
        'ebay.com': [
            {'Name': 'eBay Data Breach 2014', 'Date': '2014-05-21', 'PwnCount': 145000000, 'Description': '145 million user records'}
        ],
        'equifax.com': [
            {'Name': 'Equifax Data Breach 2017', 'Date': '2017-07-29', 'PwnCount': 147000000, 'Description': '147 million consumers affected'}
        ],
        'marriott.com': [
            {'Name': 'Marriott Data Breach 2018', 'Date': '2018-09-08', 'PwnCount': 500000000, 'Description': '500 million guest records'}
        ],
        'facebook.com': [
            {'Name': 'Facebook Data Breach 2019', 'Date': '2019-04-03', 'PwnCount': 533000000, 'Description': '533 million user records'}
        ],
        'twitter.com': [
            {'Name': 'Twitter Data Breach 2020', 'Date': '2020-07-15', 'PwnCount': 130000000, 'Description': '130 million user records'}
        ],
        'microsoft.com': [
            {'Name': 'Microsoft Data Breach 2020', 'Date': '2020-12-13', 'PwnCount': 250000000, 'Description': '250 million customer records'}
        ],
        'tiktok.com': [
            {'Name': 'TikTok Data Breach 2021', 'Date': '2021-09-20', 'PwnCount': 2000000000, 'Description': '2 billion user records'}
        ],
        'google.com': [
            {'Name': 'Google Data Breach 2018', 'Date': '2018-10-08', 'PwnCount': 50000000, 'Description': '50 million user accounts'}
        ],
        'amazon.com': [
            {'Name': 'Amazon Data Breach 2020', 'Date': '2020-11-20', 'PwnCount': 200000000, 'Description': '200 million customer records'}
        ]
    }
    
    # Check for exact domain match
    if domain in known_breaches:
        return known_breaches[domain]
    
    # Check for subdomain matches (e.g., mail.yahoo.com -> yahoo.com)
    for known_domain, breaches in known_breaches.items():
        if domain.endswith('.' + known_domain):
            return breaches
    
    # Check for common variations
    domain_variations = [
        domain.replace('www.', ''),
        'www.' + domain,
        domain.split('.')[0] if '.' in domain else domain
    ]
    
    for variation in domain_variations:
        if variation in known_breaches:
            return known_breaches[variation]
    
    return []

def check_website_breaches_live(domain: str):
    """
    Query Have I Been Pwned v3 API for breaches by domain.
    Requires env var HIBP_API_KEY. Falls back to [] on error.
    Output is normalized to a list of dicts with keys: Name, Date, PwnCount, Description.
    """
    if not HIBP_API_KEY:
        return []
    try:
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
        headers = {
            "hibp-api-key": HIBP_API_KEY,
            "user-agent": USER_AGENT,
            "accept": "application/json"
        }
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            items = resp.json() or []
            normalized = []
            for it in items:
                normalized.append({
                    "Name": it.get("Name") or it.get("Title") or domain,
                    "Date": it.get("BreachDate"),
                    "PwnCount": it.get("PwnCount"),
                    "Description": it.get("Description")
                })
            return normalized
        # 404 means no breach for that domain in HIBP
        if resp.status_code == 404:
            return []
        return []
    except Exception as e:
        print(f"HIBP domain query failed: {e}")
        return []

# -----------------------------
# Suspicious patterns
# -----------------------------
def check_suspicious_patterns(url):
    patterns = {
        'suspicious_keywords': ['login', 'account', 'verify', 'secure', 'update', 'confirm'],
        'suspicious_tlds': ['xyz', 'top', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq'],
        'suspicious_characters': ['@', '\\', '//', '..']
    }
    parsed = urlparse(url if '://' in url else 'http://' + url)
    # Evaluate special characters only within path+query to avoid flagging the scheme separator
    path_and_query = (parsed.path or '') + (('?' + parsed.query) if parsed.query else '')
    netloc_lower = (parsed.netloc or '').lower()
    results = {
        'contains_keywords': any(keyword in (netloc_lower + path_and_query).lower() for keyword in patterns['suspicious_keywords']),
        'suspicious_tld': False,
        'contains_suspicious_chars': (
            ('@' in path_and_query) or ('\\' in path_and_query) or ('//' in path_and_query) or ('..' in path_and_query)
        ),
        'ip_instead_of_domain': False
    }
    try:
        tld_obj = get_tld(url, as_object=True)
        if tld_obj and tld_obj.domain:
            results['suspicious_tld'] = tld_obj.domain in patterns['suspicious_tlds']
    except Exception:
        results['suspicious_tld'] = False

    try:
        results['ip_instead_of_domain'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', netloc_lower))
    except Exception:
        results['ip_instead_of_domain'] = False

    return results

# -----------------------------
# analyze_url
# -----------------------------
@app.route('/')
def index():
    try:
        # Try multiple candidate locations, return the first existing file
        candidates = [
            os.path.join(app.root_path, 'static', 'templates', 'index.html'),
            os.path.join(app.root_path, 'templates', 'index.html'),
        ]
        for path in candidates:
            if os.path.exists(path):
                return send_file(path)
        # As a last resort, try Flask template loader
        return render_template('index.html')
    except Exception as e:
        print(f"Error loading index.html: {e}")
        missing = " | ".join(candidates)
        return f"Error loading page: index.html (checked: {missing})", 500

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url = data.get('url', '')

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # WHOIS
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            registrar = w.registrar
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
                creation_date_str = creation_date.strftime('%Y-%m-%d')
            else:
                domain_age = 0
                creation_date_str = "Unknown"
            if not registrar:
                registrar = "Unknown"
        except Exception:
            creation_date_str = "Unknown"
            registrar = "Unknown"
            domain_age = 0

        # Response time
        start_time = time.time()
        try:
            response = requests.get(url, timeout=5, headers={"User-Agent": USER_AGENT})
            response_time = time.time() - start_time
            http_status = getattr(response, 'status_code', None)
        except Exception:
            response_time = 999
            http_status = None
            

        # SSL cert
        try:
            context = ssl.create_default_context()
            host = domain.split(':')[0]
            with socket.create_connection((host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    ssl_valid = True
                    try:
                        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d')
                    except Exception:
                        expiry = None
        except Exception:
            ssl_valid = False
            expiry = None

        # ML
        ml_analysis = None
        if url_analyzer:
            try:
                ml_analysis = url_analyzer.predict(url)
            except Exception as e:
                ml_analysis = {'prediction': 'unknown', 'confidence': 0, 'method': 'error'}

        # Threat score
        threat_score = 0
        if not ssl_valid:
            threat_score += 2
        if domain_age and domain_age < 365:
            threat_score += 1
        if response_time > 2:
            threat_score += 1
        if ml_analysis and ml_analysis.get('prediction') == 'malicious':
            threat_score += 3
        elif ml_analysis and ml_analysis.get('prediction') == 'suspicious':
            threat_score += 2

        if threat_score <= 1:
            risk_level = 'low-risk'
        elif threat_score <= 4:
            risk_level = 'medium-risk'
        else:
            risk_level = 'high-risk'

        return jsonify({
            'domain': domain,
            'risk_level': risk_level,
            'threat_score': threat_score,
            'ml_analysis': ml_analysis,
            'ssl_info': {'valid': ssl_valid, 'expiry': expiry},
            'features': {'response_time': response_time, 'http_status': http_status},
            'domain_info': {
                'creation_date': creation_date_str,
                'registrar': registrar,
                'age_days': domain_age
            },
            'suspicious_patterns': {
                'short_domain_age': bool(domain_age and domain_age < 365),
                'no_ssl': not ssl_valid,
                'slow_response': response_time > 2,
                'pattern_checks': check_suspicious_patterns(url)
            }
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'risk_level': 'error',
            'threat_score': 0,
            'ml_analysis': None,
            'ssl_info': {'valid': False},
            'features': {'response_time': 0},
            'domain_info': {'creation_date': "Unknown", 'registrar': "Unknown", 'age_days': 0},
            'suspicious_patterns': {}
        })

# -----------------------------
# Detailed ML
# -----------------------------
@app.route('/detailed_analysis', methods=['POST'])
def detailed_analysis():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        if url_analyzer:
            detailed_result = url_analyzer.get_detailed_analysis(url)
            # Remove raw extracted features from API response for cleaner UI
            if isinstance(detailed_result, dict) and 'features' in detailed_result:
                detailed_result.pop('features', None)
            return jsonify(detailed_result)
        else:
            return jsonify({'error': 'ML model not available'})
    except Exception as e:
        return jsonify({'error': str(e)})
@app.route('/system_metrics')
def system_metrics():
    try:
        errors = []
        # CPU
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
        except Exception as e:
            cpu_percent = 0
            errors.append(f'cpu_error: {e}')

        # Memory
        try:
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
        except Exception as e:
            memory_percent = 0
            errors.append(f'memory_error: {e}')

        # Disk: try multiple candidate paths so it works across platforms and odd envs
        disk_percent = 0
        disk_errors = []
        candidates = []
        try:
            if platform.system() == 'Windows':
                sd = os.getenv('SystemDrive')
                if sd:
                    candidates.append(os.path.join(sd + os.sep))
                    candidates.append(sd + os.sep)
                # common fallback
                candidates.append('C:\\')
            else:
                candidates.append('/')
        except Exception:
            pass
        # also try cwd and os.path.abspath(os.sep)
        try:
            candidates.append(os.path.abspath(os.sep))
        except Exception:
            pass
        try:
            candidates.append(os.getcwd())
        except Exception:
            pass

        # Ensure unique and non-empty
        seen = set()
        candidates = [c for c in candidates if c and (c not in seen and not seen.add(c))]

        for cpath in candidates:
            try:
                disk = psutil.disk_usage(cpath)
                disk_percent = disk.percent
                break
            except Exception as e:
                # if psutil fails for this path, try shutil as a fallback
                try:
                    du = shutil.disk_usage(cpath)
                    total, used, free = du.total, du.used, du.free
                    disk_percent = round((used / total) * 100, 1) if total else 0
                    break
                except Exception as e2:
                    disk_errors.append(f'{cpath}: psutil_error={e} | shutil_error={e2}')

        if disk_errors:
            errors.append('disk_error: ' + ' | '.join(disk_errors))

        # Frontend expects keys: cpu_percent, memory_percent, disk_percent
        result = {'cpu_percent': cpu_percent, 'memory_percent': memory_percent, 'disk_percent': disk_percent}
        if errors:
            result['errors'] = errors
        return jsonify(result)
    except Exception as e:
        return jsonify({'cpu_percent': 0, 'memory_percent': 0, 'disk_percent': 0, 'error': str(e)})

# -----------------------------
# New API endpoints
# -----------------------------

@app.route('/api/chatbot', methods=['POST'])
def api_chatbot():
    data = request.get_json()
    prompt = data.get('prompt', '')
    reply = chatbot_reply_ai(prompt)
    return jsonify({"reply": reply})

@app.route('/api/website_breached', methods=['POST'])
def api_website_breached():
    data = request.get_json()
    domain = data.get('domain', '')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    # Clean domain input
    domain = domain.lower().strip()
    if domain.startswith(('http://', 'https://')):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Prefer live API if key is present; otherwise fallback to offline list
    breaches = check_website_breaches_live(domain)
    if not breaches:
        breaches = check_website_breaches(domain)
    return jsonify({
        "domain": domain,
        "breaches": breaches,
        "breach_count": len(breaches)
    })


if __name__ == '__main__':
    print("Starting Flask application...")
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)