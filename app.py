import os
import re
import ssl
import socket
import pickle
import time
import urllib.parse
import urllib3
import numpy as np

from datetime import datetime
from flask import Flask, render_template, request, jsonify, make_response
from dotenv import load_dotenv

# Load local environment variables from .env file
load_dotenv()

# Suppress urllib3 InsecureRequestWarning for SSL verification bypass
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
    from requests.exceptions import SSLError, ConnectionError, Timeout
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# ── App Setup ──────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cybersec_ml_secret_2024")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Set the GROQ_API_KEY environment variable in production; the fallback below is for local development only.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

CHATBOT_SYSTEM_PROMPT = """You are SecureU Assistant, a cybersecurity AI embedded in the SecureU Website Checker.
Your role is to help users understand SSL/TLS, security headers, phishing, XSS, SQL injection,
clickjacking, MITM attacks, and how to read their scan results.
Keep responses concise (2-4 sentences), friendly, and actionable.
If a question is unrelated to cybersecurity, politely redirect to security topics."""


# ── Load ML Model ──────────────────────────────────────────────────────────

def load_models():
    models_dir = os.path.join(BASE_DIR, "models")
    try:
        with open(os.path.join(models_dir, "model.pkl"), "rb") as f:
            model = pickle.load(f)
        with open(os.path.join(models_dir, "scaler.pkl"), "rb") as f:
            scaler = pickle.load(f)
        print("[+] ML model loaded successfully")
        return model, scaler
    except FileNotFoundError:
        print("[!] Model files not found. Run train_model.py first.")
        return None, None

MODEL, SCALER = load_models()


# ── Security Checks ────────────────────────────────────────────────────────

def check_ssl(url):
    result = {"has_https": False, "ssl_valid": False, "ssl_error": None, "score": 0}

    if not url.startswith("https://"):
        result["ssl_error"] = "No HTTPS — data transmitted in plaintext"
        return result

    result["has_https"] = True
    try:
        hostname = urllib.parse.urlparse(url).hostname
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()

        if cert:
            result["ssl_valid"] = True
            result["score"] = 20
        else:
            result["ssl_error"] = "Certificate not found"
            result["score"] = 10

    except ssl.SSLCertVerificationError as e:
        result["ssl_error"] = f"SSL Verification Error: {str(e)[:60]}"
        result["score"] = 5
    except Exception as e:
        result["ssl_valid"] = True
        result["ssl_error"] = f"Note: {str(e)[:60]}"
        result["score"] = 15

    return result


def check_security_headers(url):
    HEADERS = {
        "Content-Security-Policy":   {"short": "CSP",          "description": "Prevents XSS and data injection attacks",       "recommendation": "Add Content-Security-Policy header to restrict resource loading"},
        "X-Frame-Options":           {"short": "X-Frame",       "description": "Prevents clickjacking attacks",                 "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN"},
        "Strict-Transport-Security": {"short": "HSTS",          "description": "Forces HTTPS connections",                     "recommendation": "Add Strict-Transport-Security: max-age=31536000"},
        "X-XSS-Protection":          {"short": "XSS-Protect",   "description": "Enables browser XSS filter",                   "recommendation": "Add X-XSS-Protection: 1; mode=block"},
        "X-Content-Type-Options":    {"short": "Content-Type",  "description": "Prevents MIME-type sniffing",                  "recommendation": "Add X-Content-Type-Options: nosniff"},
        "Referrer-Policy":           {"short": "Referrer",      "description": "Controls referrer information",                "recommendation": "Add Referrer-Policy: no-referrer-when-downgrade"},
    }

    result = {"present": [], "missing": [], "score": 0, "max_score": 20, "raw_headers": {}}

    if not REQUESTS_AVAILABLE:
        result["missing"] = [{**v, "header": k} for k, v in HEADERS.items()]
        return result

    try:
        resp = requests.get(url, timeout=5, verify=False, allow_redirects=True, stream=True,
                            headers={"User-Agent": "Mozilla/5.0"})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        result["raw_headers"] = dict(resp.headers)
        resp.close()

        points_each = result["max_score"] / len(HEADERS)
        for header, meta in HEADERS.items():
            if header.lower() in headers:
                result["present"].append({"header": header, "value": headers[header.lower()], **meta})
                result["score"] += points_each
            else:
                result["missing"].append({"header": header, **meta})

        result["score"] = round(result["score"])

    except Exception as e:
        result["error"]   = str(e)
        result["missing"] = [{**v, "header": k} for k, v in HEADERS.items()]

    return result


def analyze_url(url):
    result = {"url_length": len(url), "has_ip": False, "suspicious_patterns": [], "special_char_count": 0, "score": 20}

    parsed   = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    url_low  = url.lower()

    # IP-based URL
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
        result["has_ip"] = True
        result["suspicious_patterns"].append("⚠ IP address used instead of domain name")
        result["score"] -= 10

    # Long URL
    if len(url) > 75:
        result["suspicious_patterns"].append(f"⚠ Unusually long URL ({len(url)} chars) — phishing indicator")
        result["score"] -= 5

    # Special characters
    special = re.findall(r"[@$%&\-_~=+]", url)
    result["special_char_count"] = len(special)
    if len(special) > 6:
        result["suspicious_patterns"].append(f"⚠ High special character count ({len(special)}) in URL")
        result["score"] -= 3

    # Excessive subdomains
    subdomain_count = len(hostname.split(".")) - 2
    if subdomain_count > 2:
        result["suspicious_patterns"].append(f"⚠ Excessive subdomains ({subdomain_count}) — possible typosquatting")
        result["score"] -= 5

    # Brand keyword impersonation
    brands = ["paypal", "amazon", "google", "facebook", "apple", "microsoft",
              "bank", "secure", "login", "verify", "account", "password", "update", "confirm"]
    matched = [b for b in brands if b in url_low]
    if len(matched) >= 2:
        result["suspicious_patterns"].append(f"⚠ Multiple brand keywords in URL: {', '.join(matched)}")
        result["score"] -= 5

    # Suspicious TLDs
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".club", ".ru", ".su", ".biz."]
    for tld in suspicious_tlds:
        if url_low.endswith(tld) or tld + "/" in url_low:
            result["suspicious_patterns"].append(f"⚠ Suspicious TLD detected: {tld}")
            result["score"] -= 3
            break

    # URL encoding obfuscation
    if "%" in url and url.count("%") > 3:
        result["suspicious_patterns"].append("⚠ URL encoding detected — possible obfuscation attempt")
        result["score"] -= 3

    result["score"] = max(0, result["score"])
    return result


def check_vulnerabilities(url, page_content=""):
    result = {"xss_risk": False, "sqli_risk": False, "findings": [], "score": 20}

    content_low = page_content.lower()
    url_low     = url.lower()

    xss_patterns = {
        r"<script[^>]*>": "<script> tag",   r"javascript:": "javascript: URI",
        r"onerror\s*=": "onerror handler",  r"onload\s*=": "onload handler",
        r"alert\s*\(": "alert() call",      r"document\.cookie": "document.cookie access",
        r"eval\s*\(": "eval() execution",   r"innerHTML": "innerHTML manipulation",
        r"<iframe": "<iframe> tag",         r"src=['\"]javascript": "JS source payload",
    }
    xss_hits = [name for pat, name in xss_patterns.items()
                if re.search(pat, content_low) or re.search(pat, url_low)]
    if xss_hits:
        result["xss_risk"] = True
        result["findings"].append(f"⚠ Potential XSS indicators found: {', '.join(xss_hits[:3])}")
        result["score"] -= 10

    sqli_patterns = {
        r"union\s+select": "UNION SELECT",   r"'\s*or\s+'1'\s*=\s*'1": "OR 1=1 bypass",
        r"drop\s+table": "DROP TABLE",       r"insert\s+into": "INSERT INTO",
        r"--\s*$": "SQL comment",            r";\s*select": "Stacked query",
        r"xp_cmdshell": "xp_cmdshell",       r"exec\s*\(": "EXEC()",
        r"1\s*=\s*1": "Tautology (1=1)",     r"sleep\s*\(": "Time-based payload",
    }
    sqli_hits = [name for pat, name in sqli_patterns.items()
                 if re.search(pat, url_low) or re.search(pat, content_low)]
    if sqli_hits:
        result["sqli_risk"] = True
        result["findings"].append(f"⚠ SQL Injection pattern detected ({', '.join(sqli_hits[:2])})")
        result["score"] -= 10

    if re.search(r"redirect=https?://", url_low):
        result["findings"].append("⚠ Open redirect parameter detected in URL")
        result["score"] -= 5

    result["score"] = max(0, result["score"])
    return result


def check_availability(url):
    result = {"reachable": False, "status_code": None, "response_time": None,
              "content": "", "title": "", "error": None, "score": 20}

    if not REQUESTS_AVAILABLE:
        result["error"]     = "requests library not available"
        result["reachable"] = True
        return result

    try:
        start = time.time()
        resp  = requests.get(url, timeout=5, verify=False, allow_redirects=True, stream=True,
                             headers={"User-Agent": "Mozilla/5.0 (CyberSec-Checker/1.0)"})

        chunks, bytes_read = [], 0
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                chunks.append(chunk.decode(errors="ignore"))
                bytes_read += len(chunk)
                if bytes_read > 50000:
                    break

        content = "".join(chunks)
        result.update({
            "reachable":     True,
            "status_code":   resp.status_code,
            "response_time": round((time.time() - start) * 1000, 2),
            "content":       content[:5000],
        })

        if BS4_AVAILABLE:
            soup      = BeautifulSoup(content, "html.parser")
            title_tag = soup.find("title")
            result["title"] = title_tag.text.strip()[:80] if title_tag else ""

        if resp.status_code >= 400:
            result["score"] = 10
            result["error"] = f"HTTP {resp.status_code} error"

    except Timeout:
        result["error"] = "Request timed out (>10s)"
        result["score"] = 0
    except ConnectionError:
        result["error"] = "Cannot connect — host unreachable or DNS failure"
        result["score"] = 0
    except SSLError:
        result["error"]     = "SSL/TLS handshake failed"
        result["reachable"] = True
        result["score"]     = 10
    except Exception as e:
        result["error"] = str(e)[:100]
        result["score"] = 0

    return result


# ── ML Classification ──────────────────────────────────────────────────────

def ml_classify(url):
    if MODEL is None or SCALER is None:
        return {"prediction": "Unknown", "probability": 0, "confidence": 0,
                "features_used": [], "error": "Model not loaded. Run train_model.py first."}

    parsed   = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    features = np.array([[
        len(url),
        1 if url.startswith("https://") else 0,
        len(re.findall(r"[@$%&\-_~=+]", url)),
        1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) else 0,
    ]])

    scaled     = SCALER.transform(features)
    prediction = MODEL.predict(scaled)[0]
    proba      = MODEL.predict_proba(scaled)[0]

    return {
        "prediction":  "Malicious" if prediction == 1 else "Safe",
        "probability": round(proba[1] * 100, 2),
        "confidence":  round(max(proba) * 100, 2),
        "features_used": {
            "url_length":        int(features[0][0]),
            "has_https":         int(features[0][1]),
            "special_char_count": int(features[0][2]),
            "has_ip":            int(features[0][3]),
        }
    }


# ── Score Calculation ──────────────────────────────────────────────────────

def calculate_score(ssl, headers, url_analysis, vuln, availability):
    total = max(0, min(100,
        ssl.get("score", 0) + headers.get("score", 0) +
        url_analysis.get("score", 0) + vuln.get("score", 0) +
        availability.get("score", 0)
    ))

    if   total >= 80: grade, level, color = "A", "Safe",       "success"
    elif total >= 60: grade, level, color = "B", "Moderate",   "warning"
    elif total >= 40: grade, level, color = "C", "Suspicious", "orange"
    else:             grade, level, color = "D", "Malicious",  "danger"

    return {
        "total": total, "grade": grade, "level": level, "color": color,
        "breakdown": {
            "ssl":             ssl.get("score", 0),
            "headers":         headers.get("score", 0),
            "url":             url_analysis.get("score", 0),
            "vulnerabilities": vuln.get("score", 0),
            "availability":    availability.get("score", 0),
        }
    }


# ── Recommendation Engine ──────────────────────────────────────────────────

def build_recommendations(ssl, headers, url_analysis, vuln, ml):
    recs = []

    if not ssl.get("has_https"):
        recs.append({"category": "SSL/TLS", "priority": "Critical", "issue": "No HTTPS Detected",
                     "fix": "Install an SSL/TLS certificate (e.g., Let's Encrypt). Redirect all HTTP to HTTPS.",
                     "impact": "Protects data in transit from eavesdropping and MITM attacks"})

    if ssl.get("ssl_error") and ssl.get("has_https"):
        recs.append({"category": "SSL/TLS", "priority": "High", "issue": "SSL Certificate Issue",
                     "fix": "Renew or replace the SSL certificate. Ensure it is from a trusted CA and not expired.",
                     "impact": "Prevents browser security warnings and certificate spoofing"})

    for h in headers.get("missing", []):
        recs.append({"category": "Security Headers", "priority": "High",
                     "issue": f"Missing {h['header']}", "fix": h["recommendation"], "impact": h["description"]})

    if url_analysis.get("has_ip"):
        recs.append({"category": "URL Security", "priority": "Critical", "issue": "IP Address Used as Domain",
                     "fix": "Register a proper domain name. IP-based URLs are a strong phishing indicator.",
                     "impact": "Establishes legitimate identity and builds user trust"})

    for pattern in url_analysis.get("suspicious_patterns", []):
        recs.append({"category": "URL Security", "priority": "Medium", "issue": "Suspicious URL Pattern",
                     "fix": f"Review and simplify the URL structure. {pattern}",
                     "impact": "Reduces phishing risk score and improves user trust"})

    if vuln.get("xss_risk"):
        recs.append({"category": "Web Security", "priority": "Critical", "issue": "Potential XSS Vulnerability",
                     "fix": "Implement output encoding, use CSP, and validate all user inputs.",
                     "impact": "Prevents attackers from injecting malicious scripts"})

    if vuln.get("sqli_risk"):
        recs.append({"category": "Web Security", "priority": "Critical", "issue": "SQL Injection Risk Detected",
                     "fix": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                     "impact": "Prevents unauthorized database access and data breaches"})

    if ml.get("prediction") == "Malicious":
        recs.append({"category": "ML Analysis", "priority": "Critical",
                     "issue": f"ML Model: URL classified as Malicious ({ml.get('confidence', 0)}% confidence)",
                     "fix": "Investigate URL structure. Remove IP references, implement HTTPS, reduce special characters.",
                     "impact": "Improves URL trust score across security tools"})

    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recs.sort(key=lambda r: priority_order.get(r["priority"], 4))
    return recs


# ── Helper: Full Scan ──────────────────────────────────────────────────────

def run_full_scan(url):
    """Run all checks on a URL and return the complete result dict."""
    availability = check_availability(url)
    page_content = availability.get("content", "")

    ssl             = check_ssl(url)
    headers         = check_security_headers(url)
    url_analysis    = analyze_url(url)
    vulnerabilities = check_vulnerabilities(url, page_content)
    ml              = ml_classify(url)
    score           = calculate_score(ssl, headers, url_analysis, vulnerabilities, availability)
    recommendations = build_recommendations(ssl, headers, url_analysis, vulnerabilities, ml)

    return {
        "url":             url,
        "scan_time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score":           score,
        "ssl":             ssl,
        "headers":         headers,
        "url_analysis":    url_analysis,
        "vulnerabilities": vulnerabilities,
        "availability":    availability,
        "ml_classification": ml,
        "recommendations": recommendations,
        "total_issues": (
            (0 if ssl.get("ssl_valid") else 1) +
            len(headers.get("missing", [])) +
            len(url_analysis.get("suspicious_patterns", [])) +
            len(vulnerabilities.get("findings", []))
        ),
    }


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("index.html", error="Please enter a URL.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        urllib.parse.urlparse(url)
    except Exception:
        return render_template("index.html", error="Invalid URL format.")

    result = run_full_scan(url)
    return render_template("result.html", result=result)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    r = run_full_scan(url)
    return jsonify({
        "url":           r["url"],
        "score":         r["score"]["total"],
        "level":         r["score"]["level"],
        "ml_prediction": r["ml_classification"]["prediction"],
        "ml_confidence": r["ml_classification"]["confidence"],
    })


@app.route("/download_report")
def download_report():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400

    r = run_full_scan(url)

    missing_hdrs  = "\n".join([f"  - {h['header']}: {h['description']}" for h in r["headers"].get("missing", [])])
    url_issues    = "\n".join([f"  - {i}" for i in r["url_analysis"].get("suspicious_patterns", [])]) or "  - None detected"
    vuln_findings = "\n".join([f"  - {f}" for f in r["vulnerabilities"].get("findings", [])]) or "  - None detected"
    recs          = "\n".join([f"  [{rec['priority']}] {rec['issue']}\n    -> Fix: {rec['fix']}" for rec in r["recommendations"]]) or "  - No critical actions needed"
    score         = r["score"]
    ml            = r["ml_classification"]
    ssl           = r["ssl"]

    report = f"""{"="*60}
CYBERSECURITY ANALYSIS REPORT
{"="*60}
Target URL : {url}
Date/Time  : {r['scan_time']}
Grade      : {score['grade']} ({score['level']})
Total Score: {score['total']}/100

-- ML CLASSIFICATION --
Result: {ml.get('prediction')} ({ml.get('confidence')}% confidence)

-- SSL / TLS --
HTTPS     : {ssl.get('has_https')}
Valid Cert: {ssl.get('ssl_valid')}
Issues    : {ssl.get('ssl_error') or 'None'}

-- MISSING SECURITY HEADERS --
{missing_hdrs}

-- URL HEURISTICS --
{url_issues}

-- VULNERABILITY SCAN --
{vuln_findings}

-- RECOMMENDATIONS --
{recs}

{"="*60}
Generated by SecureU Scanner
"""

    response = make_response(report)
    response.headers["Content-Disposition"] = "attachment; filename=secureu_report.txt"
    response.headers["Content-Type"]        = "text/plain; charset=utf-8"
    return response


@app.route("/chat", methods=["POST"])
def chat():
    data         = request.get_json()
    msg          = data.get("msg", "")
    history      = data.get("history", [])
    scan_context = data.get("scan_context", "")

    if not msg:
        return jsonify({"reply": "Please enter a message."})

    system_prompt = CHATBOT_SYSTEM_PROMPT
    if scan_context:
        system_prompt += f"\n\n--- CURRENT SCAN REPORT ---\n{scan_context}\n--- END OF REPORT ---\nUse the data above to give precise, actionable advice tailored to this website's actual issues."

    messages = [{"role": "system", "content": system_prompt}]
    for turn in history[-6:]:
        messages.append({"role": turn["role"], "content": turn["content"]})
    messages.append({"role": "user", "content": msg})

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={"model": "llama-3.3-70b-versatile", "messages": messages, "max_tokens": 400},
            timeout=15,
        )
        reply = resp.json()["choices"][0]["message"]["content"] if resp.status_code == 200 \
                else f"Error {resp.status_code}: Could not reach AI service."
    except Exception as e:
        reply = f"Connection error: {str(e)}"

    return jsonify({"reply": reply})


# ── Entry Point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)