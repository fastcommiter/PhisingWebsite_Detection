from flask import Flask, request, render_template, redirect, url_for, session
import numpy as np
import warnings
import pickle
import re
from urllib.parse import urlparse

warnings.filterwarnings('ignore')
from feature import FeatureExtraction
from convert import convertion
from database import init_db, save_scan, get_user_scans, get_user_stats, delete_scans

# --- FLASK APP INITIALIZATION (Pehle define karna zaroori hai) ---
app = Flask(__name__)
app.secret_key = "phishdetector_secret_key"

init_db()

# --- MODEL LOADING ---
try:
    # Pehle try karenge model load karne ka
    file = open("newmodel.pkl", "rb")
    gbc = pickle.load(file)
    file.close()
except Exception as e:
    # Agar model fail ho jaye, toh project crash nahi hoga, dummy model load hoga
    print(f"WARNING: Model load nahi hua ({e}), dummy model use ho raha hai.")
    from sklearn.ensemble import GradientBoostingClassifier
    gbc = GradientBoostingClassifier()
    # Dummy fit taaki code run ho sake
    gbc.fit(np.zeros((10, 30)), [0,1,0,1,1,0,1,0,1,0])

TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com',
    'leetcode.com', 'wikipedia.org', 'linkedin.com', 'twitter.com',
    'instagram.com', 'reddit.com', 'netflix.com', 'flipkart.com',
    'paytm.com', 'irctc.co.in', 'sbi.co.in', 'hdfcbank.com',
    'geeksforgeeks.org', 'hackerrank.com', 'codechef.com',
    'coursera.org', 'udemy.com', 'medium.com', 'notion.so',
    'canva.com', 'figma.com', 'npmjs.com', 'pypi.org',
    'docker.com', 'heroku.com', 'vercel.com', 'netlify.com',
    'digitalocean.com', 'anthropic.com', 'openai.com',
    'huggingface.co', 'kaggle.com', 'w3schools.com',
    'mozilla.org', 'python.org', 'geu.ac.in', 'graphicera.edu.in',
    'x.com', 'whatsapp.com', 'zoom.us', 'slack.com',
    'trello.com', 'atlassian.com', 'jira.atlassian.com',
    'dropbox.com', 'onedrive.live.com', 'sharepoint.com',
    'office.com', 'live.com', 'outlook.com', 'hotmail.com',
    'yahoo.com', 'gmail.com', 'protonmail.com'
]


# --- TYPOSQUATTING DETECTION ---
SQUATTING_TARGETS = [
    'google', 'youtube', 'facebook', 'amazon', 'microsoft', 'apple',
    'instagram', 'twitter', 'whatsapp', 'netflix', 'paypal', 'paytm',
    'linkedin', 'github', 'gmail', 'yahoo', 'outlook', 'hotmail',
    'sbi', 'hdfc', 'icici', 'irctc', 'flipkart', 'snapdeal',
    'reddit', 'wikipedia', 'dropbox', 'zoom', 'slack'
]

def _edit_distance(s1, s2):
    if len(s1) < len(s2):
        return _edit_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(0 if c1==c2 else 1)))
        prev = curr
    return prev[-1]

def is_typosquatting(url):
    try:
        root = get_root_domain(url)
        domain_name = root.split('.')[0].lower()
        for target in SQUATTING_TARGETS:
            if domain_name == target:
                continue
            if target in domain_name and domain_name != target:
                return True
            if _edit_distance(domain_name, target) <= 2 and len(target) >= 5:
                return True
    except:
        pass
    return False


# --- SUSPICIOUS KEYWORD DETECTION ---
SUSPICIOUS_KEYWORDS = [
    # Money scams
    'getfreemoney', 'freemoney', 'earnmoney', 'makemoney', 'fastcash',
    'freecash', 'getcash', 'instantcash', 'freegift', 'freeprize',
    'winner', 'youwin', 'youwon', 'claimprize', 'claimreward',
    'freeiphone', 'freegiveaway', 'giveaway',
    # Urgency / fear
    'accountsuspended', 'accountblocked', 'verifynow', 'confirmnow',
    'urgent', 'alertsecurity', 'securityalert', 'suspiciousactivity',
    'unusualactivity', 'limitedtime', 'expiringsoon', 'actfast',
    # Credential harvesting
    'login-verify', 'signin-verify', 'verify-account', 'update-account',
    'confirm-identity', 'validateaccount', 'reactivate',
    # Crypto scams
    'cryptogiveaway', 'bitcoinfree', 'ethgiveaway', 'doublecrypto',
    # Generic scam patterns
    '1000aday', '500aday', 'workfromhome-earn', 'earnfromhome',
    'getrichfast', 'richfast', 'millionaire-secret',
]

# Single high-risk words that alone indicate scam (checked separately on word-split)
SINGLE_RISK_WORDS = [
    'prize', 'giveaway', 'winner', 'freegift', 'claimfree',
    'jackpot', 'lottery', 'luckywin', 'sweepstake',
]

def has_suspicious_keywords(url):
    """URL mein scam keywords check karo (case-insensitive, hyphens/dots ignore)"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        # Sirf domain + path check karo, lowercase, punctuation hata do
        url_clean = (parsed.netloc + parsed.path).lower()
        url_nopunct = url_clean.replace('-','').replace('_','').replace('.','').replace('/','')
        for kw in SUSPICIOUS_KEYWORDS:
            kw_clean = kw.replace('-','').replace('_','')
            if kw_clean in url_nopunct:
                return True
        # Single high-risk words (only flag if domain contains them, not just path)
        domain_clean = parsed.netloc.lower().replace('-','').replace('.','')
        for word in SINGLE_RISK_WORDS:
            if word in domain_clean:
                return True
    except:
        pass
    return False

# --- UTILITY FUNCTIONS ---
def get_root_domain(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        hostname = parsed.netloc.lower()
        hostname = re.sub(r'^www\.', '', hostname)
        parts = hostname.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname
    except:
        return ''

def is_trusted(url):
    root = get_root_domain(url)
    if not root:
        return False
    for domain in TRUSTED_DOMAINS:
        trusted_root = get_root_domain('http://' + domain)
        if root == trusted_root:
            return True
    return False

def get_risk_score(features, is_safe, phish_proba=None):
    """
    Proba-based risk score:
    - Phishing (is_safe=False): score 89-99  (higher proba = higher score)
    - Safe (is_safe=True):      score 5-30   (lower proba = lower score)
    - phish_proba: model ki probability ki URL phishing hai (0.0 - 1.0)
    """
    if phish_proba is None:
        # Fallback: feature ratio se estimate karo
        suspicious = sum(1 for f in features if f == -1)
        phish_proba = suspicious / len(features)

    if not is_safe:
        # Phishing range: 89 to 99
        score = int(89 + (phish_proba * 10))
        return min(99, max(89, score))
    else:
        # Safe range: 5 to 30
        score = int(5 + (phish_proba * 50))
        return min(30, max(5, score))

def get_risk_level(score):
    if score < 25: return "Low"
    elif score < 50: return "Medium"
    elif score < 75: return "High"
    else: return "Critical"

def get_threat_details(features):
    labels = [
        "IP Address in URL", "Long URL", "Short URL Service", "@ Symbol in URL",
        "Redirecting with //", "Prefix/Suffix with -", "Multi Subdomain",
        "SSL Certificate", "Domain Registration Length", "Favicon", "Port",
        "HTTPS in Domain", "Request URL", "Anchor URL", "Links in Tags",
        "SFH", "Email Submit", "Abnormal URL", "Redirect", "On Mouseover",
        "Right Click Disabled", "Popup Window", "Iframe", "Domain Age",
        "DNS Record", "Web Traffic", "Page Rank", "Google Index",
        "Links Pointing", "Statistical Report"
    ]
    threats = []
    safe_features = []
    for i, f in enumerate(features):
        if i < len(labels):
            if f == -1: threats.append(labels[i])
            else: safe_features.append(labels[i])
    return threats, safe_features

def smart_predict(features, model, url=''):
    """Returns (y_pred, phish_proba) tuple.
    phish_proba = probability that URL is phishing (0.0 to 1.0)
    """
    if is_trusted(url):
        return 1, 0.02  # trusted = almost zero phish probability

    if is_typosquatting(url):
        return -1, 0.95  # typosquat = high confidence phishing

    if has_suspicious_keywords(url):
        return -1, 0.92  # scam keyword in URL

    x = np.array(features).reshape(1, 30)
    y_pred  = model.predict(x)[0]
    y_proba = model.predict_proba(x)[0]
    # y_proba[0] = prob of class -1 (phishing), y_proba[1] = prob of class 1 (safe)
    phish_proba = float(y_proba[0])

    suspicious_count = sum(1 for f in features if f == -1)
    suspicious_ratio = suspicious_count / len(features)

    if suspicious_ratio >= 0.40:
        y_pred = -1
        phish_proba = max(phish_proba, 0.85)
    elif suspicious_ratio >= 0.30 and y_proba[1] < 0.60:
        y_pred = -1
        phish_proba = max(phish_proba, 0.70)
    elif y_pred == 1 and y_proba[1] >= 0.60:
        y_pred = 1
        phish_proba = min(phish_proba, 0.40)

    return int(y_pred), phish_proba

# --- ROUTES ---
@app.route("/login")
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/login/verify", methods=["POST"])
def verify_login():
    email = request.form.get("email")
    name  = request.form.get("name")
    if email and name:
        session["user"] = {"email": email, "name": name}
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/")
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route('/result', methods=['POST', 'GET'])
def predict():
    if "user" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        url = request.form["name"]
        obj = FeatureExtraction(url)
        features = obj.getFeaturesList()

        y_pred, phish_proba = smart_predict(features, gbc, url)
        is_safe    = y_pred == 1
        risk_score = get_risk_score(features, is_safe, phish_proba)
        result_text = "Safe" if is_safe else "Unsafe"

        save_scan(session["user"]["email"], url, result_text, 1 if is_safe else 0, risk_score)
        return redirect(url_for("report", url=url))
    return redirect(url_for("home"))

@app.route('/report')
def report():
    if "user" not in session:
        return redirect(url_for("login"))
    url = request.args.get("url", "")
    if not url: return redirect(url_for("home"))

    obj = FeatureExtraction(url)
    features = obj.getFeaturesList()
    y_pred, phish_proba = smart_predict(features, gbc, url)
    is_safe = y_pred == 1
    risk_score = get_risk_score(features, is_safe, phish_proba)
    risk_level = get_risk_level(risk_score)
    threats, safe_features = get_threat_details(features)

    return render_template("report.html", url=url, is_safe=is_safe, risk_score=risk_score, 
                           risk_level=risk_level, threats=threats, safe_features=safe_features,
                           result="Safe" if is_safe else "Unsafe", user=session["user"])

@app.route('/dashboard')
def dashboard():
    if "user" not in session: return redirect(url_for("login"))
    stats = get_user_stats(session["user"]["email"])
    return render_template("dashboard.html", stats=stats, user=session["user"])

@app.route('/history')
def history():
    if "user" not in session: return redirect(url_for("login"))
    scans = get_user_scans(session["user"]["email"])
    return render_template("history.html", scans=scans, user=session["user"])

@app.route('/usecases', methods=['GET', 'POST'])
def usecases():
    if "user" not in session: return redirect(url_for("login"))
    return render_template('usecases.html')


@app.route('/history/delete', methods=['POST'])
def delete_history():
    if "user" not in session:
        return {"success": False}, 401
    from flask import jsonify
    data = request.get_json()
    ids = data.get('ids', [])
    if ids:
        delete_scans(session["user"]["email"], ids)
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True)