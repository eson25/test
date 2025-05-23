from flask import Flask, render_template, request, redirect, url_for, flash
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import requests
from models import db, User, BreachLog
from collections import Counter
from datetime import datetime
from dateutil.relativedelta import relativedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
db.init_app(app)  

with app.app_context():
    db.create_all()

API_KEY = "20e80cfdaea7408f9a04ecff835f233a"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/check-password', methods=['GET', 'POST'])
@login_required
def check_password():
    if request.method == 'POST':
        password = request.form['password']

        # Simple HIBP password check
        import hashlib
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        res = requests.get(url)

        pwned_count = 0
        if res.status_code == 200:
            hashes = (line.split(':') for line in res.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    pwned_count = int(count)
                    break

        return render_template('results.html', password=password, pwned_count=pwned_count)

    return render_template('check_password.html')

@app.route('/check-email', methods=['GET', 'POST'])
@login_required
def check_email():
    if request.method == 'POST':
        email = request.form['email']
        headers = {
            "hibp-api-key": API_KEY,
            "User-Agent": "PwnedCheckerApp"
        }
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            breaches = response.json()
            for breach in breaches:
                log = BreachLog(user_email=email, source=breach['Name'])
                db.session.add(log)
            db.session.commit()
            # Retrieve unique combinations of user_email and source
            unique_logs = db.session.query(
                BreachLog.user_email, BreachLog.source
            ).distinct().all()

            # Counts each source only once per email
            source_counts = {}
            for email, source in unique_logs:
                source_counts[source] = source_counts.get(source, 0) + 1

            labels = list(source_counts.keys())
            data = list(source_counts.values())

            all_logs = BreachLog.query.all()
            months = [log.timestamp.strftime("%Y-%m") for log in all_logs if log.timestamp]
            month_counts = Counter(months)
            timeline_labels = sorted(month_counts.keys())
            timeline_data = [month_counts[m] for m in timeline_labels]

            #Advice stuff
            all_data_classes = set()
            for breach in breaches:
                all_data_classes.update(breach.get("DataClasses", []))

                advice = []

                if "Passwords" in all_data_classes:
                    advice.append("🔒 Change your password immediately and avoid reusing passwords across sites, install a password manager such as bitwarden.")
                if "Email addresses" in all_data_classes:
                    advice.append("📬 Be cautious of phishing emails pretending to be from trusted services double check links before clicking.")
                if "Phone numbers" in all_data_classes:
                    advice.append("📱 Be wary of scam calls or messages. Consider enabling spam filtering on your device.")
                if "Usernames" in all_data_classes:
                    advice.append("👤 Avoid using the same username-password combo across websites.")
                if "Physical addresses" in all_data_classes:
                    advice.append("🏠 Monitor for suspicious physical mail or packages.")
                if "IP addresses" in all_data_classes:
                    advice.append("🌐 Consider using a VPN when browsing to obscure your location.")
                if not advice:
                    advice.append("✅ No sensitive data types were found. Still, stay safe and monitor your accounts.")

            return render_template('results.html', email=email, breaches=breaches, labels=labels, data=data, advice=advice, timeline_labels=timeline_labels,timeline_data=timeline_data)
        
        
        elif response.status_code == 404:
            return render_template('results.html', email=email, breaches=[], labels=[], data=[])
        
        else:
            flash("Error checking email", "danger")
            return redirect(url_for('check_email'))

    return render_template('check_email.html')



@app.route('/')
def home():
    return render_template('home.html')

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully", "success")
        return redirect(url_for('login'))
    return render_template('register.html', show_navbar=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        flash("Invalid credentials", "danger")
    return render_template('login.html', show_navbar=False)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    breaches = []
    if request.method == 'POST':
        email = request.form['email']
        headers = {
            'hibp-api-key': API_KEY,
            'user-agent': 'PwnedCheckerApp'
        }
        response = requests.get(f"{HIBP_URL}{email}?truncateResponse=false", headers=headers)
        if response.status_code == 200:
            breaches = response.json()
        elif response.status_code == 404:
            flash("No breaches found!", "info")
        else:
            flash("Error contacting API.", "danger")
    return render_template('dashboard.html', breaches=breaches)

@app.route('/breach-graph')
def breach_graph():
    from models import BreachLog
    from collections import Counter

    breaches = BreachLog.query.all()
    sources = [b.source for b in breaches]

    labels = list(counts.keys())
    data = list(counts.values())

    return render_template("breach_graph.html", labels=labels, data=data)
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0")

@app.route('/api/breach-timeline')
@login_required
def api_breach_timeline():
    # Only logs from the last 2 years
    cutoff = datetime.utcnow() - relativedelta(years=2)
    logs = BreachLog.query.filter(BreachLog.timestamp >= cutoff).all()

    # Group by month ("YYYY-MM")
    months = [log.timestamp.strftime("%Y-%m") for log in logs]
    counts = {}
    for m in months:
        counts[m] = counts.get(m, 0) + 1

    # Sort chronologically
    labels = sorted(counts.keys())
    data = [counts[m] for m in labels]

    return jsonify(labels=labels, data=data)
