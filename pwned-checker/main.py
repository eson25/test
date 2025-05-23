from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import requests
from models import db, User, BreachLog
from collections import Counter

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

@app.route('/check-password')
def check_password():
    return "<h2>Password check tool coming soon!</h2><a href='/'>Back</a>"

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
            # Aggregate data
            all_logs = BreachLog.query.all()
            sources = [entry.source for entry in all_logs]
            counts = Counter(sources)
            labels = list(counts.keys())
            data = list(counts.values())
            return render_template('results.html', email=email, breaches=breaches, labels=labels, data=data)
        
        
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
    counts = Counter(sources)

    labels = list(counts.keys())
    data = list(counts.values())

    return render_template("breach_graph.html", labels=labels, data=data)
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0")
