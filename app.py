from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError
from datetime import datetime
import os
import re

# -------------------------------------------------
# APP INIT
# -------------------------------------------------
app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'local_secret_key')

# -------------------------------------------------
# MYSQL CONFIG (RENDER + AIVEN SAFE)
# -------------------------------------------------
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3306))
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# SSL for Aiven (التعديل الصحيح والمضمون)
if os.environ.get('MYSQL_HOST') and os.environ.get('MYSQL_HOST') != 'localhost':
    app.config['MYSQL_CUSTOM_OPTIONS'] = {
        "ssl": {
            "ca": "/etc/ssl/certs/ca-certificates.crt"
        }
    }

mysql = MySQL(app)

# -------------------------------------------------
# UPLOAD FOLDERS (RENDER SAFE)
# -------------------------------------------------
app.config['PROFILE_UPLOAD_FOLDER'] = 'static/uploads/profiles'
app.config['IMAGE_UPLOAD_FOLDER'] = 'static/uploads/images'

os.makedirs(app.config['PROFILE_UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['IMAGE_UPLOAD_FOLDER'], exist_ok=True)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain one special character."
    return True, ""

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route('/')
def home():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("SELECT * FROM articles ORDER BY created_at DESC LIMIT 3")
        recent_articles = cursor.fetchall()
    except:
        recent_articles = []

    try:
        cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 3")
        recent_events = cursor.fetchall()
    except:
        recent_events = []

    cursor.close()
    return render_template('index.html',
                           recent_articles=recent_articles,
                           recent_events=recent_events)

# -------------------------------------------------
# AUTH
# -------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['username'] = user['first_name']
            flash("Login successful", "success")
            return redirect(url_for('profile'))

        flash("Invalid credentials", "danger")

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        confirm = request.form['confirm_password']

        try:
            email = validate_email(email).normalized
        except EmailNotValidError as e:
            flash(str(e), "danger")
            return redirect(url_for('register'))

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('register'))

        strong, msg = is_strong_password(password)
        if not strong:
            flash(msg, "warning")
            return redirect(url_for('register'))

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            flash("Email already exists", "warning")
            cursor.close()
            return redirect(url_for('register'))

        hashed = generate_password_hash(password)
        cursor.execute("""
            INSERT INTO users (first_name,last_name,email,password,role)
            VALUES (%s,%s,%s,%s,%s)
        """, ("User", "User", email, hashed, "Member"))

        mysql.connection.commit()
        cursor.close()

        flash("Account created", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# أضف هذا في نهاية ملف app.py لإصلاح الـ BuildError
@app.route('/members')
def members():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE role='Member'")
    all_members = cursor.fetchall()
    cursor.close()
    return render_template('members.html', members=all_members)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# -------------------------------------------------
# PROFILE
# -------------------------------------------------
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()

    return render_template('profile.html', user=user)

# -------------------------------------------------
# EVENTS
# -------------------------------------------------
@app.route('/events')
def events():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM events ORDER BY id DESC")
    events = cursor.fetchall()
    cursor.close()
    return render_template('events.html', events=events)

@app.route('/add_event', methods=['GET', 'POST'])
def add_event():
    if 'email' not in session or session['email'] not in ['nidalhasnaoui04@gmail.com']:
        flash("Access denied", "danger")
        return redirect(url_for('events'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO events (title, content)
            VALUES (%s,%s)
        """, (title, content))
        mysql.connection.commit()
        cursor.close()

        flash("Event added", "success")
        return redirect(url_for('events'))

    return render_template('add_event.html')

# -------------------------------------------------
# ARTICLES
# -------------------------------------------------
@app.route('/articles')
def articles():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM articles ORDER BY created_at DESC")
    articles = cursor.fetchall()
    cursor.close()
    return render_template('articles.html', articles=articles)

@app.route('/add_article', methods=['GET', 'POST'])
def add_article():
    if 'email' not in session or session['email'] not in ['nidalhasnaoui04@gmail.com']:
        flash("Access denied", "danger")
        return redirect(url_for('articles'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        created_at = datetime.now()

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO articles (title, content, created_at)
            VALUES (%s,%s,%s)
        """, (title, content, created_at))
        mysql.connection.commit()
        cursor.close()

        flash("Article published", "success")
        return redirect(url_for('articles'))

    return render_template('add_article.html')
