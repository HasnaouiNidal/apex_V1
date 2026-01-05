from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError
from datetime import datetime
import os
import re
import MySQLdb.cursors
from functools import wraps # <--- هذه المكتبة ضرورية للـ Decorator

# -------------------------------------------------
# APP INIT
# -------------------------------------------------
app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'local_secret_key')

# -------------------------------------------------
# MYSQL CONFIG
# -------------------------------------------------
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3306))
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

if os.environ.get('MYSQL_HOST') and os.environ.get('MYSQL_HOST') != 'localhost':
    app.config['MYSQL_CUSTOM_OPTIONS'] = {
        "ssl": {
            "ssl_mode": "REQUIRED",
            "fake_option_to_trigger_ssl": True
        }
    }

mysql = MySQL(app)

# -------------------------------------------------
# UPLOAD FOLDERS
# -------------------------------------------------
app.config['PROFILE_UPLOAD_FOLDER'] = 'static/uploads/profiles'
app.config['IMAGE_UPLOAD_FOLDER'] = 'static/uploads/images'

os.makedirs(app.config['PROFILE_UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['IMAGE_UPLOAD_FOLDER'], exist_ok=True)

# -------------------------------------------------
# 🔥 THE MAGIC DECORATOR (الطريقة الاحترافية رقم 2)
# -------------------------------------------------
def db_task(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. فتح الاتصال أوتوماتيكياً قبل بدء الدالة
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        try:
            # 2. تمرير الـ cursor للدالة الأصلية
            # نضيفه لـ kwargs لكي تستقبله الدالة كـ argument
            kwargs['cursor'] = cursor
            result = f(*args, **kwargs)
            
            # 3. حفظ التغييرات إذا لم يحدث خطأ
            mysql.connection.commit()
            return result
            
        except Exception as e:
            # 4. تراجع عن التغييرات إذا حدث خطأ
            mysql.connection.rollback()
            print(f"❌ DATABASE ERROR: {e}")
            flash("An error occurred with the database connection.", "danger")
            return redirect(url_for('home')) # أو أي صفحة آمنة
            
        finally:
            # 5. إغلاق الباب دائماً وأبداً (The Fix)
            cursor.close()
            
    return decorated_function

def is_strong_password(password):
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password): return False, "Missing uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Missing lowercase letter."
    if not re.search(r"[0-9]", password): return False, "Missing digit."
    return True, ""

# -------------------------------------------------
# ROUTES
# -------------------------------------------------

@app.route('/')
@db_task
def home(cursor): # لاحظ: الدالة الآن تستقبل cursor كهدية من الـ Decorator
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
    
    return render_template('index.html', recent_articles=recent_articles, recent_events=recent_events)

# --- AUTH SYSTEM ---

@app.route('/login', methods=['GET', 'POST'])
@db_task
def login(cursor):
    if 'user_id' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['user_id'] = user['id'] 
            session['username'] = user['first_name']
            session['email'] = user['email'] 
            flash('You logged in successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Email or password is not correct', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@db_task
def register(cursor):
    if 'user_id' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        try:
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized 
        except EmailNotValidError as e:
            flash(f'Invalid email: {str(e)}', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        is_strong, msg = is_strong_password(password)
        if not is_strong:
            flash(f'Weak Password: {msg}', 'warning')
            return redirect(url_for('register'))

        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        if cursor.fetchone():
            flash('Email already used! Please login.', 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (first_name, last_name, email, phone_number, password, role, team, profile_image) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (first_name, last_name, email, phone_number, hashed_password, 'Member', None, 'profile.jpg'))

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear() 
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

# --- USER PROFILE ---

@app.route('/profile')
@db_task
def profile(cursor):
    if 'user_id' not in session:
        flash('Please login to view your profile', 'warning')
        return redirect(url_for('login'))
    
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user_data = cursor.fetchone()
    
    if user_data:
        return render_template('profile.html', user=user_data)
    else:
        session.clear()
        return redirect(url_for('login'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@db_task
def edit_profile(cursor):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone_number')
        bio = request.form.get('bio')
        
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.root_path, app.config['PROFILE_UPLOAD_FOLDER'], filename))
                cursor.execute("UPDATE users SET profile_image=%s WHERE id=%s", (filename, user_id))

        cursor.execute("""
            UPDATE users 
            SET first_name=%s, last_name=%s, phone_number=%s, bio=%s 
            WHERE id=%s
        """, (first_name, last_name, phone, bio, user_id))
        
        session['username'] = first_name
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    return render_template('edit_profile.html', user=user)

# --- MEMBERS SYSTEM ---

@app.route('/members')
@db_task
def members(cursor):
    # This page caused the issue before. Now it's protected by the decorator.
    query = "SELECT * FROM users WHERE team IS NOT NULL ORDER BY team, role"
    cursor.execute(query)
    all_members = cursor.fetchall()
    return render_template('members.html', members=all_members)

@app.route('/add_member', methods=['GET', 'POST'])
@db_task
def add_member(cursor):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    ALLOWED_ADMINS = ['nidalhasnaoui04@gmail.com', 'khalidouisnaf@gmail.com']
    if session.get('email') not in ALLOWED_ADMINS:
        flash("Access Denied!", "danger")
        return redirect(url_for('members'))

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone_number')
        role = request.form.get('role')
        team = request.form.get('team')
        password = generate_password_hash("12345678")
        
        filename = 'default_profile.jpg'
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.root_path, app.config['PROFILE_UPLOAD_FOLDER'], filename))

        cursor.execute('SELECT id FROM users WHERE email=%s', (email,))
        if cursor.fetchone():
             flash('Error! This email exists.', 'danger')
        else:
            cursor.execute('''
                INSERT INTO users (first_name, last_name, email, phone_number, password, role, team, profile_image) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (first_name, last_name, email, phone, password, role, team, filename))
            flash(f'Member {first_name} added successfully!', 'success')
        
        return redirect(url_for('add_member'))

    return render_template('add_member.html')

# --- EVENTS SYSTEM ---

@app.route('/events')
@db_task
def events(cursor):
    cursor.execute("SELECT * FROM events ORDER BY id DESC")
    events_data = cursor.fetchall()
    return render_template('events.html', events=events_data)

@app.route('/add_event', methods=['GET', 'POST'])
@db_task
def add_event(cursor):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    ALLOWED_ADMINS = ['nidalhasnaoui04@gmail.com', 'khalidouisnaf@gmail.com']
    if session.get('email') not in ALLOWED_ADMINS:
        flash("Access Denied!", "danger")
        return redirect(url_for('home')) 

    if request.method == 'POST':
        title = request.form.get('title')
        raw_date = request.form.get('date_str')
        category = request.form.get('category')
        description = request.form.get('description')
        content = request.form.get('content')
        
        try:
            date_obj = datetime.strptime(raw_date, '%Y-%m-%d')
            formatted_date = date_obj.strftime('%B %d, %Y')
        except:
            formatted_date = raw_date 
        
        filename = 'default_event.jpg'
        if 'event_image' in request.files:
            file = request.files['event_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.root_path, app.config['IMAGE_UPLOAD_FOLDER'], filename))

        cursor.execute('''
            INSERT INTO events (title, date_str, category, description, content, image)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (title, formatted_date, category, description, content, filename))

        flash('Event published successfully!', 'success')
        return redirect(url_for('events'))

    return render_template('add_event.html')

@app.route('/event/<int:id>')
@db_task
def event_detail(cursor, id): # لاحظ: cursor دائماً هو الأول، ثم id
    cursor.execute("SELECT * FROM events WHERE id = %s", (id,))
    event_data = cursor.fetchone()
    
    if event_data:
        return render_template('event_detail.html', event=event_data)
    else:
        flash("Event not found!", "danger")
        return redirect(url_for('events'))

# --- ARTICLES SYSTEM ---

@app.route('/articles')
@db_task
def articles(cursor):
    cursor.execute("SELECT * FROM articles ORDER BY created_at DESC")
    articles_data = cursor.fetchall()
    return render_template('articles.html', articles=articles_data)

@app.route('/article/<int:id>')
@db_task
def article_detail_dynamic(cursor, id):
    cursor.execute("SELECT * FROM articles WHERE id = %s", (id,))
    article = cursor.fetchone()
    
    if article:
        return render_template('article_detail.html', article=article)
    else:
        flash("Article not found!", "danger")
        return redirect(url_for('articles'))

@app.route('/add_article', methods=['GET', 'POST'])
@db_task
def add_article(cursor):
    if 'user_id' not in session:
        flash("Login required.", "warning")
        return redirect(url_for('login'))

    ALLOWED_ADMINS = ['nidalhasnaoui04@gmail.com', 'khalidouisnaf@gmail.com']
    if session.get('email') not in ALLOWED_ADMINS:
        flash("Access Denied!", "danger")
        return redirect(url_for('articles'))

    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        subject = request.form.get('subject')
        summary = request.form.get('summary')
        content = request.form.get('content')
        created_at = datetime.now() 

        filename = 'default_article.jpg'
        if 'article_image' in request.files:
            file = request.files['article_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.root_path, app.config['IMAGE_UPLOAD_FOLDER'], filename))

        cursor.execute('''
            INSERT INTO articles (title, author, subject, image, summary, content, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (title, author, subject, filename, summary, content, created_at))

        flash('Article published successfully!', 'success')
        return redirect(url_for('articles'))

    return render_template('add_article.html')

if __name__ == '__main__':
    app.run(debug=True)