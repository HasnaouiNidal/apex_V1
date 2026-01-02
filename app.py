from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError
from datetime import datetime
import os
import re
import MySQLdb.cursors
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

# SSL for Aiven (الحل النهائي لخطأ Certificate Chain)
if os.environ.get('MYSQL_HOST') and os.environ.get('MYSQL_HOST') != 'localhost':
    app.config['MYSQL_CUSTOM_OPTIONS'] = {
        "ssl": {
            "ssl_mode": "REQUIRED",
            "fake_option_to_trigger_ssl": True # أحياناً تحتاجه بعض إصدارات المكتبة
        }
    }
    # ملاحظة: حذفنا مسار الملف /etc/ssl/... لأنه يسبب تعارض مع شهادة Aiven

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
# --- PUBLIC ROUTES ---
@app.route('/')
def home():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # 1. Get 3 Newest Articles
    try:
        cursor.execute("SELECT * FROM articles ORDER BY created_at DESC LIMIT 3")
        recent_articles = cursor.fetchall()
    except:
        recent_articles = [] # Handle if table doesn't exist

    # 2. Get 3 Newest Events (ADDED THIS PART)
    try:
        cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 3")
        recent_events = cursor.fetchall()
    except:
        recent_events = []

    cursor.close()
    
    # Send both to the HTML
    return render_template('index.html', recent_articles=recent_articles, recent_events=recent_events)

# --- AUTH SYSTEM (Login/Register/Logout) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['user_id'] = user['id'] 
            session['username'] = user['first_name']
            
            # --- هذا هو السطر الجديد المهم جداً ---
            session['email'] = user['email'] 
            # --------------------------------------
            
            flash('You logged in successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Email or password is not correct', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        # 1. تنظيف المدخلات (Sanitization) لإزالة المسافات الزائدة
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # 2. التحقق من صحة الإيميل (Validation)
        try:
            # يتأكد أن شكل الإيميل صحيح وأن الدومين موجود
            valid = validate_email(email, check_deliverability=True)
            email = valid.normalized 
        except EmailNotValidError as e:
            flash(f'Invalid email address: {str(e)}', 'danger')
            return redirect(url_for('register'))

        # 3. التحقق من تطابق كلمات السر
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        # 4. التحقق من قوة كلمة السر (Strong Password Policy)
        is_strong, msg = is_strong_password(password)
        if not is_strong:
            flash(f'Weak Password: {msg}', 'warning')
            return redirect(url_for('register'))

        # 5. التحقق من عدم تكرار الإيميل في قاعدة البيانات
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Email already used! Please login.', 'warning')
            cursor.close()
            return redirect(url_for('register'))

        # 6. إنشاء الحساب
        hashed_password = generate_password_hash(password)

        default_role = 'Member'
        default_team = None 
        default_image = 'profile.jpg'

        cursor.execute('''
            INSERT INTO users (first_name, last_name, email, phone_number, password, role, team, profile_image) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (first_name, last_name, email, phone_number, hashed_password, default_role, default_team, default_image))
        
        mysql.connection.commit()
        cursor.close()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear() 
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

# --- USER PROFILE SYSTEM ---

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login to view your profile', 'warning')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    
    if user_data:
        return render_template('profile.html', user=user_data)
    else:
        session.clear()
        return redirect(url_for('login'))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone_number')
        bio = request.form.get('bio')
        
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                # Save to profile_pics folder
                file.save(os.path.join(app.root_path, app.config['PROFILE_UPLOAD_FOLDER'], filename))
                cursor.execute("UPDATE users SET profile_image=%s WHERE id=%s", (filename, user_id))

        cursor.execute("""
            UPDATE users 
            SET first_name=%s, last_name=%s, phone_number=%s, bio=%s 
            WHERE id=%s
        """, (first_name, last_name, phone, bio, user_id))
        
        mysql.connection.commit()
        session['username'] = first_name
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    
    return render_template('edit_profile.html', user=user)

# --- MEMBERS SYSTEM ---

@app.route('/members')
def members():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    query = "SELECT * FROM users WHERE team IS NOT NULL ORDER BY team, role"
    cursor.execute(query)
    all_members = cursor.fetchall()
    cursor.close()
    return render_template('members.html', members=all_members)

@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    # ---------------------------------------------------------
    # 1. الحماية الأمنية (Security Check)
    # ---------------------------------------------------------
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # قائمة المدراء المسموح لهم فقط
    ALLOWED_ADMINS = ['nidalhasnaoui04@gmail.com', 'khalidouisnaf@gmail.com']
    
    if session.get('email') not in ALLOWED_ADMINS:
        flash("Access Denied! Only admins can add new members.", "danger")
        return redirect(url_for('members'))

    # ---------------------------------------------------------
    # 2. معالجة البيانات (Logic)
    # ---------------------------------------------------------
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone_number')
        role = request.form.get('role')
        team = request.form.get('team')
        
        # كلمة سر افتراضية للعضو الجديد (يمكنه تغييرها لاحقاً)
        password = generate_password_hash("12345678")
        
        # معالجة صورة البروفايل
        filename = 'default_profile.jpg'
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                # حفظ في مجلد profile_pics
                file.save(os.path.join(app.root_path, app.config['PROFILE_UPLOAD_FOLDER'], filename))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        try:
            cursor.execute('''
                INSERT INTO users (first_name, last_name, email, phone_number, password, role, team, profile_image) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (first_name, last_name, email, phone, password, role, team, filename))
            mysql.connection.commit()
            flash(f'Member {first_name} added successfully!', 'success')
        except Exception as e:
            # في حال كان الإيميل مكرراً
            flash('Error! This email might already exist.', 'danger')
        finally:
            cursor.close()
        
        return redirect(url_for('add_member'))

    return render_template('add_member.html')


# --- EVENTS SYSTEM ROUTES ---

@app.route('/events')
def events():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM events ORDER BY id DESC")
    events_data = cursor.fetchall()
    cursor.close()
    return render_template('events.html', events=events_data)


@app.route('/add_event', methods=['GET', 'POST'])
def add_event():
    # ---------------------------------------------------------
    # 1. الحماية الأمنية (Security Check)
    # ---------------------------------------------------------
    
    # أولاً: هل المستخدم مسجل دخول؟
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # ثانياً: قائمة "الأشخاص المهمين جداً" (VIP List)
    # غير هذه الإيميلات إلى إيميلك وإيميل صديقك الحقيقي
    ALLOWED_ADMINS = ['nidalhasnaoui04@gmail.com', 'khalidouisnaf@gmail.com']
    
    # نحضر الإيميل من الجلسة (Session)
    current_email = session.get('email')
    
    # إذا لم يكن الإيميل في القائمة، نطرده فوراً
    if current_email not in ALLOWED_ADMINS:
        flash("Access Denied! You don't have permission to post events.", "danger")
        return redirect(url_for('home')) 

    # ---------------------------------------------------------
    # 2. معالجة البيانات وحفظ الحدث (Logic & Database)
    # ---------------------------------------------------------
    if request.method == 'POST':
        title = request.form.get('title')
        raw_date = request.form.get('date_str') # التاريخ كما يأتي من المتصفح (YYYY-MM-DD)
        category = request.form.get('category')
        description = request.form.get('description')
        content = request.form.get('content')
        
        # --- تصحيح التاريخ (مهم جداً لكي لا يتوقف الموقع) ---
        try:
            # نحول التاريخ من 2025-12-28 إلى December 28, 2025
            date_obj = datetime.strptime(raw_date, '%Y-%m-%d')
            formatted_date = date_obj.strftime('%B %d, %Y')
        except:
            # في حالة حدوث أي خطأ، نترك التاريخ كما هو
            formatted_date = raw_date 
        # ----------------------------------------------------
        
        # معالجة الصورة
        filename = 'default_event.jpg'
        if 'event_image' in request.files:
            file = request.files['event_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.root_path, app.config['IMAGE_UPLOAD_FOLDER'], filename))

        # الحفظ في قاعدة البيانات
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('''
            INSERT INTO events (title, date_str, category, description, content, image)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (title, formatted_date, category, description, content, filename))
        
        mysql.connection.commit()
        cursor.close()

        flash('Event published successfully!', 'success')
        return redirect(url_for('events'))

    return render_template('add_event.html')

@app.route('/event/<int:id>')
def event_detail(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM events WHERE id = %s", (id,))
    event_data = cursor.fetchone()
    cursor.close()
    
    if event_data:
        return render_template('event_detail.html', event=event_data)
    else:
        flash("Event not found!", "danger")
        return redirect(url_for('events'))


# --- ARTICLES SYSTEM ROUTES ---

@app.route('/articles')
def articles():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Get all articles, newest first
    cursor.execute("SELECT * FROM articles ORDER BY created_at DESC")
    articles_data = cursor.fetchall()
    cursor.close()
    return render_template('articles.html', articles=articles_data)

@app.route('/article/<int:id>')
def article_detail_dynamic(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM articles WHERE id = %s", (id,))
    article = cursor.fetchone()
    cursor.close()
    
    if article:
        return render_template('article_detail.html', article=article)
    else:
        flash("Article not found!", "danger")
        return redirect(url_for('articles'))

@app.route('/add_article', methods=['GET', 'POST'])
def add_article():
    # ---------------------------------------------------------
    # 1. الحماية الأمنية (Security Check)
    # ---------------------------------------------------------
    if 'user_id' not in session:
        flash("You need to login to publish articles.", "warning")
        return redirect(url_for('login'))

    # قائمة المسموح لهم (نفس القائمة التي وضعناها في Events)
    ALLOWED_ADMINS = ['nidalhasnaoui04@gmail.com', 'khalidouisnaf@gmail.com']
    
    current_email = session.get('email')
    
    if current_email not in ALLOWED_ADMINS:
        flash("Access Denied! You are not an editor.", "danger")
        return redirect(url_for('articles'))

    # ---------------------------------------------------------
    # 2. معالجة البيانات (Logic)
    # ---------------------------------------------------------
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        subject = request.form.get('subject') # Math, PC, SVT...
        summary = request.form.get('summary')
        content = request.form.get('content') # From CKEditor/TinyMCE

        # --- توليد تاريخ اللحظة الحالية ---
        # هذا ضروري جداً لأن ملف html يستخدم .strftime
        # إذا لم نرسل تاريخاً، قد يكون الحقل فارغاً ويسبب Error 500
        created_at = datetime.now() 
        # --------------------------------

        # معالجة الصورة
        filename = 'default_article.jpg'
        if 'article_image' in request.files:
            file = request.files['article_image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                # حفظ في نفس مجلد الصور العام
                file.save(os.path.join(app.root_path, app.config['IMAGE_UPLOAD_FOLDER'], filename))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # ملاحظة: تأكد أن جدول articles في قاعدة البيانات يحتوي على عمود اسمه created_at
        cursor.execute('''
            INSERT INTO articles (title, author, subject, image, summary, content, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (title, author, subject, filename, summary, content, created_at))
        
        mysql.connection.commit()
        cursor.close()

        flash('Article published successfully!', 'success')
        return redirect(url_for('articles'))

    return render_template('add_article.html')