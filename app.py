import os
import sqlite3
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import docx  # For DOCX parsing
import PyPDF2  # For PDF parsing

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure random key
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'jpg', 'png', 'zip', 'exe'}

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Database connection helper
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create tables if not exist
with get_db() as db:
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            phone TEXT,
            location TEXT,
            college TEXT
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS file_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            upload_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    db.commit()

# Helper: Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Decorator for login required
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Route: Home/Dashboard (after login)
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        
        with get_db() as db:
            try:
                db.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                           (username, email, password_hash))
                db.commit()
                flash('Registration successful! Please log in.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username or email already exists.')
    return render_template('register.html')

# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Logged in successfully.')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.')
    return render_template('login.html')

# Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

# Route: Profile View
@app.route('/profile')
@login_required
def profile():
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('profile.html', user=user)

# Route: Edit Profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        full_name = request.form['full_name']
        phone = request.form['phone']
        location = request.form['location']
        college = request.form['college']
        
        with get_db() as db:
            db.execute('''
                UPDATE users SET full_name = ?, phone = ?, location = ?, college = ?
                WHERE id = ?
            ''', (full_name, phone, location, college, session['user_id']))
            db.commit()
            flash('Profile updated successfully.')
            return redirect(url_for('profile'))
    
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('edit_profile.html', user=user)

# Route: File Upload
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part.')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file.')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            # Secure filename and store in user-specific folder
            filename = secure_filename(file.filename)
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{session['user_id']}")
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)
            file_path = os.path.join(user_folder, filename)
            file.save(file_path)
            
            # Analyze file
            file_type = filename.rsplit('.', 1)[1].lower()
            risk_level, recommendation = analyze_file(file_path, file_type)
            
            # Save to history
            with get_db() as db:
                db.execute('''
                    INSERT INTO file_history (user_id, file_name, file_type, risk_level, file_path)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session['user_id'], filename, file_type, risk_level, file_path))
                db.commit()
            
            return render_template('result.html', filename=filename, file_type=file_type,
                                   risk_level=risk_level, recommendation=recommendation)
        else:
            flash('Invalid file type.')
    return render_template('upload.html')

# File Analysis Logic
def analyze_file(file_path, file_type):
    size = os.path.getsize(file_path) / (1024 * 1024)  # MB
    is_executable = file_type in {'exe', 'bat'}
    keywords_found = False
    
    # Scan for suspicious keywords in text-based files
    suspicious_keywords = ['malware', 'virus', 'exploit', 'trojan']
    if file_type in {'txt', 'docx', 'pdf'}:
        text = ''
        if file_type == 'txt':
            with open(file_path, 'r', errors='ignore') as f:
                text = f.read().lower()
        elif file_type == 'docx':
            doc = docx.Document(file_path)
            text = ' '.join([para.text for para in doc.paragraphs]).lower()
        elif file_type == 'pdf':
            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                text = ' '.join([page.extract_text() for page in pdf.pages if page.extract_text()]).lower()
        keywords_found = any(kw in text for kw in suspicious_keywords)
    
    # Determine risk
    if is_executable or keywords_found:
        risk_level = 'High'
        recommendation = 'Delete Recommended'
    elif size > 10 or file_type == 'zip':  # ZIPs can contain risks
        risk_level = 'Medium'
        recommendation = 'Do Not Open'
    else:
        risk_level = 'Low'
        recommendation = 'Safe to Open'
    
    return risk_level, recommendation

# Route: History
@app.route('/history')
@login_required
def history():
    with get_db() as db:
        files = db.execute('''
            SELECT * FROM file_history WHERE user_id = ? ORDER BY upload_date DESC
        ''', (session['user_id'],)).fetchall()
    return render_template('history.html', files=files)

# Route: Delete File
@app.route('/delete/<int:file_id>')
@login_required
def delete(file_id):
    with get_db() as db:
        file = db.execute('SELECT * FROM file_history WHERE id = ? AND user_id = ?',
                          (file_id, session['user_id'])).fetchone()
        if file:
            # Delete from filesystem
            if os.path.exists(file['file_path']):
                os.remove(file['file_path'])
            # Delete from DB
            db.execute('DELETE FROM file_history WHERE id = ?', (file_id,))
            db.commit()
            flash('File deleted successfully.')
        else:
            flash('File not found or unauthorized.')
    return redirect(url_for('history'))

if __name__ == '__main__':
    app.run(debug=True)