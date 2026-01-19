import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import docx  # For DOCX parsing
import PyPDF2  # For PDF parsing

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default_secret_key")
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb://localhost:27017/fileproject")

mongo = PyMongo(app)

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'jpg', 'png', 'zip', 'exe'}

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

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
        confirm_password = request.form['confirm_password']
        
        # Check Passwords
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        
        # Check if user exists
        existing_user = mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]})
        
        if existing_user is None:
            mongo.db.users.insert_one({
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'full_name': None,
                'phone': None,
                'location': None,
                'college': None
            })
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Username or email already exists.')
    return render_template('register.html')

# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = mongo.db.users.find_one({'username': username})
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = str(user['_id'])
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
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
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
        
        mongo.db.users.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {
                'full_name': full_name,
                'phone': phone,
                'location': location,
                'college': college
            }}
        )
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))
    
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
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
            mongo.db.file_history.insert_one({
                'user_id': session['user_id'],
                'file_name': filename,
                'file_type': file_type,
                'risk_level': risk_level,
                'upload_date': datetime.datetime.utcnow(),
                'file_path': file_path
            })
            
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
        try:
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
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
    
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
    # Find all files for the user
    files = list(mongo.db.file_history.find({'user_id': session['user_id']}).sort('upload_date', -1))
    return render_template('history.html', files=files)

# Route: Delete File
@app.route('/delete/<file_id>')
@login_required
def delete(file_id):
    file = mongo.db.file_history.find_one({'_id': ObjectId(file_id), 'user_id': session['user_id']})
    if file:
        # Delete from filesystem
        if os.path.exists(file['file_path']):
            try:
                os.remove(file['file_path'])
            except OSError as e:
                print(f"Error deleting file {file['file_path']}: {e}")
                
        # Delete from DB
        mongo.db.file_history.delete_one({'_id': ObjectId(file_id)})
        flash('File deleted successfully.')
    else:
        flash('File not found or unauthorized.')
    return redirect(url_for('history'))

if __name__ == '__main__':
    app.run(debug=True)
