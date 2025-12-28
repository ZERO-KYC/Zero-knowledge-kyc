from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os, urllib, uuid
from flask_wtf import CSRFProtect
from supabase import create_client, Client
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import Integer, String, BigInteger, DateTime, ForeignKey
from sqlalchemy.sql import func
import base64
from authlib.integrations.flask_client import OAuth

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

params = urllib.parse.quote_plus(
    f"Driver={{ODBC Driver 17 for SQL Server}};"
    f"Server={os.getenv('DB_SERVER')};"
    f"Database={os.getenv('DB_NAME')};"
    f"Uid={os.getenv('DB_USER')};"
    f"Pwd={os.getenv('DB_PASSWORD')};"
    f"Encrypt=yes;"
    f"TrustServerCertificate=no;"
)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc:///?odbc_connect={params}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv("APP_SECRET_KEY")

csrf = CSRFProtect(app)
db = SQLAlchemy(app)

# --- GOOGLE OAUTH SETUP ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- DATABASE MODELS ---
class Users(db.Model):
    __tablename__ = "Users"
    UserID = db.Column(Integer, primary_key=True, autoincrement=True)
    Username = db.Column(String(50), unique=True, nullable=False)
    Email = db.Column(String(100), unique=True, nullable=False)
    PasswordHash = db.Column(String(255), nullable=False)
    ProfileImage = db.Column(String(255), nullable=True)
    CreatedAt = db.Column(DateTime, server_default=func.getdate())

class UserFiles(db.Model):
    __tablename__ = "UserFiles"
    FileID = db.Column(Integer, primary_key=True, autoincrement=True)
    UserID = db.Column(Integer, ForeignKey("Users.UserID"), nullable=False)
    FileName = db.Column(String(255), nullable=False)
    FileSizeBytes = db.Column(BigInteger, nullable=False)
    FileType = db.Column(String(50))
    StoragePath = db.Column(String(500), nullable=False)
    StorageProvider = db.Column(String(50), server_default='supabase')
    EncryptionSalt = db.Column(String(255), nullable=False)
    EncryptionIV = db.Column(String(255), nullable=False)
    UploadDate = db.Column(DateTime, server_default=func.getdate())

# --- ROUTES ---

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# 1. Login & Registration Pages
@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/register_page")
def register_page():
    return render_template("register.html")

# 2. Standard Auth Logic
@app.route("/register", methods=["POST"])
def register_user():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    if Users.query.filter((Users.Username == username) | (Users.Email == email)).first():
        return jsonify({"success": False, "message": "Username or Email already exists"}), 409

    hashed_pw = generate_password_hash(password)
    
    new_user = Users(Username=username, Email=email, PasswordHash=hashed_pw)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"success": True, "redirect": url_for("login")})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database Error"}), 500

@app.route('/login_button', methods=['POST'])
def login_post():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = Users.query.filter_by(Username=username).first()

    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    if not check_password_hash(user.PasswordHash, password):
        return jsonify({"success": False, "message": "Incorrect password"}), 401

    session.permanent = True
    session['user_id'] = user.UserID
    session['username'] = user.Username

    return jsonify({"success": True, "redirect": url_for('dashboard')})

# 3. Google OAuth Logic
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            return "Login Failed: No user info received", 400

        email = user_info['email']
        user = Users.query.filter_by(Email=email).first()

        if user:
            # User exists: Log in directly
            session.permanent = True
            session['user_id'] = user.UserID
            session['username'] = user.Username
            return redirect(url_for('dashboard'))
        else:
            # New User: Redirect to "Finalize Account" to set Password (Required for Encryption!)
            session['temp_email'] = email
            return redirect(url_for('finalize_account'))
            
    except Exception as e:
        print(f"OAuth Error: {e}")
        return f"OAuth Error: {str(e)}", 500

@app.route("/finalize-account", methods=["GET", "POST"])
def finalize_account():
    # Ensure they actually came from Google Auth
    if 'temp_email' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = session['temp_email']

        # Check if username is taken
        if Users.query.filter_by(Username=username).first():
             return render_template("reg2.html", email=email, error="Username already taken")

        # Hash password (User MUST have a password for Zero-Knowledge encryption key derivation)
        hashed_pw = generate_password_hash(password)

        try:
            new_user = Users(Username=username, Email=email, PasswordHash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()

            # Clean up session and log in
            session.pop('temp_email', None)
            session.permanent = True
            session['user_id'] = new_user.UserID
            session['username'] = new_user.Username
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            return f"Database Error: {str(e)}", 500

    return render_template("reg2.html", email=session['temp_email'])

# 4. Main App Logic
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user_id = session["user_id"]
    total_files = UserFiles.query.filter_by(UserID=user_id).count()
    recent_files = UserFiles.query.filter_by(UserID=user_id).order_by(UserFiles.UploadDate.desc()).limit(5).all()
        
    return render_template("dashboard.html", username=session["username"], total_files=total_files, files=recent_files)

@app.route("/files")
def files_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user_id = session["user_id"]
    all_files = UserFiles.query.filter_by(UserID=user_id).order_by(UserFiles.UploadDate.desc()).all()
    
    return render_template("files.html", files=all_files, username=session["username"])

@app.route("/api/upload", methods=["POST"])
def upload_secure():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        file_obj = request.files.get('file')
        file_name = request.form.get('fileName')
        file_size = request.form.get('fileSize')
        file_type = request.form.get('fileType')
        salt = request.form.get('salt')
        iv = request.form.get('iv')

        if not file_obj:
            return jsonify({"success": False, "message": "No file provided"}), 400

        user_id = session["user_id"]
        random_name = f"{uuid.uuid4()}.enc"
        storage_path = f"vault/user_{user_id}/{random_name}"

        file_bytes = file_obj.read()
        supabase.storage.from_("secure_vault").upload(
            path=storage_path,
            file=file_bytes,
            file_options={"content-type": "application/octet-stream"}
        )

        new_file = UserFiles(
            UserID=user_id,
            FileName=file_name,
            FileSizeBytes=file_size,
            FileType=file_type,
            StoragePath=storage_path,
            StorageProvider='supabase',
            EncryptionSalt=salt,
            EncryptionIV=iv
        )

        db.session.add(new_file)
        db.session.commit()

        from datetime import datetime
        return jsonify({
            "success": True, 
            "message": "File Vaulted Successfully!",
            "new_file": {
                "name": file_name,
                "size": file_size,
                "date": datetime.now().strftime('%Y-%m-%d'),
                "type": "AES-256"
            }
        })

    except Exception as e:
        db.session.rollback()
        print(f"Upload Error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/download/<int:file_id>")
def download_file(file_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    file_record = UserFiles.query.filter_by(FileID=file_id, UserID=session["user_id"]).first()
    
    if not file_record:
        return jsonify({"success": False, "message": "File not found"}), 404

    try:
        res = supabase.storage.from_("secure_vault").download(file_record.StoragePath)
        encrypted_b64 = base64.b64encode(res).decode('utf-8')

        return jsonify({
            "success": True,
            "fileName": file_record.FileName,
            "fileType": file_record.FileType,
            "encryptedData": encrypted_b64,
            "salt": file_record.EncryptionSalt,
            "iv": file_record.EncryptionIV
        })

    except Exception as e:
        print(f"Download Error: {e}")
        return jsonify({"success": False, "message": "Failed to retrieve file"}), 500

@app.route("/settings")
def settings_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("settings.html", username=session["username"])

@app.route("/api/delete_account", methods=["DELETE"])
def delete_account():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user_id = session["user_id"]

    try:
        files = UserFiles.query.filter_by(UserID=user_id).all()
        paths_to_delete = [f.StoragePath for f in files]

        if paths_to_delete:
            supabase.storage.from_("secure_vault").remove(paths_to_delete)

        UserFiles.query.filter_by(UserID=user_id).delete()
        Users.query.filter_by(UserID=user_id).delete()
        
        db.session.commit()
        session.clear()

        return jsonify({"success": True, "message": "Account deleted successfully"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

if __name__ == "__main__":
    app.run(debug=True)