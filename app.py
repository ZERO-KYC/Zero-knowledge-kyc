from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os, urllib
from urllib.parse import quote_plus
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from supabase import create_client, Client

# SQLAlchemy imports (IMPORTANT)
from sqlalchemy import  Integer, String, BigInteger, DateTime, ForeignKey
from sqlalchemy.sql import func

# ---------------------------------------------------
# Load environment variables
# ---------------------------------------------------
load_dotenv()

# ---------------------------------------------------
# Build ODBC connection string safely
# ---------------------------------------------------
params = urllib.parse.quote_plus(
    f"Driver={{ODBC Driver 17 for SQL Server}};"
    f"Server={os.getenv('DB_SERVER')};"
    f"Database={os.getenv('DB_NAME')};"
    f"Uid={os.getenv('DB_USER')};"
    f"Pwd={os.getenv('DB_PASSWORD')};"
    f"Encrypt=yes;"
    f"TrustServerCertificate=no;"
)

# ---------------------------------------------------
# Supabase Configuration
# ---------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

try:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("Supabase Keys missing in .env")

    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("Supabase Connected!")
except Exception as e:
    print(f"Supabase Connection Failed: {e}")

# ---------------------------------------------------
# Flask App Setup
# ---------------------------------------------------
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mssql+pyodbc:///?odbc_connect={params}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.secret_key = os.getenv("APP_SECRET_KEY")  # required for sessions

# CSRF Protection
csrf = CSRFProtect(app)

# SQLAlchemy Init
db = SQLAlchemy(app)

# ---------------------------------------------------
# USERS MODEL (MATCHES YOUR SQL TABLE EXACTLY)
# ---------------------------------------------------
class Users(db.Model):
    __tablename__ = "Users"
    __table_args__ = {'schema': 'dbo'}

    UserID = db.Column(Integer, primary_key=True, autoincrement=True)
    Username = db.Column(String(50), nullable=False, unique=True)
    Email = db.Column(String(100), nullable=False, unique=True)
    PasswordHash = db.Column(String(255), nullable=False)
    ProfileImage = db.Column(String(255), nullable=True)
    CreatedAt = db.Column(DateTime, server_default=func.getdate())

class UserFiles(db.Model):
    __tablename__ = "UserFiles"
    __table_args__ = {'schema': 'dbo'}

    FileID = db.Column(Integer, primary_key=True, autoincrement=True)

    # Foreign key to Users table
    UserID = db.Column(
        Integer,
        ForeignKey("dbo.Users.UserID", ondelete="CASCADE"),
        nullable=False
    )

    # Display info (visible to user)
    FileName = db.Column(String(255), nullable=False)
    FileSizeBytes = db.Column(BigInteger, nullable=False)
    FileType = db.Column(String(50), nullable=True)

    # Supabase storage reference
    StoragePath = db.Column(String(500), nullable=False)
    StorageProvider = db.Column(String(50), default="supabase")

    # Crypto metadata (zero-knowledge support)
    EncryptionSalt = db.Column(String(255), nullable=False)
    EncryptionIV = db.Column(String(255), nullable=False)

    UploadDate = db.Column(DateTime, server_default=func.getdate())


@app.route("/")
def login():
    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)
