from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os, urllib
from urllib.parse import quote_plus
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf

load_dotenv()

# Build ODBC connection string safely
params = urllib.parse.quote_plus(
    f"Driver={{ODBC Driver 17 for SQL Server}};"
    f"Server={os.getenv('DB_SERVER')};"
    f"Database={os.getenv('DB_NAME')};"
    f"Uid={os.getenv('DB_USER')};"
    f"Pwd={os.getenv('DB_PASSWORD')};"
    f"Encrypt=yes;"
    f"TrustServerCertificate=no;"
)


app=Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc:///?odbc_connect={params}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.secret_key = os.getenv("app_secret_key")    # Required for sessions
csrf = CSRFProtect(app)                         # Globally enables protection

db = SQLAlchemy(app)

class (db.Model):
    __tablename__ = ""
    __table_args__ = {'schema': ''}

    username = db.Column(db.String(20), primary_key=True)
    
