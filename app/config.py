# app/config.py
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-this')
    BASEDIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'instance', 'roofing.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'instance', 'uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB limit
    ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    # Session / cookie security
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # session timeout
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False  # set True when running under HTTPS
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Flask-WTF CSRF
    WTF_CSRF_TIME_LIMIT = None  # you can enable expiration if desired

    # Rate limiting, other security settings can be added later