# app/config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-this')
    BASEDIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    # sqlite database in instance folder
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'instance', 'roofing.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File upload settings (for later)
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'instance', 'uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB limit for uploads
    ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}