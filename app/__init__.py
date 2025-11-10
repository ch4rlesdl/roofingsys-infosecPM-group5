# app/__init__.py
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    app.config.from_object('app.config.Config')
    app.config.from_pyfile('config.py', silent=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # optional: configure login view
    login_manager.login_view = 'auth.login'
    login_manager.session_protection = 'strong'

    # Register blueprints
    from app import auth, api  # will create these files
    app.register_blueprint(auth.bp)
    app.register_blueprint(api.bp)

    # user loader
    from app.models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # add security headers to every response
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

    # Import models to ensure create_all picks them up when called elsewhere
    with app.app_context():
        from app import models  # noqa: F401

    return app