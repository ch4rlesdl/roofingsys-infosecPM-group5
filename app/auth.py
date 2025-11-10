# app/auth.py
from flask import Blueprint, request, render_template, redirect, url_for, flash, current_app, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, Role, SecurityLog
from app import db
from app.forms import RegisterForm, LoginForm
from app.utils import hash_password, verify_password
from datetime import datetime

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    # minimal validation
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name', '')
    if not email or not password:
        return jsonify({'error': 'email and password required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'email already registered'}), 400

    # default role: customer
    customer_role = Role.query.filter_by(name='customer').first()
    user = User(email=email, password=hash_password(password), full_name=full_name, role_id=customer_role.id)
    db.session.add(user)
    db.session.commit()

    # create empty cart for user
    from app.models import Cart
    cart = Cart(user_id=user.id)
    db.session.add(cart)
    db.session.commit()

    return jsonify({'ok': True, 'message': 'registered'}), 201

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'email and password required'}), 400

    user = User.query.filter_by(email=email).first()
    client_ip = request.remote_addr
    ua = request.headers.get('User-Agent')

    if not user or not verify_password(user.password, password):
        # log failed attempt
        log = SecurityLog(user_id=user.id if user else None, event_type='login_failed',
                          ip_address=client_ip, user_agent=ua, detail=f"login failed for {email}")
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'invalid credentials'}), 401

    if not user.is_active:
        return jsonify({'error': 'account disabled'}), 403

    login_user(user)
    # set session permanent to apply PERMANENT_SESSION_LIFETIME
    session.permanent = True

    # log success
    log = SecurityLog(user_id=user.id, event_type='login_success', ip_address=client_ip, user_agent=ua, detail='login success')
    db.session.add(log)
    db.session.commit()

    return jsonify({'ok': True, 'message': 'logged in', 'role': user.get_role()})

@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    user = current_user
    logout_user()
    # log logout
    log = SecurityLog(user_id=user.id, event_type='logout', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent'), detail='user logged out')
    db.session.add(log)
    db.session.commit()
    return jsonify({'ok': True, 'message': 'logged out'})