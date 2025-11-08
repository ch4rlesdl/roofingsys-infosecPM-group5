# app/utils.py
from werkzeug.security import generate_password_hash, check_password_hash
import os

def hash_password(password: str) -> str:
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def verify_password(hashed: str, candidate: str) -> bool:
    return check_password_hash(hashed, candidate)

def allowed_image(filename: str, allowed_ext: set):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_ext