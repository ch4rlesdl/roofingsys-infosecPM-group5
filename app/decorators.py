# app/decorators.py
from functools import wraps
from flask import abort
from flask_login import current_user

def role_required(*allowed_roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user or not getattr(current_user, 'role', None):
                abort(403)
            user_role = current_user.get_role() if hasattr(current_user, 'get_role') else None
            if user_role not in allowed_roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return wrapper