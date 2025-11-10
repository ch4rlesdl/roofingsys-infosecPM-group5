# app/upload_helpers.py
import os
from werkzeug.utils import secure_filename
from flask import current_app

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in current_app.config.get('ALLOWED_IMAGE_EXTENSIONS', set())

def save_image(file_storage, subfolder=''):
    filename = secure_filename(file_storage.filename)
    if not allowed_file(filename):
        raise ValueError("Invalid image extension")
    upload_folder = current_app.config['UPLOAD_FOLDER']
    if subfolder:
        dirpath = os.path.join(upload_folder, subfolder)
    else:
        dirpath = upload_folder
    os.makedirs(dirpath, exist_ok=True)
    dest = os.path.join(dirpath, filename)
    file_storage.save(dest)
    return filename