# backup_db.py
"""
Creates an encrypted backup of db.json with timestamp
Run: python backup_db.py
"""
import os
import shutil
from datetime import datetime
from encrypted_storage import EncryptedJSONStorage

DB_FILE = "db.json"
BACKUP_DIR = "backups"

def ensure_backup_dir():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        print(f"Created backup folder: {BACKUP_DIR}")

def create_backup():
    if not os.path.exists(DB_FILE):
        print("No db.json found! Nothing to backup.")
        return

    ensure_backup_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"db_backup_{timestamp}.json"
    backup_path = os.path.join(BACKUP_DIR, backup_name)

    shutil.copy2(DB_FILE, backup_path)
    print(f"BACKUP SUCCESS: {backup_path}")

if __name__ == "__main__":
    create_backup()