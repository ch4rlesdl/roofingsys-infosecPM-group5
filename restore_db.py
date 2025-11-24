# restore_db.py
"""
Restores database from a backup file
Run: python restore_db.py backups/db_backup_20251124_223015.json
"""
import os
import sys
import shutil

DB_FILE = "db.json"

if len(sys.argv) != 2:
    print("Usage: python restore_db.py <backup_file>")
    print("Example: python restore_db.py backups/db_backup_20251124_223015.json")
    sys.exit(1)

backup_file = sys.argv[1]

if not os.path.exists(backup_file):
    print(f"Backup file not found: {backup_file}")
    sys.exit(1)

if not os.path.exists(DB_FILE):
    print(f"No current db.json — restoring will create it.")
else:
    confirm = input(f"Overwrite current {DB_FILE}? (type YES): ")
    if confirm != "YES":
        print("Restore cancelled.")
        sys.exit(0)

shutil.copy2(backup_file, DB_FILE)
print(f"RESTORED SUCCESSFULLY from {backup_file}")
print(f"→ Your database is now from: {os.path.basename(backup_file)}")