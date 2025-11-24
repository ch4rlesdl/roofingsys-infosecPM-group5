# create_db.py
"""
Seeds a TinyDB database for JDGS Homeshield Roofing (ROOFSYS-TRI).
Produces db.json in the same directory and ensures minimal collections exist.
Run: python create_db.py
"""

import os
import uuid
import secrets
from datetime import datetime
from tinydb import TinyDB, where
from passlib.hash import pbkdf2_sha256
from encrypted_storage import EncryptedJSONStorage

# PyCryptodome for key derivation
from Crypto.Hash import SHA256

DB_FILE = "db.json"
ITEMPICS_DIR = "itempics"
SECRET_FILE = ".secret_key"

def make_id(prefix="id"):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def ensure_itempics_dir():
    if not os.path.exists(ITEMPICS_DIR):
        os.makedirs(ITEMPICS_DIR)
        print(f"Created folder: {ITEMPICS_DIR} — please add product images and logo.png")

def hashpw(pwd: str):
    return pbkdf2_sha256.hash(pwd)

# SECRET KEY management (copied from main.py for consistency)
def ensure_secret():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            return f.read()
    else:
        key = secrets.token_urlsafe(32).encode()
        with open(SECRET_FILE, "wb") as f:
            f.write(key)
        return key

# Derive a fixed 32-byte key for DB encryption from SECRET_KEY (SHA256)
def _derive_db_key(secret_bytes: bytes) -> bytes:
    h = SHA256.new()
    h.update(secret_bytes)
    return h.digest()

def seed():
    ensure_itempics_dir()
    secret = ensure_secret()
    db_enc_key = _derive_db_key(secret)
    db = TinyDB(DB_FILE, storage=lambda path: EncryptedJSONStorage(path, db_enc_key))
    db.drop_tables()

    # Users collection: roles = ADMIN, INVENTORY, SALES, CUSTOMER
    users = [
        {
            "id": make_id("user"),
            "username": "admin",
            "display_name": "Admin User",
            "email": "admin@example.com",
            "password_hash": hashpw("AdminPass123!"),
            "role": "ADMIN",
            "created_at": now_iso(),
        },
        {
            "id": make_id("user"),
            "username": "inventory",
            "display_name": "Inventory Manager",
            "email": "inventory@example.com",
            "password_hash": hashpw("InvPass123!"),
            "role": "INVENTORY",
            "created_at": now_iso(),
        },
        {
            "id": make_id("user"),
            "username": "sales",
            "display_name": "Sales Rep",
            "email": "sales@example.com",
            "password_hash": hashpw("SalesPass123!"),
            "role": "SALES",
            "created_at": now_iso(),
        },
        {
            "id": make_id("user"),
            "username": "customer",
            "display_name": "Demo Customer",
            "email": "customer@example.com",
            "password_hash": hashpw("CustPass123!"),
            "role": "CUSTOMER",
            "created_at": now_iso(),
        },
    ]
    db.table("users").insert_multiple(users)
    print(f"Seeded {len(users)} users.")

    # Products: 2 shingles
    products = [
        {
            "id": make_id("prod"),
            "sku": "SHINGLE-01",
            "name": "Classic Shingle 3T",
            "description": "Classic asphalt shingle, 3-tab, durable and economical.",
            "price": 12.50,
            "quantity": 150,
            "image": "shingle1.png",
            "created_at": now_iso(),
            "active": True,
        },
        {
            "id": make_id("prod"),
            "sku": "SHINGLE-02",
            "name": "Premium Shingle HD",
            "description": "Premium architectural shingle for high durability and curb appeal.",
            "price": 18.75,
            "quantity": 90,
            "image": "shingle2.png",
            "created_at": now_iso(),
            "active": True,
        },
    ]
    db.table("products").insert_multiple(products)
    print(f"Seeded {len(products)} products.")

    # Reviews: 3 positive reviews each
    reviews = []
    ratings = [5, 5, 4]
    review_texts = [
        "Great quality, installed quickly and looks solid.",
        "Very satisfied — materials feel premium.",
        "Good value and durable so far."
    ]
    prod_table = db.table("products")

    for p in prod_table.all():
        for i in range(3):
            reviews.append({
                "id": make_id("rev"),
                "product_id": p["id"],
                "user_display": f"Reviewer{i+1}",
                "rating": ratings[i],
                "text": review_texts[i],
                "created_at": now_iso(),
                "visible": True,
                "replies": [],
            })
    db.table("reviews").insert_multiple(reviews)
    print(f"Seeded {len(reviews)} reviews.")

    # Inventory audit (initial entries)
    audit_entries = []
    for p in prod_table.all():
        audit_entries.append({
            "id": make_id("audit"),
            "product_id": p["id"],
            "change": p["quantity"],
            "note": "Initial stock seed",
            "performed_by": "system",
            "created_at": now_iso(),
        })
    db.table("inventory_audit").insert_multiple(audit_entries)
    print(f"Seeded {len(audit_entries)} audit entries.")

    # Ensure orders/carts tables exist
    db.table("orders")
    db.table("carts")
    db.table("meta").insert({
        "project": "JDGS Homeshield Roofing (ROOFSYS-TRI)",
        "created_at": now_iso(),
        "notes": "TinyDB seeded with pbkdf2_sha256 hashes."
    })

    print(f"Database created: {DB_FILE} (encrypted)")

if __name__ == "__main__":
    seed()