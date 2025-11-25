# main.py
"""
Phase 2: FastAPI backend for JDGS Homeshield Roofing (ROOFSYS-TRI)
Single-file backend providing:
- User registration & login (JWT)
- Role-based access control (ADMIN, INVENTORY, SALES, CUSTOMER)
- Product CRUD (+ image upload saved to itempics/)
- Inventory audit trail on stock changes
- Reviews + Sales replies
- Persistent carts and checkout -> orders
- Minimal endpoints for dashboards
Run:
  uvicorn main:app --reload --port 8000
Notes:
  - This version adds on-disk AES-GCM encryption for TinyDB storage using pycryptodome.
  - Ensure pycryptodome is installed (you indicated you already installed it).
"""

import os
import uuid
import secrets
import time
import functools
import inspect
import re
import json
import threading
import time
from datetime import datetime
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Callable

import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Header, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from tinydb import TinyDB, where, Query
from tinydb.storages import Storage
from passlib.hash import pbkdf2_sha256
from encrypted_storage import EncryptedJSONStorage

# PyCryptodome imports for encryption
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ---------- Configuration ----------
DB_FILE = "db.json"
ITEMPICS_DIR = "itempics"
SECRET_FILE = ".secret_key"
# Sliding session inactivity window (seconds). Change as needed.
INACTIVITY_TIMEOUT_SECONDS = 2700 # default 45 minutes = 2700s
JWT_ALGORITHM = "HS256"
# NOTE: JWT_EXPIRES_MINUTES kept for compatibility but sliding tokens use INACTIVITY_TIMEOUT_SECONDS
JWT_EXPIRES_MINUTES = 60 * 24 * 7  # 7 days

# Lockout parameters (account-based, in-memory)
LOCK_THRESHOLD = 5         # failed attempts
LOCK_WINDOW = 60           # seconds to count failed attempts
LOCK_DURATION = 60         # lock duration in seconds

# ---------- App setup ----------
app = FastAPI(title="JDGS Homeshield Roofing - Phase 2 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ensure itempics exists and mount
if not os.path.isdir(ITEMPICS_DIR):
    os.makedirs(ITEMPICS_DIR)
app.mount("/itempics", StaticFiles(directory=ITEMPICS_DIR), name="itempics")
# expose frontend under /site (keeps /api free)
app.mount("/site", StaticFiles(directory=".", html=True), name="site")

# ---------- Helpers ----------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def make_id(prefix="id"):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"

# SECRET KEY management
def ensure_secret():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            return f.read()
    else:
        key = secrets.token_urlsafe(32).encode()
        with open(SECRET_FILE, "wb") as f:
            f.write(key)
        return key

SECRET_KEY = ensure_secret()  # bytes

# Derive a fixed 32-byte key for DB encryption from SECRET_KEY (SHA256)
def _derive_db_key(secret_bytes: bytes) -> bytes:
    h = SHA256.new()
    h.update(secret_bytes)
    return h.digest()  # 32 bytes

DB_ENC_KEY = _derive_db_key(SECRET_KEY)

def create_token(payload: dict, expires_in_seconds: Optional[int] = None) -> str:
    """
    Create a JWT containing payload and exp. If expires_in_seconds provided, use that;
    otherwise default to JWT_EXPIRES_MINUTES.
    """
    to_encode = payload.copy()
    now = datetime.utcnow()
    if expires_in_seconds is not None:
        expire = now + timedelta(seconds=expires_in_seconds)
    else:
        expire = now + timedelta(minutes=JWT_EXPIRES_MINUTES)
    to_encode.update({"exp": expire, "last_seen": int(time.time())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def hash_password(password: str) -> str:
    return pbkdf2_sha256.hash(password)

def verify_password(password: str, hashval: str) -> bool:
    return pbkdf2_sha256.verify(password, hashval)

def require_role(user: dict, allowed: List[str]):
    if user.get("role") not in allowed:
        raise HTTPException(status_code=403, detail="Forbidden for this role")
    
    

# ---------- Basic server-side sanitization (XSS protection) ----------
def sanitize_text(s: Optional[str]) -> Optional[str]:
    """
    Basic sanitizer: remove HTML tags. This is simple and not a full HTML sanitizer,
    but it prevents common script tag injection and inline tags.
    """
    if s is None:
        return s
    no_tags = re.sub(r'<[^>]*?>', '', s)
    no_tags = no_tags.replace('\r', '').replace('\n', '\\n')
    return no_tags

# ---------- TinyDB encrypted storage implementation ----------
class EncryptedJSONStorage(Storage):
    """
    TinyDB Storage that encrypts JSON content on disk using AES-GCM.
    File layout: [12 bytes nonce][16 bytes tag][ciphertext]
    If file does not exist, acts as empty DB.
    """
    def __init__(self, path: str, key: bytes):
        self.path = path
        self.key = key  # must be 16/24/32 bytes (we use 32)
        # Ensure directory exists
        d = os.path.dirname(os.path.abspath(path))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)

    def read(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "rb") as f:
                raw = f.read()
            if not raw:
                return {}
            # raw: nonce(12) + tag(16) + ciphertext
            if len(raw) < 12 + 16:
                # corrupted or plaintext fallback: try parse as utf-8 JSON
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception:
                    return {}
            nonce = raw[:12]
            tag = raw[12:28]
            ct = raw[28:]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ct, tag)
            return json.loads(data.decode("utf-8"))
        except Exception:
            # On any decrypt/read error, return empty DB to avoid crash.
            return {}

    def write(self, data: dict) -> None:
        try:
            plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
            nonce = get_random_bytes(12)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            with open(self.path, "wb") as f:
                f.write(nonce + tag + ct)
        except Exception:
            # If encryption fails, fall back to writing plaintext (last resort)
            with open(self.path, "wb") as f:
                f.write(json.dumps(data).encode("utf-8"))

# Modified get_db to use encrypted storage
def get_db_encryption_key() -> bytes:
    """
    Always returns the same 32-byte encryption key derived from .secret_key
    → No more random keys, no more .db_key file, fully persistent encryption
    """
    if not os.path.exists(SECRET_FILE):
        ensure_secret()  # creates .secret_key if missing
    with open(SECRET_FILE, "rb") as f:
        master_key = f.read()
    return _derive_db_key(master_key)  # uses SHA256 → stable 32-byte key

@functools.lru_cache()
def get_db():
    key = get_db_encryption_key()  # returns the stable 32-byte key from .secret_key
    return TinyDB(DB_FILE, storage=lambda path: EncryptedJSONStorage(path, key))

# ---------- In-memory account failure tracker (no TinyDB writes) ----------
# Structure: account_failures[user_id] = {"attempts": [ts1, ts2, ...], "lock_until": ts_or_none}
account_failures: Dict[str, Dict[str, Any]] = {}

def _clean_attempts(attempts: List[float], window: int) -> List[float]:
    now = time.time()
    return [t for t in attempts if now - t < window]

def _is_locked(user_id: str) -> Optional[float]:
    rec = account_failures.get(user_id)
    if not rec:
        return None
    lock_until = rec.get("lock_until")
    if lock_until and time.time() < lock_until:
        return lock_until
    return None

def _record_failed_attempt(user_id: str):
    now = time.time()
    rec = account_failures.setdefault(user_id, {"attempts": [], "lock_until": None})
    attempts = _clean_attempts(rec["attempts"], LOCK_WINDOW)
    attempts.append(now)
    rec["attempts"] = attempts
    if len(attempts) >= LOCK_THRESHOLD:
        rec["lock_until"] = now + LOCK_DURATION
    account_failures[user_id] = rec

def _clear_failures(user_id: str):
    if user_id in account_failures:
        account_failures[user_id] = {"attempts": [], "lock_until": None}

# ---------- Simple In-Memory Rate Limiter ----------
rate_store: Dict[tuple, List[float]] = {}

def _cleanup_old(ts_list: List[float], window: int) -> List[float]:
    now = time.time()
    return [t for t in ts_list if now - t < window]

def asyncio_is_coroutine(fn: Callable) -> bool:
    try:
        return inspect.iscoroutinefunction(fn)
    except Exception:
        return False

def rate_limit(limit: int, window: int, key: Optional[str] = None):
    def decorator(func: Callable):
        is_coroutine = asyncio_is_coroutine(func)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            request = kwargs.get("request", None)
            if not request:
                for a in args:
                    if isinstance(a, Request):
                        request = a
                        break
            ip = (request.client.host if request and request.client else "unknown")
            endpoint_key = key or f"{func.__module__}.{func.__name__}"
            store_key = (ip, endpoint_key)
            now = time.time()
            arr = rate_store.get(store_key, [])
            arr = _cleanup_old(arr, window)
            if len(arr) >= limit:
                return JSONResponse(status_code=429, content={"detail": "Too many requests"})
            arr.append(now)
            rate_store[store_key] = arr
            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            request = kwargs.get("request", None)
            if not request:
                for a in args:
                    if isinstance(a, Request):
                        request = a
                        break
            ip = (request.client.host if request and request.client else "unknown")
            endpoint_key = key or f"{func.__module__}.{func.__name__}"
            store_key = (ip, endpoint_key)
            now = time.time()
            arr = rate_store.get(store_key, [])
            arr = _cleanup_old(arr, window)
            if len(arr) >= limit:
                return JSONResponse(status_code=429, content={"detail": "Too many requests"})
            arr.append(now)
            rate_store[store_key] = arr
            return func(*args, **kwargs)

        return async_wrapper if is_coroutine else sync_wrapper
    return decorator

# ---------- Authentication + Sliding Session ----------
def _issue_sliding_token_for_user(user: dict) -> str:
    payload = {"user_id": user["id"], "role": user["role"], "username": user["username"]}
    return create_token(payload, expires_in_seconds=INACTIVITY_TIMEOUT_SECONDS)

def _refresh_token_from_payload(payload: dict) -> str:
    new_payload = {
        "user_id": payload.get("user_id"),
        "role": payload.get("role"),
        "username": payload.get("username"),
    }
    return create_token(new_payload, expires_in_seconds=INACTIVITY_TIMEOUT_SECONDS)

def get_current_user(response: Response, authorization: Optional[str] = Header(None)):
    """
    Dependency used by endpoints. Implements sliding session logic:
    - Expects Authorization: Bearer <token>
    - Decodes token normally (pyjwt will validate exp)
    - Checks last_seen claim: if more than INACTIVITY_TIMEOUT_SECONDS ago -> session expired
    - Otherwise issues a refreshed token and sets header X-Refreshed-Token
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth header")
    token = authorization.split(" ", 1)[1]
    data = decode_token(token)
    last_seen = data.get("last_seen")
    now_ts = int(time.time())
    if last_seen is None:
        raise HTTPException(status_code=401, detail="Session expired (no activity timestamp)")
    if (now_ts - int(last_seen)) > INACTIVITY_TIMEOUT_SECONDS:
        raise HTTPException(status_code=401, detail="Session expired due to inactivity")
    try:
        refreshed = _refresh_token_from_payload(data)
        response.headers["X-Refreshed-Token"] = refreshed
    except Exception:
        pass

    db = get_db()
    user = db.table("users").get(where("id") == data.get("user_id"))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ---------- AUTH Endpoints ----------
@app.post("/api/register")
@rate_limit(limit=3, window=60, key="register")
def register(request: Request, username: str = Form(...), password: str = Form(...), display_name: str = Form(""), email: str = Form("")):
    # Password complexity enforced here (for new registers)
    if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password) or re.match(r'^[A-Za-z0-9]*$', password):
        raise HTTPException(status_code=400, detail="Password does not meet complexity requirements (min 8 chars, 1 uppercase, 1 number, 1 special char).")
    db = get_db()
    users = db.table("users")
    if users.get(where("username") == username):
        raise HTTPException(status_code=400, detail="Username taken")
    user = {
        "id": make_id("user"),
        "username": username,
        "display_name": display_name or username,
        "email": email,
        "password_hash": hash_password(password),
        "role": "CUSTOMER",
        "created_at": now_iso(),
    }
    users.insert(user)
    db.table("carts").insert({"user_id": user["id"], "items": [], "created_at": now_iso()})
    return {"ok": True, "user_id": user["id"], "role": user["role"]}

@app.post("/api/login")
@rate_limit(limit=5, window=60, key="login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = get_db()
    users_tbl = db.table("users")
    user = users_tbl.get(where("username") == username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = user.get("id")
    lock_until = _is_locked(user_id)
    if lock_until:
        remaining = int(lock_until - time.time())
        if remaining < 0: remaining = 0
        raise HTTPException(status_code=403, detail=f"Account temporarily locked due to multiple failed login attempts. Try again in {remaining} seconds.")

    if not verify_password(password, user["password_hash"]):
        _record_failed_attempt(user_id)
        rec = account_failures.get(user_id, {})
        if rec.get("lock_until") and time.time() < rec["lock_until"]:
            remaining = int(rec["lock_until"] - time.time())
            if remaining < 0: remaining = 0
            raise HTTPException(status_code=403, detail=f"Account temporarily locked due to multiple failed login attempts. Try again in {remaining} seconds.")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    _clear_failures(user_id)
    token = _issue_sliding_token_for_user(user)
    return {"access_token": token, "token_type": "Bearer", "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}

@app.get("/api/me")
def me(user: dict = Depends(get_current_user)):
    safe = {k: v for k, v in user.items() if k != "password_hash"}
    return safe

# ---------- PRODUCTS ----------
@app.get("/api/products")
@rate_limit(limit=60, window=60, key="list_products")
def list_products(request: Request, q: Optional[str] = None, page: int = 1, per_page: int = 10):
    db = get_db()
    products = db.table("products").all()
    if q:
        q_lower = q.strip().lower()
        def matches(p):
            sku = (p.get("sku") or "").lower()
            name = (p.get("name") or "").lower()
            desc = (p.get("description") or "").lower()
            return (q_lower in sku) or (q_lower in name) or (q_lower in desc)
        products = [p for p in products if matches(p)]
    total = len(products)
    start = max(0, (page - 1) * per_page)
    end = start + per_page
    return {"items": products[start:end], "total": total, "page": page, "per_page": per_page}

@app.post("/api/products")
@rate_limit(limit=20, window=60, key="create_product")
def create_product(request: Request,
    name: str = Form(...),
    sku: str = Form(...),
    description: str = Form(""),
    price: float = Form(...),
    quantity: int = Form(...),
    image: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user)
):
    require_role(user, ["ADMIN", "INVENTORY"])
    if price < 0:
        raise HTTPException(status_code=400, detail="Price cannot be negative.")
    if quantity < 0:
        raise HTTPException(status_code=400, detail="Quantity cannot be negative.")

    db = get_db()
    products = db.table("products")

    image_filename = ""
    if image:
        ext = os.path.splitext(image.filename)[1] or ".png"
        image_filename = f"{make_id('img')}{ext}"
        dest = os.path.join(ITEMPICS_DIR, image_filename)
        with open(dest, "wb") as f:
            f.write(image.file.read())

    prod = {
        "id": make_id("prod"),
        "sku": sku,
        "name": name,
        "description": description,
        "price": float(price),
        "quantity": int(quantity),
        "image": image_filename,
        "created_at": now_iso(),
        "active": True,
    }
    products.insert(prod)
    db.table("inventory_audit").insert({
        "id": make_id("audit"),
        "product_id": prod["id"],
        "change": int(quantity),
        "note": "Product created/initial stock",
        "performed_by": user["username"],
        "created_at": now_iso(),
    })
    return {"ok": True, "product": prod}

@app.put("/api/products/{product_id}")
@rate_limit(limit=20, window=60, key="update_product")
def update_product(request: Request,
    product_id: str,
    name: Optional[str] = Form(None),
    sku: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    price: Optional[float] = Form(None),
    quantity: Optional[int] = Form(None),
    image: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user)
):
    require_role(user, ["ADMIN", "INVENTORY"])
    db = get_db()
    products = db.table("products")
    prod = products.get(where("id") == product_id)
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")
    updates = {}
    if name is not None: updates["name"] = name
    if sku is not None: updates["sku"] = sku
    if description is not None: updates["description"] = description
    if price is not None:
        if price < 0:
            raise HTTPException(status_code=400, detail="Price cannot be negative.")
        updates["price"] = float(price)
    if quantity is not None:
        if quantity < 0:
            raise HTTPException(status_code=400, detail="Quantity cannot be negative.")
        old_qty = int(prod.get("quantity", 0))
        new_qty = int(quantity)
        updates["quantity"] = new_qty
        diff = new_qty - old_qty
        if diff != 0:
            db.table("inventory_audit").insert({
                "id": make_id("audit"),
                "product_id": product_id,
                "change": diff,
                "note": "Manual quantity update",
                "performed_by": user["username"],
                "created_at": now_iso(),
            })
    if image:
        ext = os.path.splitext(image.filename)[1] or ".png"
        image_filename = f"{make_id('img')}{ext}"
        dest = os.path.join(ITEMPICS_DIR, image_filename)
        with open(dest, "wb") as f:
            f.write(image.file.read())
        updates["image"] = image_filename
    if updates:
        products.update(updates, where("id") == product_id)
    prod_after = products.get(where("id") == product_id)
    return {"ok": True, "product": prod_after}

@app.delete("/api/products/{product_id}", status_code=204)
@rate_limit(limit=20, window=60, key="delete_product")
def delete_product(request: Request, product_id: str, user: dict = Depends(get_current_user)):
    require_role(user, ["ADMIN", "INVENTORY"])
    db = get_db()
    products_tbl = db.table("products")
    prod = products_tbl.get(where("id") == product_id)
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")

    products_tbl.remove(where("id") == product_id)
    reviews_tbl = db.table("reviews")
    reviews_tbl.remove(where("product_id") == product_id)
    audit_tbl = db.table("inventory_audit")
    audit_tbl.remove(where("product_id") == product_id)

    carts_tbl = db.table("carts")
    all_carts = carts_tbl.all()
    for c in all_carts:
        items = c.get("items", [])
        new_items = [it for it in items if it.get("product_id") != product_id]
        if len(new_items) != len(items):
            user_id = c.get("user_id")
            created_at = c.get("created_at")
            carts_tbl.remove((where("user_id") == user_id) & (where("created_at") == created_at))
            carts_tbl.insert({"user_id": user_id, "items": new_items, "created_at": created_at})

    orders_tbl = db.table("orders")
    all_orders = orders_tbl.all()
    for ord in all_orders:
        items = ord.get("items", [])
        new_items = [it for it in items if it.get("product_id") != product_id]
        if len(new_items) != len(items):
            orders_tbl.remove(where("id") == ord.get("id"))
            updated = ord.copy()
            updated["items"] = new_items
            if not new_items:
                updated["status"] = "CANCELLED"
            orders_tbl.insert(updated)

    try:
        image_filename = prod.get("image")
        if image_filename:
            fp = os.path.join(ITEMPICS_DIR, image_filename)
            if os.path.exists(fp):
                os.remove(fp)
    except Exception:
        pass

    return JSONResponse(status_code=204, content=None)

# ---------- REVIEWS ----------
@app.get("/api/reviews/{product_id}")
def get_reviews(product_id: str):
    db = get_db()
    reviews = db.table("reviews").search(where("product_id") == product_id)
    return {"product_id": product_id, "reviews": reviews}

@app.post("/api/reviews/{product_id}")
@rate_limit(limit=10, window=60, key="post_review")
def post_review(request: Request, product_id: str, rating: int = Form(...), text: str = Form(""), user: dict = Depends(get_current_user)):
    role = user.get("role")
    if role not in ("CUSTOMER", "ADMIN"):
        raise HTTPException(status_code=403, detail="Only customers may post reviews.")

    if rating < 1 or rating > 5:
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5.")

    db = get_db()
    products = db.table("products")
    if not products.get(where("id") == product_id):
        raise HTTPException(status_code=404, detail="Product not found")

    clean_text = sanitize_text(text)
    review = {
        "id": make_id("rev"),
        "product_id": product_id,
        "user_id": user["id"],
        "user_display": user.get("display_name") or user.get("username"),
        "rating": int(rating),
        "text": clean_text,
        "created_at": now_iso(),
        "visible": True,
        "replies": [],
    }
    db.table("reviews").insert(review)
    return {"ok": True, "review": review}

@app.post("/api/reviews/{product_id}/reply")
@rate_limit(limit=10, window=60, key="reply_review")
def reply_review(request: Request, product_id: str, review_id: str = Form(...), text: str = Form(...), user: dict = Depends(get_current_user)):
    require_role(user, ["ADMIN", "SALES"])
    db = get_db()
    tbl = db.table("reviews")
    review = tbl.get(where("id") == review_id)
    if not review or review.get("product_id") != product_id:
        raise HTTPException(status_code=404, detail="Review not found")
    reply = {
        "id": make_id("rpl"),
        "by_user": user["username"],
        "by_display": user.get("display_name"),
        "text": sanitize_text(text),
        "created_at": now_iso()
    }
    replies = review.get("replies", [])
    replies.append(reply)
    tbl.update({"replies": replies}, where("id") == review_id)
    return {"ok": True, "reply": reply}

@app.delete("/api/reviews/{product_id}/{review_id}", status_code=204)
@rate_limit(limit=10, window=60, key="delete_review")
def delete_review(request: Request, product_id: str, review_id: str, user: dict = Depends(get_current_user)):
    require_role(user, ["ADMIN"])
    db = get_db()
    tbl = db.table("reviews")
    review = tbl.get(where("id") == review_id)
    if not review or review.get("product_id") != product_id:
        raise HTTPException(status_code=404, detail="Review not found")
    tbl.remove(where("id") == review_id)
    return JSONResponse(status_code=204, content=None)

# ---------- CART & ORDERS ----------
@app.get("/api/cart")
def get_cart(user: dict = Depends(get_current_user)):
    db = get_db()
    cart = db.table("carts").get(where("user_id") == user["id"])
    if not cart:
        cart = {"user_id": user["id"], "items": [], "created_at": now_iso()}
        db.table("carts").insert(cart)
    return cart

@app.post("/api/cart/add")
@rate_limit(limit=20, window=60, key="cart_add")
def cart_add(request: Request, product_id: str = Form(...), qty: int = Form(...), user: dict = Depends(get_current_user)):
    db = get_db()
    prod = db.table("products").get(where("id") == product_id)
    if not prod or not prod.get("active", True):
        raise HTTPException(status_code=404, detail="Product not found")
    if not isinstance(qty, int) and isinstance(qty, str) and qty.isdigit():
        qty = int(qty)
    if qty <= 0:
        raise HTTPException(status_code=400, detail="Quantity must be > 0")

    carts = db.table("carts")
    cart = carts.get(where("user_id") == user["id"])
    if not cart:
        cart = {"user_id": user["id"], "items": [], "created_at": now_iso()}
        carts.insert(cart)
    items = cart.get("items", [])
    found = False
    for it in items:
        if it["product_id"] == product_id:
            it["qty"] += qty
            found = True
            break
    if not found:
        items.append({"product_id": product_id, "qty": int(qty)})
    carts.update({"items": items}, where("user_id") == user["id"])
    return {"ok": True, "cart": {"user_id": user["id"], "items": items}}

@app.post("/api/cart/remove")
@rate_limit(limit=20, window=60, key="cart_remove")
def cart_remove(request: Request, product_id: str = Form(...), qty: Optional[int] = Form(None), user: dict = Depends(get_current_user)):
    db = get_db()
    carts = db.table("carts")
    cart = carts.get(where("user_id") == user["id"])
    if not cart:
        raise HTTPException(status_code=400, detail="Cart is empty")
    items = cart.get("items", [])
    changed = False
    new_items = []
    for it in items:
        if it.get("product_id") != product_id:
            new_items.append(it)
            continue
        if qty is None:
            changed = True
            continue
        try:
            q = int(qty)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid qty")
        if q <= 0:
            raise HTTPException(status_code=400, detail="Quantity to remove must be > 0")
        if q >= it.get("qty", 0):
            changed = True
            continue
        else:
            it["qty"] = it.get("qty", 0) - q
            new_items.append(it)
            changed = True
    if changed:
        carts.update({"items": new_items}, where("user_id") == user["id"])
        return {"ok": True, "cart": {"user_id": user["id"], "items": new_items}}
    else:
        raise HTTPException(status_code=404, detail="Product not in cart")

@app.post("/api/checkout")
@rate_limit(limit=3, window=60, key="checkout")
def checkout(request: Request, user: dict = Depends(get_current_user)):
    require_role(user, ["CUSTOMER"])
    db = get_db()
    carts = db.table("carts")
    cart = carts.get(where("user_id") == user["id"])
    if not cart or not cart.get("items"):
        raise HTTPException(status_code=400, detail="Cart is empty")
    products_tbl = db.table("products")
    orders_tbl = db.table("orders")
    audit_tbl = db.table("inventory_audit")
    for it in cart["items"]:
        pid = it.get("product_id")
        qty = it.get("qty", 0)
        if not isinstance(qty, int):
            try:
                qty = int(qty)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid cart quantity value")
        if qty <= 0:
            raise HTTPException(status_code=400, detail="Invalid cart quantity: must be > 0")
        prod = products_tbl.get(where("id") == pid)
        if not prod or not prod.get("active", True):
            raise HTTPException(status_code=400, detail=f"Product {pid} not available")
        if prod.get("quantity", 0) < qty:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for {prod['name']}")

    for it in cart["items"]:
        prod = products_tbl.get(where("id") == it["product_id"])
        new_qty = prod.get("quantity", 0) - int(it["qty"])
        products_tbl.update({"quantity": new_qty}, where("id") == it["product_id"])
        audit_tbl.insert({
            "id": make_id("audit"),
            "product_id": it["product_id"],
            "change": -int(it["qty"]),
            "note": "Order checkout",
            "performed_by": user["username"],
            "created_at": now_iso(),
        })

    order = {
        "id": make_id("ord"),
        "user_id": user["id"],
        "items": cart["items"],
        "status": "PLACED",
        "created_at": now_iso(),
    }
    orders_tbl.insert(order)
    carts.update({"items": []}, where("user_id") == user["id"])
    return {"ok": True, "order": order}

@app.get("/api/orders")
def list_orders(user: dict = Depends(get_current_user)):
    db = get_db()
    orders = db.table("orders")
    if user.get("role") == "ADMIN":
        all_orders = orders.all()
    elif user.get("role") == "SALES":
        all_orders = orders.all()
    else:
        all_orders = orders.search(where("user_id") == user["id"])
    return {"orders": all_orders}



# ---------- DASHBOARD ENDPOINTS (examples) ----------
@app.get("/api/dashboard/inventory")
def dashboard_inventory(user: dict = Depends(get_current_user)):
    require_role(user, ["ADMIN", "INVENTORY"])
    db = get_db()
    products = db.table("products").all()
    audits = sorted(db.table("inventory_audit").all(), key=lambda x: x["created_at"], reverse=True)
    return {"products_count": len(products), "recent_audits": audits}

@app.get("/api/dashboard/sales")
def dashboard_sales(user: dict = Depends(get_current_user)):
    require_role(user, ["ADMIN", "SALES"])
    db = get_db()
    orders = db.table("orders").all()
    return {"orders_count": len(orders), "orders_last_10": orders[-10:]}

@app.get("/")
def root_redirect():
    return RedirectResponse(url="/site/index.html")

# ---------- Ping ----------
@app.get("/api/ping")
def ping():
    return {"status": "ok", "phase": 2}

def auto_backup_loop():
    """Runs in background and backs up db.json every 30 minutes"""
    if not os.path.exists(DB_FILE):
        return  # no database yet

    while True:
        time.sleep(30 * 60)  # 30 minutes
        try:
            from backup_db import create_backup
            create_backup()
            print(f"[AUTO-BACKUP] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Backup created")
        except Exception as e:
            print(f"[AUTO-BACKUP] Failed: {e}")

# Start auto-backup in background when server starts
def start_auto_backup():
    thread = threading.Thread(target=auto_backup_loop, daemon=True)
    thread.start()
    print("[AUTO-BACKUP] Started — will backup every 30 minutes")

# Call this when app starts
start_auto_backup()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)