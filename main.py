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
"""

import os
import uuid
import secrets
import re
from datetime import datetime, timedelta
from typing import Optional, List

import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Header
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from tinydb import TinyDB, where
from passlib.hash import pbkdf2_sha256

# ---------- Configuration ----------
DB_FILE = "db.json"
ITEMPICS_DIR = "itempics"
SECRET_FILE = ".secret_key"
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = 60 * 24 * 7  # 7 days

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
def get_db():
    if not os.path.exists(DB_FILE):
        raise RuntimeError("Database file not found. Run create_db.py first.")
    return TinyDB(DB_FILE)

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

SECRET_KEY = ensure_secret()

def create_token(payload: dict, minutes: int = JWT_EXPIRES_MINUTES) -> str:
    to_encode = payload.copy()
    expire = datetime.utcnow() + timedelta(minutes=minutes)
    to_encode.update({"exp": expire})
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

# ---------- XSS Sanitizer ----------
# Very conservative sanitizer: strips tags and common dangerous patterns.
_TAG_RE = re.compile(r'<[^>]+>')
_EVENT_HANDLER_RE = re.compile(r'on\w+\s*=', re.IGNORECASE)
_JAVASCRIPT_SCHEME_RE = re.compile(r'javascript\s*:', re.IGNORECASE)

def sanitize(text: Optional[str]) -> str:
    if not text:
        return ""
    t = str(text)
    # remove tags
    t = _TAG_RE.sub("", t)
    # strip inline event handlers
    t = _EVENT_HANDLER_RE.sub("", t)
    # strip javascript: schemes
    t = _JAVASCRIPT_SCHEME_RE.sub("", t)
    # extra trimming
    return t.strip()

# Role-check dependency
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth header")
    token = authorization.split(" ", 1)[1]
    data = decode_token(token)
    db = get_db()
    user = db.table("users").get(where("id") == data.get("user_id"))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_role(user: dict, allowed: List[str]):
    if user.get("role") not in allowed:
        raise HTTPException(status_code=403, detail="Forbidden for this role")

# ---------- AUTH Endpoints ----------
@app.post("/api/register")
def register(username: str = Form(...), password: str = Form(...), display_name: str = Form(""), email: str = Form("")):
    db = get_db()
    users = db.table("users")
    uname = sanitize(username).lower()
    if users.get(where("username") == uname):
        raise HTTPException(status_code=400, detail="Username taken")
    # default role CUSTOMER
    user = {
        "id": make_id("user"),
        "username": uname,
        "display_name": sanitize(display_name) or uname,
        "email": sanitize(email),
        "password_hash": hash_password(password),
        "role": "CUSTOMER",
        "created_at": now_iso(),
    }
    users.insert(user)
    # auto-create an empty cart for this user
    db.table("carts").insert({"user_id": user["id"], "items": [], "created_at": now_iso()})
    return {"ok": True, "user_id": user["id"], "role": user["role"]}

@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    db = get_db()
    users = db.table("users")
    uname = sanitize(username).lower()
    user = users.get(where("username") == uname)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"user_id": user["id"], "role": user["role"], "username": user["username"]})
    return {"access_token": token, "token_type": "Bearer", "user": {"id": user["id"], "username": user["username"], "role": user["role"], "display_name": user.get("display_name")}}

@app.get("/api/me")
def me(user: dict = Depends(get_current_user)):
    safe = {k: v for k, v in user.items() if k != "password_hash"}
    return safe

# ---------- PRODUCTS ----------
@app.get("/api/products")
def list_products(q: Optional[str] = None, page: int = 1, per_page: int = 10):
    """
    Returns products list. If `q` provided, searches sku, name, and description (case-insensitive).
    Pagination preserved.
    """
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
def create_product(
    name: str = Form(...),
    sku: str = Form(...),
    description: str = Form(""),
    price: float = Form(...),
    quantity: int = Form(...),
    image: Optional[UploadFile] = File(None),
    user: dict = Depends(get_current_user)
):
    require_role(user, ["ADMIN", "INVENTORY"])
    db = get_db()
    products = db.table("products")

    # handle image upload
    image_filename = ""
    if image:
        ext = os.path.splitext(image.filename)[1] or ".png"
        image_filename = f"{make_id('img')}{ext}"
        dest = os.path.join(ITEMPICS_DIR, image_filename)
        with open(dest, "wb") as f:
            f.write(image.file.read())

    prod = {
        "id": make_id("prod"),
        "sku": sanitize(sku),
        "name": sanitize(name),
        "description": sanitize(description),
        "price": float(price),
        "quantity": int(quantity),
        "image": image_filename,
        "created_at": now_iso(),
        "active": True,
    }
    products.insert(prod)

    # inventory audit
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
def update_product(
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
    if name is not None: updates["name"] = sanitize(name)
    if sku is not None: updates["sku"] = sanitize(sku)
    if description is not None: updates["description"] = sanitize(description)
    if price is not None: updates["price"] = float(price)
    # handle quantity change + audit
    if quantity is not None:
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
def delete_product(product_id: str, user: dict = Depends(get_current_user)):
    """
    HARD delete product and related artifacts. Only ADMIN and INVENTORY allowed.
    Removes:
      - product record
      - reviews for that product
      - inventory_audit entries for that product
      - removes product references from carts
      - updates/cancels orders referencing the product
      - deletes product image file from itempics/
    Returns 204 No Content on success.
    """
    require_role(user, ["ADMIN", "INVENTORY"])
    db = get_db()
    products_tbl = db.table("products")
    prod = products_tbl.get(where("id") == product_id)
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")

    # Remove product record
    products_tbl.remove(where("id") == product_id)

    # Remove reviews referencing product_id
    reviews_tbl = db.table("reviews")
    reviews_tbl.remove(where("product_id") == product_id)

    # Remove inventory audit entries referencing product_id
    audit_tbl = db.table("inventory_audit")
    audit_tbl.remove(where("product_id") == product_id)

    # Remove from carts (all carts)
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

    # Update orders: remove product lines; if no items left, mark CANCELLED
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

    # Delete associated image file if present
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
def post_review(product_id: str, rating: int = Form(...), text: str = Form(""), user: dict = Depends(get_current_user)):
    # any logged user can post, but we will allow CUSTOMER too
    db = get_db()
    products = db.table("products")
    if not products.get(where("id") == product_id):
        raise HTTPException(status_code=404, detail="Product not found")
    review = {
        "id": make_id("rev"),
        "product_id": product_id,
        "user_id": user["id"],
        "user_display": sanitize(user.get("display_name") or user.get("username")),
        "rating": int(rating),
        "text": sanitize(text),
        "created_at": now_iso(),
        "visible": True,
        "replies": [],
    }
    db.table("reviews").insert(review)
    return {"ok": True, "review": review}

@app.post("/api/reviews/{product_id}/reply")
def reply_review(product_id: str, review_id: str = Form(...), text: str = Form(...), user: dict = Depends(get_current_user)):
    require_role(user, ["ADMIN", "SALES"])
    db = get_db()
    tbl = db.table("reviews")
    review = tbl.get(where("id") == review_id)
    if not review or review.get("product_id") != product_id:
        raise HTTPException(status_code=404, detail="Review not found")
    reply = {
        "id": make_id("rpl"),
        "by_user": user["username"],
        "by_display": sanitize(user.get("display_name") or user.get("username")),
        "text": sanitize(text),
        "created_at": now_iso()
    }
    replies = review.get("replies", [])
    replies.append(reply)
    tbl.update({"replies": replies}, where("id") == review_id)
    return {"ok": True, "reply": reply}

@app.post("/api/reviews/{product_id}/moderate")
def moderate_review(product_id: str, review_id: str = Form(...), visible: bool = Form(True), user: dict = Depends(get_current_user)):
    require_role(user, ["ADMIN"])
    db = get_db()
    tbl = db.table("reviews")
    review = tbl.get(where("id") == review_id)
    if not review or review.get("product_id") != product_id:
        raise HTTPException(status_code=404, detail="Review not found")
    tbl.update({"visible": bool(visible)}, where("id") == review_id)
    return {"ok": True}

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
def cart_add(product_id: str = Form(...), qty: int = Form(...), user: dict = Depends(get_current_user)):
    db = get_db()
    prod = db.table("products").get(where("id") == product_id)
    if not prod or not prod.get("active", True):
        raise HTTPException(status_code=404, detail="Product not found")
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

@app.post("/api/checkout")
def checkout(user: dict = Depends(get_current_user)):
    require_role(user, ["CUSTOMER"])
    db = get_db()
    carts = db.table("carts")
    cart = carts.get(where("user_id") == user["id"])
    if not cart or not cart.get("items"):
        raise HTTPException(status_code=400, detail="Cart is empty")
    products_tbl = db.table("products")
    orders_tbl = db.table("orders")
    audit_tbl = db.table("inventory_audit")
    # validate stock
    for it in cart["items"]:
        prod = products_tbl.get(where("id") == it["product_id"])
        if not prod or not prod.get("active", True):
            raise HTTPException(status_code=400, detail=f"Product {it['product_id']} not available")
        if prod.get("quantity", 0) < it["qty"]:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for {prod['name']}")

    # deduct stock and add audit
    for it in cart["items"]:
        prod = products_tbl.get(where("id") == it["product_id"])
        new_qty = prod.get("quantity", 0) - it["qty"]
        products_tbl.update({"quantity": new_qty}, where("id") == it["product_id"])
        audit_tbl.insert({
            "id": make_id("audit"),
            "product_id": it["product_id"],
            "change": -int(it["qty"]),
            "note": "Order checkout",
            "performed_by": user["username"],
            "created_at": now_iso(),
        })

    # create order record
    order = {
        "id": make_id("ord"),
        "user_id": user["id"],
        "items": cart["items"],
        "status": "PLACED",
        "created_at": now_iso(),
    }
    orders_tbl.insert(order)

    # clear cart
    carts.update({"items": []}, where("user_id") == user["id"])

    return {"ok": True, "order": order}

@app.get("/api/orders")
def list_orders(user: dict = Depends(get_current_user)):
    db = get_db()
    orders = db.table("orders")
    if user.get("role") == "ADMIN":
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
    audits = sorted(db.table("inventory_audit").all(), key=lambda x: x["created_at"], reverse=True)[:20]
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