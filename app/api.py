# app/api.py
import math
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from app import db
from app.models import Product, ProductImage, InventoryAudit, Review, ReviewReply, Cart, CartItem, Order, OrderItem, SecurityLog
from app.decorators import role_required
from app.upload_helpers import save_image
from decimal import Decimal
from sqlalchemy import or_

bp = Blueprint('api', __name__, url_prefix='/api')

# --- Products: public listing with search/filter/pagination ---
@bp.route('/products', methods=['GET'])
def list_products():
    q = request.args.get('q', '').strip()
    page = max(int(request.args.get('page', 1)), 1)
    per_page = min(int(request.args.get('per_page', 10)), 50)
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')
    only_active = request.args.get('active', '1') == '1'

    query = Product.query
    if only_active:
        query = query.filter_by(is_active=True)
    if q:
        query = query.filter(or_(Product.name.ilike(f'%{q}%'), Product.description.ilike(f'%{q}%'), Product.sku.ilike(f'%{q}%')))
    if min_price:
        query = query.filter(Product.price >= Decimal(min_price))
    if max_price:
        query = query.filter(Product.price <= Decimal(max_price))

    total = query.count()
    items = query.order_by(Product.created_at.desc()).offset((page-1)*per_page).limit(per_page).all()

    results = []
    for p in items:
        # compute avg ratings
        avg = db.session.query(db.func.avg(Review.rating)).filter(Review.product_id==p.id, Review.is_hidden==False).scalar()
        results.append({
            'id': p.id,
            'sku': p.sku,
            'name': p.name,
            'description': p.description,
            'price': str(p.price),
            'quantity': p.quantity,
            'avg_rating': float(avg) if avg else None,
            'images': [img.filename for img in p.images]
        })

    return jsonify({
        'items': results,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': math.ceil(total / per_page) if per_page else 0
        }
    })

# --- Product create/update/delete (Admin & Inventory roles) ---
@bp.route('/products', methods=['POST'])
@login_required
@role_required('admin', 'inventory')
def create_product():
    data = request.form or {}
    sku = data.get('sku')
    name = data.get('name')
    price = data.get('price')
    qty = int(data.get('quantity', 0))
    desc = data.get('description', '')

    if not sku or not name or price is None:
        return jsonify({'error': 'sku, name, price required'}), 400

    # basic uniqueness check
    if Product.query.filter_by(sku=sku).first():
        return jsonify({'error': 'sku exists'}), 400

    product = Product(sku=sku, name=name, description=desc, price=Decimal(price), quantity=qty)
    db.session.add(product)
    db.session.commit()

    # inventory audit
    audit = InventoryAudit(product_id=product.id, changed_by=current_user.id, delta=qty, reason='initial create')
    db.session.add(audit)
    db.session.commit()

    return jsonify({'ok': True, 'product_id': product.id}), 201

@bp.route('/products/<int:product_id>', methods=['PUT'])
@login_required
@role_required('admin', 'inventory')
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    data = request.get_json() or {}
    # allow changing quantity via inventory adjustments
    if 'quantity' in data:
        new_qty = int(data['quantity'])
        delta = new_qty - product.quantity
        product.quantity = new_qty
        db.session.add(InventoryAudit(product_id=product.id, changed_by=current_user.id, delta=delta, reason=data.get('reason', 'quantity update')))
    if 'name' in data:
        product.name = data['name']
    if 'description' in data:
        product.description = data['description']
    if 'price' in data:
        product.price = Decimal(data['price'])
    db.session.commit()

    # log inventory change
    if 'quantity' in data:
        log = SecurityLog(user_id=current_user.id, event_type='inventory_change', detail=f'Product {product.sku} quantity changed by {delta}')
        db.session.add(log)
        db.session.commit()

    return jsonify({'ok': True})

@bp.route('/products/<int:product_id>', methods=['DELETE'])
@login_required
@role_required('admin')
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'ok': True})

# --- Upload product image (Admin & Inventory) ---
@bp.route('/products/<int:product_id>/images', methods=['POST'])
@login_required
@role_required('admin', 'inventory')
def upload_product_image(product_id):
    product = Product.query.get_or_404(product_id)
    if 'image' not in request.files:
        return jsonify({'error': 'no image file'}), 400
    file = request.files['image']
    try:
        filename = save_image(file)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    img = ProductImage(product_id=product.id, filename=filename, uploaded_by=current_user.id)
    db.session.add(img)
    db.session.commit()
    return jsonify({'ok': True, 'filename': filename})

# --- Cart endpoints ---
@bp.route('/cart', methods=['GET'])
@login_required
def get_cart():
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart:
        return jsonify({'items': []})
    items = []
    for ci in cart.items:
        items.append({'product_id': ci.product_id, 'quantity': ci.quantity, 'name': ci.product.name, 'unit_price': str(ci.product.price)})
    return jsonify({'items': items})

@bp.route('/cart/items', methods=['POST'])
@login_required
def add_cart_item():
    data = request.get_json() or {}
    product_id = data.get('product_id')
    quantity = int(data.get('quantity', 1))
    if not product_id:
        return jsonify({'error': 'product_id required'}), 400
    product = Product.query.get_or_404(product_id)
    if quantity <= 0:
        return jsonify({'error': 'quantity must be positive'}), 400

    cart = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart:
        cart = Cart(user_id=current_user.id)
        db.session.add(cart)
        db.session.commit()

    item = CartItem.query.filter_by(cart_id=cart.id, product_id=product.id).first()
    if item:
        item.quantity += quantity
    else:
        item = CartItem(cart_id=cart.id, product_id=product.id, quantity=quantity)
        db.session.add(item)
    db.session.commit()
    return jsonify({'ok': True})

@bp.route('/cart/items/<int:item_id>', methods=['DELETE'])
@login_required
def remove_cart_item(item_id):
    item = CartItem.query.get_or_404(item_id)
    if item.cart.user_id != current_user.id:
        return jsonify({'error': 'not allowed'}), 403
    db.session.delete(item)
    db.session.commit()
    return jsonify({'ok': True})

# --- Checkout -> create Order ---
@bp.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart or not cart.items:
        return jsonify({'error': 'cart empty'}), 400

    # calculate total, check stock
    total = Decimal('0.00')
    for ci in cart.items:
        if ci.quantity > ci.product.quantity:
            return jsonify({'error': f'not enough stock for {ci.product.name}'}), 400
        total += Decimal(ci.product.price) * ci.quantity

    # create order
    import uuid
    order = Order(order_number=str(uuid.uuid4()), user_id=current_user.id, total_price=total)
    db.session.add(order)
    db.session.flush()  # get order.id

    for ci in list(cart.items):
        oi = OrderItem(order_id=order.id, product_id=ci.product_id, quantity=ci.quantity, unit_price=ci.product.price, subtotal=Decimal(ci.product.price) * ci.quantity)
        db.session.add(oi)
        # decrement stock
        old_qty = ci.product.quantity
        ci.product.quantity -= ci.quantity
        db.session.add(InventoryAudit(product_id=ci.product_id, changed_by=current_user.id, delta=-ci.quantity, reason='checkout order'))
        db.session.delete(ci)  # remove from cart

    db.session.commit()
    return jsonify({'ok': True, 'order_id': order.id, 'order_number': order.order_number})

# --- Order history ---
@bp.route('/orders', methods=['GET'])
@login_required
def list_orders():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    out = []
    for o in orders:
        out.append({
            'order_id': o.id,
            'order_number': o.order_number,
            'total_price': str(o.total_price),
            'status': o.status,
            'created_at': o.created_at.isoformat(),
            'items': [{'product_id': it.product_id, 'quantity': it.quantity, 'unit_price': str(it.unit_price)} for it in o.items]
        })
    return jsonify(out)

# --- Reviews & replies ---
@bp.route('/products/<int:product_id>/reviews', methods=['POST'])
@login_required
def create_review(product_id):
    data = request.get_json() or {}
    rating = int(data.get('rating', 0))
    title = data.get('title', '')
    body = data.get('body', '')
    if rating < 1 or rating > 5:
        return jsonify({'error': 'rating must be 1-5'}), 400
    review = Review(product_id=product_id, user_id=current_user.id, rating=rating, title=title, body=body)
    db.session.add(review)
    db.session.commit()
    return jsonify({'ok': True, 'review_id': review.id})

@bp.route('/reviews/<int:review_id>/reply', methods=['POST'])
@login_required
@role_required('admin', 'sales')
def reply_review(review_id):
    data = request.get_json() or {}
    body = data.get('body', '')
    if not body:
        return jsonify({'error': 'body required'}), 400
    reply = ReviewReply(review_id=review_id, user_id=current_user.id, body=body)
    db.session.add(reply)
    db.session.commit()
    return jsonify({'ok': True})

@bp.route('/reviews/<int:review_id>/hide', methods=['POST'])
@login_required
@role_required('admin')
def hide_review(review_id):
    review = Review.query.get_or_404(review_id)
    review.is_hidden = True
    db.session.commit()
    return jsonify({'ok': True})