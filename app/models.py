# app/models.py
from datetime import datetime
from enum import Enum
from flask_login import UserMixin
from app import db
from sqlalchemy import event, CheckConstraint, Index, func
from sqlalchemy.orm import relationship

class RoleEnum(Enum):
    ADMIN = "admin"
    CUSTOMER = "customer"
    SALES = "sales"
    INVENTORY = "inventory"

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    description = db.Column(db.String(255))

    def __repr__(self):
        return f"<Role {self.name}>"

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    role = relationship('Role')

    def get_role(self):
        return self.role.name if self.role else None

    def __repr__(self):
        return f"<User {self.email} role={self.get_role()}>"

# Product Catalog
class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(12, 2), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    images = relationship('ProductImage', back_populates='product', cascade="all, delete-orphan")
    reviews = relationship('Review', back_populates='product', cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint('quantity >= 0', name='check_quantity_positive'),
    )

    def average_rating(self):
        # computed in app logic via queries - placeholder
        return None

    def __repr__(self):
        return f"<Product {self.sku} {self.name}>"

class ProductImage(db.Model):
    __tablename__ = 'product_images'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    filename = db.Column(db.String(512), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    product = relationship('Product', back_populates='images')

# Inventory audit trail
class InventoryAudit(db.Model):
    __tablename__ = 'inventory_audits'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    changed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    delta = db.Column(db.Integer, nullable=False)  # + for add, - for remove
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    product = relationship('Product')

# Reviews and moderation
class Review(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    title = db.Column(db.String(255))
    body = db.Column(db.Text)
    is_hidden = db.Column(db.Boolean, default=False)  # soft-delete/hide for moderation
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    product = relationship('Product', back_populates='reviews')

    __table_args__ = (
        CheckConstraint('rating >= 1 AND rating <= 5', name='check_rating_range'),
    )

class ReviewReply(db.Model):
    __tablename__ = 'review_replies'
    id = db.Column(db.Integer, primary_key=True)
    review_id = db.Column(db.Integer, db.ForeignKey('reviews.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # sales or admin user who replies
    body = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    review = relationship('Review')

# Shopping cart & persistent cart pattern
class Cart(db.Model):
    __tablename__ = 'carts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    items = relationship('CartItem', back_populates='cart', cascade="all, delete-orphan")

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('carts.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    cart = relationship('Cart', back_populates='items')
    product = relationship('Product')

    __table_args__ = (
        CheckConstraint('quantity > 0', name='check_cartitem_quantity'),
        Index('ix_cart_product', 'cart_id', 'product_id', unique=True),
    )

# Orders and Order items
class OrderStatusEnum(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    CANCELLED = "cancelled"
    COMPLETED = "completed"

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_price = db.Column(db.Numeric(12,2), nullable=False)
    status = db.Column(db.String(32), default=OrderStatusEnum.PENDING.value, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = relationship('OrderItem', back_populates='order', cascade="all, delete-orphan")

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(12,2), nullable=False)
    subtotal = db.Column(db.Numeric(12,2), nullable=False)

    order = relationship('Order', back_populates='items')
    product = relationship('Product')

# Security / activity log
class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_type = db.Column(db.String(64), nullable=False)  # login_success, login_failed, inventory_change, etc.
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6-safe
    user_agent = db.Column(db.String(255), nullable=True)
    detail = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)