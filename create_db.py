# create_db.py
import os
from app import create_app, db
from app.models import Role, User, Product, ProductImage, InventoryAudit, Review, ReviewReply, Cart
from app.utils import hash_password
from datetime import datetime
import secrets

APP = create_app()
APP.app_context().push()

DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'roofing.db')
print("DB path:", DB_PATH)

# Ensure instance dir exists
os.makedirs(os.path.join(os.path.dirname(__file__), 'instance'), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'instance', 'uploads'), exist_ok=True)

# Remove existing DB (if you want fresh seed)
if os.path.exists(DB_PATH):
    print("Removing existing DB for fresh seed...")
    os.remove(DB_PATH)

print("Creating database and tables...")
db.create_all()

# Seed roles
roles = {
    'admin': Role(name='admin', description='Full administrator'),
    'customer': Role(name='customer', description='End customer'),
    'sales': Role(name='sales', description='Sales representative'),
    'inventory': Role(name='inventory', description='Inventory manager')
}
for r in roles.values():
    db.session.add(r)
db.session.commit()

# Create admin user (preconfigured)
admin_email = 'admin@roofing.local'
admin_password = 'AdminPass123!'  # CHANGE IMMEDIATELY in production
admin = User(
    email=admin_email,
    password=hash_password(admin_password),
    full_name='Default Admin',
    role_id=roles['admin'].id
)
db.session.add(admin)
db.session.commit()
print(f"Created admin {admin_email} with password: {admin_password}")

# Create sample users
sample_customer = User(
    email='customer1@example.com',
    password=hash_password('Customer123!'),
    full_name='Customer One',
    role_id=roles['customer'].id
)
sample_sales = User(
    email='sales1@example.com',
    password=hash_password('Sales123!'),
    full_name='Sales Rep',
    role_id=roles['sales'].id
)
sample_inventory = User(
    email='inv1@example.com',
    password=hash_password('Inv123!'),
    full_name='Inventory Manager',
    role_id=roles['inventory'].id
)
db.session.add_all([sample_customer, sample_sales, sample_inventory])
db.session.commit()
print("Created sample users")

# Create sample products
p1 = Product(sku='RF-001', name='Corrugated Metal Sheet', description='Galvanized corrugated metal roofing sheet 2x8m', price=2500.00, quantity=100)
p2 = Product(sku='RF-002', name='Asphalt Shingle Pack', description='Asphalt shingles pack, 20 pieces', price=1200.00, quantity=50)
p3 = Product(sku='RF-003', name='Ridge Cap', description='Aluminum ridge cap 3m', price=300.00, quantity=200)
db.session.add_all([p1, p2, p3])
db.session.commit()

# Add product images as filename references
img1 = ProductImage(product_id=p1.id, filename='corrugated_1.jpg', uploaded_by=admin.id)
img2 = ProductImage(product_id=p2.id, filename='shingle_pack.jpg', uploaded_by=admin.id)
db.session.add_all([img1, img2])
db.session.commit()

# Inventory audit seeded
inv1 = InventoryAudit(product_id=p1.id, changed_by=admin.id, delta=100, reason='Initial stock')
inv2 = InventoryAudit(product_id=p2.id, changed_by=admin.id, delta=50, reason='Initial stock')
db.session.add_all([inv1, inv2])
db.session.commit()

# Sample review
review1 = Review(product_id=p1.id, user_id=sample_customer.id, rating=5, title='Great quality', body='Very sturdy sheets, installed easily.')
db.session.add(review1)
db.session.commit()

# sales reply
reply1 = ReviewReply(review_id=review1.id, user_id=sample_sales.id, body='Thanks for the review! Let us know if you need installation tips.')
db.session.add(reply1)
db.session.commit()

# Create a cart for customer (persistent)
cart = Cart(user_id=sample_customer.id)
db.session.add(cart)
db.session.commit()

print("Database seeding complete. DB file created at:", DB_PATH)
print("Admin email:", admin_email)
print("Admin password:", admin_password)
print("IMPORTANT: Change the admin password after first run.")