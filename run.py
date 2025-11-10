# run.py
from app import create_app, db
import os

app = create_app()

if __name__ == '__main__':
    # Ensure DB exists (safe to call)
    with app.app_context():
        db.create_all()

    # For local HTTPS testing (optional), generate a self-signed cert and set paths:
    SSL_CERT = os.environ.get('SSL_CERT')  # e.g., instance/ssl/cert.pem
    SSL_KEY = os.environ.get('SSL_KEY')    # e.g., instance/ssl/key.pem

    if SSL_CERT and SSL_KEY and os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        app.run(host='127.0.0.1', port=5000, ssl_context=(SSL_CERT, SSL_KEY), debug=True)
    else:
        app.run(host='127.0.0.1', port=5000, debug=True)