# encrypted_storage.py
import os
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tinydb.storages import Storage

class EncryptedJSONStorage(Storage):
    """
    AES-GCM encrypted TinyDB storage.
    Stores: [nonce][tag][ciphertext]
    Requires a key to be provided.
    """

    def __init__(self, filename: str, key: bytes):
        if not key:
            raise ValueError("Encryption key must be provided.")
        self.filename = filename
        self.key = key  # must be 16/24/32 bytes (we use 32)
        # Ensure directory exists
        d = os.path.dirname(os.path.abspath(filename))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)

    def read(self):
        if not os.path.exists(self.filename):
            return None

        with open(self.filename, "rb") as f:
            raw = f.read()

        if len(raw) < 28:  # nonce(12) + tag(16)
            return None

        nonce = raw[:12]
        tag = raw[12:28]
        ciphertext = raw[28:]

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        except Exception:
            print("[EncryptedJSONStorage] ERROR: DB is corrupted or wrong key!")
            return None

        try:
            return json.loads(decrypted.decode("utf-8"))
        except Exception:
            return None

    def write(self, data):
        plaintext = json.dumps(data).encode("utf-8")

        nonce = get_random_bytes(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        with open(self.filename, "wb") as f:
            f.write(nonce + tag + ciphertext)