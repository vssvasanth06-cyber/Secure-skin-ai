import os
import hashlib
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================
# 🔐 HASH (INTEGRITY)
# =========================
def generate_hash(data: bytes):
    return hashlib.sha256(data).hexdigest()


# =========================
# 🔐 AES-256-GCM (DATA ENCRYPTION)
# =========================
# Bulk medical data (images + reports) is encrypted with AES-256 in GCM mode,
# an AEAD cipher that provides confidentiality AND built-in integrity (auth tag)
# with a 256-bit key. The stored ciphertext layout is:
#
#     b"GCM1" | 12-byte nonce | ciphertext-with-tag
#
# Backward compatibility: records written before the AES-256 upgrade were
# encrypted with Fernet (AES-128-CBC + HMAC). ``decrypt_data`` detects the
# legacy format and falls back transparently, so no existing data is lost.
_GCM_MAGIC = b"GCM1"
_GCM_NONCE_LEN = 12   # 96-bit nonce is the GCM-recommended size


def generate_aes_key():
    """
    Generate a 256-bit AES key as a URL-safe base64 token (44 chars).
    Base64 keeps the key printable and RSA-wrappable exactly like before, while
    now carrying a full 32 bytes = 256 bits of entropy (previously 128-bit).
    """
    return base64.urlsafe_b64encode(os.urandom(32))


def _aes256_raw_key(key) -> bytes:
    """Return the raw 32-byte AES-256 key from a base64 token or raw bytes."""
    if isinstance(key, str):
        key = key.encode()
    if isinstance(key, memoryview):
        key = bytes(key)
    if len(key) == 32:
        return key
    try:
        raw = base64.urlsafe_b64decode(key)
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    # Last-resort deterministic derivation (keeps length correct).
    return hashlib.sha256(key).digest()


def encrypt_data(data: bytes, key: bytes):
    """Encrypt bulk data with AES-256-GCM. Output: b"GCM1" | nonce | ct+tag."""
    aes_key = _aes256_raw_key(key)
    nonce = os.urandom(_GCM_NONCE_LEN)
    ct = AESGCM(aes_key).encrypt(nonce, data, None)
    return _GCM_MAGIC + nonce + ct


def decrypt_data(encrypted_data, key: bytes):
    """
    Decrypt data written by ``encrypt_data``.
    New format  → AES-256-GCM.
    Legacy data → transparent Fernet (AES-128) fallback.
    """
    if isinstance(encrypted_data, memoryview):
        encrypted_data = bytes(encrypted_data)
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()

    if encrypted_data[:4] == _GCM_MAGIC:
        aes_key = _aes256_raw_key(key)
        nonce = encrypted_data[4:4 + _GCM_NONCE_LEN]
        ct = encrypted_data[4 + _GCM_NONCE_LEN:]
        return AESGCM(aes_key).decrypt(nonce, ct, None)

    # Legacy Fernet token (AES-128-CBC + HMAC-SHA256)
    return Fernet(key).decrypt(encrypted_data)


# =========================
# 🔐 RSA KEY GENERATION
# =========================
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_bytes, private_bytes


# =========================
# 🔐 RSA ENCRYPT AES KEY
# =========================
def encrypt_key(aes_key: bytes, public_key_bytes: bytes):

    public_key = serialization.load_pem_public_key(public_key_bytes)

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


# =========================
# 🔓 RSA DECRYPT AES KEY
# =========================
def decrypt_key(encrypted_key: bytes, private_key_bytes: bytes):

    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None
    )

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key


# =========================
# 🔏 DIGITAL SIGNATURE
# =========================
def sign_data(private_key_bytes: bytes, data: bytes):

    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None
    )

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(public_key_bytes: bytes, data: bytes, signature: bytes):

    public_key = serialization.load_pem_public_key(public_key_bytes)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


# =========================
# 🔐 HYBRID ENCRYPTION (MAIN)
# =========================
def hybrid_encrypt(data: bytes, public_key_bytes: bytes, private_key_bytes: bytes):

    # Step 1: AES key
    aes_key = generate_aes_key()

    # Step 2: Encrypt data
    encrypted_data = encrypt_data(data, aes_key)

    # Step 3: Encrypt AES key using RSA
    encrypted_key = encrypt_key(aes_key, public_key_bytes)

    # Step 4: Hash
    data_hash = generate_hash(data)

    # Step 5: Sign
    signature = sign_data(private_key_bytes, data)

    # Encode for storage
    return {
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "signature": base64.b64encode(signature).decode(),
        "hash": data_hash
    }


# =========================
# 🔓 HYBRID DECRYPTION (MAIN)
# =========================
def hybrid_decrypt(enc_dict, public_key_bytes: bytes, private_key_bytes: bytes):

    encrypted_data = base64.b64decode(enc_dict["encrypted_data"])
    encrypted_key = base64.b64decode(enc_dict["encrypted_key"])
    signature = base64.b64decode(enc_dict["signature"])
    stored_hash = enc_dict["hash"]

    # Step 1: Decrypt AES key
    aes_key = decrypt_key(encrypted_key, private_key_bytes)

    # Step 2: Decrypt data
    decrypted_data = decrypt_data(encrypted_data, aes_key)

    # Step 3: Verify hash
    if generate_hash(decrypted_data) != stored_hash:
        return "Data Integrity Failed ❌"

    # Step 4: Verify signature
    if not verify_signature(public_key_bytes, decrypted_data, signature):
        return "Signature Invalid ❌"

    return decrypted_data

def load_keys():
    with open("public.pem", "rb") as f:
        public_key = f.read()

    with open("private.pem", "rb") as f:
        private_key = f.read()

    return public_key, private_key