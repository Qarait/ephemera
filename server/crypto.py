import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_ca_key(ca_key_path: str, master_password: str):
    """Encrypt CA private key at rest"""
    salt = os.urandom(16)
    encryption_key = derive_key_from_password(master_password, salt)
    fernet = Fernet(encryption_key)
    
    with open(ca_key_path, 'rb') as f:
        ca_key_data = f.read()
    
    encrypted_data = fernet.encrypt(ca_key_data)
    
    enc_path = f"{ca_key_path}.enc"
    with open(enc_path, 'wb') as f:
        f.write(salt + encrypted_data)
    
    if os.path.exists(ca_key_path):
        os.remove(ca_key_path)
    os.chmod(enc_path, 0o400)
    print(f"CA key encrypted to {enc_path}")

def decrypt_ca_key(encrypted_path: str, master_password: str) -> bytes:
    """Decrypt CA key for use"""
    with open(encrypted_path, 'rb') as f:
        data = f.read()
    
    salt = data[:16]
    encrypted_data = data[16:]
    
    encryption_key = derive_key_from_password(master_password, salt)
    fernet = Fernet(encryption_key)
    
    return fernet.decrypt(encrypted_data)
