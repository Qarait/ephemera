import os
import json
import hashlib
import shutil
import secrets
import tarfile
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Shamir Secret Sharing Implementation (Internal) ---
# 13th Mersenne Prime (2**521 - 1)
_PRIME = 2**521 - 1

def _eval_at(poly, x, prime):
    accum = 0
    for coeff in reversed(poly):
        accum = (accum * x + coeff) % prime
    return accum

def _make_random_shares(secret, k, n, prime=_PRIME):
    if k > n:
        raise ValueError("Pool size n must be greater than or equal to threshold k")
    poly = [secret] + [secrets.randbelow(prime) for _ in range(k - 1)]
    points = []
    for i in range(1, n + 1):
        x = i
        y = _eval_at(poly, x, prime)
        points.append((x, y))
    return points

def _extended_gcd(a, b):
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def _divmod(num, den, p):
    _, inv, _ = _extended_gcd(den, p)
    return (num * inv) % p

def _lagrange_interpolate(x, x_s, y_s, p):
    k = len(x_s)
    def PI(vals):
        accum = 1
        for v in vals:
            accum = (accum * v) % p
        return accum
    nums = []
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p) for i in range(k)])
    return (_divmod(num, den, p) + p) % p

def _recover_secret(shares, prime=_PRIME):
    if len(shares) < 2:
        raise ValueError("need at least two shares")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)

def _int_to_hex(val):
    return hex(val)[2:]

def _hex_to_int(val):
    return int(val, 16)
# --- End Shamir Implementation ---

def create_backup(output_dir: Path, k: int, n: int):
    """
    Creates an encrypted backup of CA keys and DB.
    The encryption password is split into N Shamir shards.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Create Tarball of critical files
    files_to_backup = ["ca.key", "ca.crt", "ephemera.db"]
    tar_path = output_dir / "temp_backup.tar.gz"
    
    with tarfile.open(tar_path, "w:gz") as tar:
        for fname in files_to_backup:
            if os.path.exists(fname):
                tar.add(fname)
            else:
                print(f"Warning: {fname} not found, skipping.")
                
    with open(tar_path, "rb") as f:
        plaintext_data = f.read()
        
    # 2. Encrypt Tarball
    # Generate random 32-byte password (AES-256 key)
    password = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12) # GCM nonce
    
    aesgcm = AESGCM(password)
    ciphertext = aesgcm.encrypt(nonce, plaintext_data, None)
    
    # Write encrypted file (nonce + ciphertext)
    enc_path = output_dir / "ephemera_backup.enc"
    with open(enc_path, "wb") as f:
        f.write(nonce + ciphertext)
        
    # Cleanup tarball
    tar_path.unlink()
    
    # 3. Split Password
    password_int = int.from_bytes(password, 'big')
    points = _make_random_shares(password_int, k, n)
    
    password_hash = hashlib.sha256(password).hexdigest()
    
    shard_paths = []
    for i, (x, y) in enumerate(points):
        shard_data = {
            "version": "2.0", # 2.0 = Encrypted Backup
            "k": k,
            "n": n,
            "password_hash": password_hash,
            "shard_index": x,
            "share_hex": _int_to_hex(y)
        }
        
        shard_filename = f"backup_shard_{x}_of_{n}.json"
        shard_path = output_dir / shard_filename
        
        with open(shard_path, "w") as f:
            json.dump(shard_data, f, indent=2)
        shard_paths.append(shard_path)
        
    return enc_path, shard_paths

def restore_backup(backup_file: Path, shard_paths: list, output_dir: Path):
    """
    Restores backup from encrypted file and shards.
    """
    # 1. Reconstruct Password
    points = []
    k = None
    password_hash = None
    
    for path in shard_paths:
        with open(path, "r") as f:
            data = json.load(f)
            
        if k is None:
            k = data['k']
            password_hash = data['password_hash']
        else:
            if data['k'] != k:
                raise ValueError("Shards have mismatched threshold (K)")
            if data['password_hash'] != password_hash:
                raise ValueError("Shards belong to different backups")
                
        points.append((data['shard_index'], _hex_to_int(data['share_hex'])))
        
    if len(points) < k:
        raise ValueError(f"Insufficient shards. Need {k}, got {len(points)}")
        
    password_int = _recover_secret(points)
    
    # Convert back to bytes (32 bytes for AES-256)
    # We know it's 32 bytes because we generated it that way.
    try:
        password = password_int.to_bytes(32, 'big')
    except OverflowError:
        # Should not happen if math is correct and prime is large enough
        # 2**521 is way larger than 256 bits.
        raise ValueError("Recovered password too large (math error?)")
        
    # Verify hash
    if hashlib.sha256(password).hexdigest() != password_hash:
        raise ValueError("Restored password hash mismatch. Integrity check failed.")
        
    # 2. Decrypt Backup
    with open(backup_file, "rb") as f:
        data = f.read()
        
    nonce = data[:12]
    ciphertext = data[12:]
    
    aesgcm = AESGCM(password)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")
        
    # 3. Extract Tarball
    output_dir.mkdir(parents=True, exist_ok=True)
    tar_path = output_dir / "restored_backup.tar.gz"
    
    with open(tar_path, "wb") as f:
        f.write(plaintext)
        
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path=output_dir)
        
    tar_path.unlink()
    return True
