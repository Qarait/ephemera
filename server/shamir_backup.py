import os
import json
import hashlib
import shutil
import secrets
from pathlib import Path

# --- Shamir Secret Sharing Implementation ---
# 13th Mersenne Prime (2**521 - 1) - Sufficient for 64-byte chunks
_PRIME = 2**521 - 1
_CHUNK_SIZE = 64  # 64 bytes < 521 bits (65 bytes)

def _eval_at(poly, x, prime):
    """Evaluates polynomial (coefficients poly) at x."""
    accum = 0
    for coeff in reversed(poly):
        accum = (accum * x + coeff) % prime
    return accum

def _make_random_shares(secret, k, n, prime=_PRIME):
    """
    Generates a random polynomial with the secret as the constant term,
    and returns n points on that polynomial.
    """
    if k > n:
        raise ValueError("Pool size n must be greater than or equal to threshold k")
        
    # Generate random coefficients
    poly = [secret] + [secrets.randbelow(prime) for _ in range(k - 1)]
    
    points = []
    for i in range(1, n + 1):
        x = i
        y = _eval_at(poly, x, prime)
        points.append((x, y))
    return points

def _extended_gcd(a, b):
    """
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)
    """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def _divmod(num, den, p):
    """Compute num / den modulo p."""
    _, inv, _ = _extended_gcd(den, p)
    return (num * inv) % p

def _lagrange_interpolate(x, x_s, y_s, p):
    """
    Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to k-1 degree.
    """
    k = len(x_s)
    assert k == len(y_s)
    
    def PI(vals):  # upper-case PI -- product of inputs
        accum = 1
        for v in vals:
            accum = (accum * v) % p
        return accum
    
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
        
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p

def _recover_secret(shares, prime=_PRIME):
    """
    Recover the secret from share points (x, y).
    """
    if len(shares) < 2:
        raise ValueError("need at least two shares")
        
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)

def _int_to_hex(val):
    return hex(val)[2:]

def _hex_to_int(val):
    return int(val, 16)

# --- End Implementation ---

def is_shamir_backup_supported(config):
    """
    Returns True only if EPHEMERA_CA_BACKEND == "file".
    """
    backend = config.get('ca_backend', 'file')
    return backend == 'file'

def split_ca_key(ca_key_path: Path, output_dir: Path, k: int, n: int):
    """
    Splits the CA private key into N shards with threshold K.
    Destructively removes the original key after verification.
    """
    if not ca_key_path.exists():
        raise FileNotFoundError(f"CA key not found at {ca_key_path}")
    
    # Read original key
    with open(ca_key_path, 'rb') as f:
        original_bytes = f.read()
    
    # Calculate hash for integrity verification
    key_hash = hashlib.sha256(original_bytes).hexdigest()
    
    # Split into chunks
    chunks = [original_bytes[i:i+_CHUNK_SIZE] for i in range(0, len(original_bytes), _CHUNK_SIZE)]
    
    # Generate shares for each chunk
    # shard_data[i] will hold the list of y-values for shard i
    all_shard_y_values = [[] for _ in range(n)]
    
    for chunk in chunks:
        secret_int = int.from_bytes(chunk, 'big')
        points = _make_random_shares(secret_int, k, n)
        for i, (x, y) in enumerate(points):
            all_shard_y_values[i].append(_int_to_hex(y))
            
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    shard_paths = []
    for i in range(n):
        shard_data = {
            "version": "1.1",
            "k": k,
            "n": n,
            "key_hash": key_hash,
            "shard_index": i + 1,
            "share_chunks": all_shard_y_values[i],
            "total_size": len(original_bytes)
        }
        
        shard_filename = f"shard_{i+1}_of_{n}.json"
        shard_path = output_dir / shard_filename
        
        with open(shard_path, 'w') as f:
            json.dump(shard_data, f, indent=2)
        
        shard_paths.append(shard_path)
        
    # Securely wipe original key
    file_size = ca_key_path.stat().st_size
    with open(ca_key_path, 'wb') as f:
        f.write(os.urandom(file_size))
    
    ca_key_path.unlink()
    
    return shard_paths

def restore_ca_key(shard_paths: list, output_path: Path):
    """
    Restores the CA private key from a list of shard files.
    """
    loaded_shards = []
    k = None
    key_hash = None
    total_size = None
    
    for path in shard_paths:
        with open(path, 'r') as f:
            data = json.load(f)
            
        # Verify metadata consistency
        if k is None:
            k = data['k']
            key_hash = data['key_hash']
            total_size = data.get('total_size')
        else:
            if data['k'] != k:
                raise ValueError("Shards have mismatched threshold (K)")
            if data['key_hash'] != key_hash:
                raise ValueError("Shards belong to different keys (hash mismatch)")
                
        loaded_shards.append(data)
    
    if len(loaded_shards) < k:
        raise ValueError(f"Insufficient shards. Need {k}, got {len(loaded_shards)}")
    
    # Reconstruct chunk by chunk
    num_chunks = len(loaded_shards[0]['share_chunks'])
    recovered_bytes_io = bytearray()
    
    for chunk_idx in range(num_chunks):
        points = []
        for shard in loaded_shards:
            x = shard['shard_index']
            y = _hex_to_int(shard['share_chunks'][chunk_idx])
            points.append((x, y))
            
        recovered_int = _recover_secret(points)
        
        # Determine chunk size (last chunk might be smaller)
        # But we don't know if it's the last chunk yet easily without math.
        # However, int.to_bytes needs size.
        # We know max chunk size is _CHUNK_SIZE.
        # If it's the last chunk, it might be smaller.
        # We can use total_size to determine.
        
        remaining = total_size - len(recovered_bytes_io)
        current_chunk_size = min(_CHUNK_SIZE, remaining)
        
        chunk_bytes = recovered_int.to_bytes(current_chunk_size, 'big')
        recovered_bytes_io.extend(chunk_bytes)
        
    recovered_bytes = bytes(recovered_bytes_io)
    
    # Verify integrity
    recovered_hash = hashlib.sha256(recovered_bytes).hexdigest()
    if recovered_hash != key_hash:
        raise ValueError("Restored key hash does not match original hash. Integrity check failed.")
        
    # Write to output
    with open(output_path, 'wb') as f:
        f.write(recovered_bytes)
        
    # Set permissions (0600)
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass
        
    return True
