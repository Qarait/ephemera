import os
import json
import datetime
import logging
from logging.handlers import SysLogHandler
import hashlib
import uuid
from collections import defaultdict

from server.crypto import derive_key_from_password, encrypt_ca_key, decrypt_ca_key
from server.hsm.softhsm import validate_softhsm_boot
from server.config_ca import (
    CA_BACKEND,
    PKCS11_MODULE,
    PKCS11_SLOT,
    PKCS11_KEY_LABEL,
    PKCS11_PIN,
)
from server.ca.backends import FileCA, SoftHsmCA
from server.key_manager import KeyManager

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_DIR = os.path.join(BASE_DIR, 'ca_store')
DATA_DIR = os.path.join(BASE_DIR, 'data')
TEMP_DIR = os.path.join(BASE_DIR, 'temp')
PUBLIC_DIR = os.path.join(os.path.dirname(BASE_DIR), 'public')

CA_KEY = os.path.join(CA_DIR, 'ca_key')
CA_PUB = os.path.join(CA_DIR, 'ca_key.pub')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
AUDIT_FILE = os.path.join(DATA_DIR, 'audit.json')

CA_MASTER_PASSWORD = os.environ.get('CA_MASTER_PASSWORD', 'ephemera-dev-secret')

# Role to Principals Mapping
ROLE_PRINCIPALS = {
    "admin": "root,admin,user",
    "developer": "user",
    "reader": "guest"
}

# In-memory rate limiting
login_attempts = defaultdict(list)  # {username:ip: [timestamps]}
cert_requests = defaultdict(list)   # {username: [timestamps]}

RATE_LIMIT_CONFIG = {
    'login': {
        'window_minutes': 15,
        'max_attempts': 5,
        'lockout_minutes': 30
    },
    'cert_request': {
        'window_minutes': 60,
        'max_requests': 20
    }
}

# Setup Syslog
syslog_logger = logging.getLogger('ephemera_audit')
syslog_logger.setLevel(logging.INFO)
try:
    handler = SysLogHandler(address=('syslog', 514), facility=SysLogHandler.LOG_USER)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    syslog_logger.addHandler(handler)
except Exception as e:
    print(f"Warning: Could not connect to syslog: {e}")

# Crypto Helpers imported from server.crypto

# Data Access
def get_users():
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def get_audit_log():
    entries = []
    if not os.path.exists(AUDIT_FILE):
        return []
        
    try:
        with open(AUDIT_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries[::-1]
    except FileNotFoundError:
        return []

def append_audit_log(entry):
    prev_hash = "0" * 64
    if os.path.exists(AUDIT_FILE):
        try:
            with open(AUDIT_FILE, 'r') as f:
                lines = f.readlines()
                for line in reversed(lines):
                    if line.strip():
                        try:
                            last_entry = json.loads(line)
                            prev_hash = last_entry.get('hash', "0" * 64)
                            break
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            print(f"Error reading audit log for chaining: {e}")

    entry['prev_hash'] = prev_hash
    entry_string_for_hash = json.dumps(entry, sort_keys=True)
    entry['hash'] = hashlib.sha256(entry_string_for_hash.encode()).hexdigest()

    try:
        with open(AUDIT_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except PermissionError:
        print("CRITICAL: Cannot write to audit log. File might be immutable.")
        
    try:
        syslog_logger.info(json.dumps(entry))
    except Exception as e:
        print(f"Failed to send to syslog: {e}")

def verify_audit_chain():
    if not os.path.exists(AUDIT_FILE):
        return {"valid": True, "message": "Log is empty"}
        
    errors = []
    try:
        with open(AUDIT_FILE, 'r') as f:
            lines = f.readlines()
            
        prev_hash = "0" * 64
        
        for i, line in enumerate(lines):
            if not line.strip(): continue
            
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"Line {i+1}: Invalid JSON")
                continue
                
            stored_hash = entry.get('hash')
            stored_prev_hash = entry.get('prev_hash')
            
            if not stored_hash:
                prev_hash = "0" * 64 
                continue

            if stored_prev_hash != prev_hash:
                errors.append(f"Line {i+1}: Broken chain. Expected prev_hash {prev_hash[:8]}..., got {stored_prev_hash[:8]}...")
            
            entry_for_hashing = entry.copy()
            if 'hash' in entry_for_hashing:
                del entry_for_hashing['hash']
            
            calculated_hash = hashlib.sha256(json.dumps(entry_for_hashing, sort_keys=True).encode()).hexdigest()
            
            if calculated_hash != stored_hash:
                 errors.append(f"Line {i+1}: Integrity failure. Content modified.")
                 
            prev_hash = stored_hash
            
        if errors:
            return {"valid": False, "errors": errors}
        return {"valid": True, "message": f"Verified {len(lines)} entries successfully."}
            
    except Exception as e:
        return {"valid": False, "error": str(e)}

def check_rate_limit(username, ip, limit_type='login'):
    config = RATE_LIMIT_CONFIG[limit_type]
    now = datetime.datetime.utcnow()
    window = datetime.timedelta(minutes=config['window_minutes'])
    
    if limit_type == 'login':
        key = f"{username}:{ip}"
        attempts = login_attempts[key]
    else:
        attempts = cert_requests[username]
    
    attempts[:] = [t for t in attempts if now - t < window]
    
    max_allowed = config.get('max_attempts') or config.get('max_requests')
    if len(attempts) >= max_allowed:
        append_audit_log({
            "timestamp": now.isoformat() + "Z",
            "username": username,
            "ip": ip,
            "event": f"{limit_type}_rate_limit_exceeded",
            "details": f"Exceeded {max_allowed} attempts in {config['window_minutes']} minutes"
        })
        return False
    
    return True

def record_attempt(username, ip, limit_type='login'):
    now = datetime.datetime.utcnow()
    if limit_type == 'login':
        login_attempts[f"{username}:{ip}"].append(now)
    else:
        cert_requests[username].append(now)

def record_login_failure(username, ip):
    record_attempt(username, ip, 'login')

def clear_login_failures(username, ip):
    if f"{username}:{ip}" in login_attempts:
        del login_attempts[f"{username}:{ip}"]

# Initialize CA Backend
if CA_BACKEND == "softhsm":
    # Prepare config dict for validation
    hsm_config = {
        'EPHEMERA_PKCS11_MODULE': PKCS11_MODULE,
        'EPHEMERA_PKCS11_SLOT': PKCS11_SLOT,
        'EPHEMERA_PKCS11_PIN': PKCS11_PIN,
        'EPHEMERA_PKCS11_KEY_LABEL': PKCS11_KEY_LABEL
    }
    
    # Strict Boot Validation
    try:
        validate_softhsm_boot(hsm_config)
    except RuntimeError as e:
        print(str(e))
        # We should probably exit here if it's a fatal error, but raising RuntimeError will crash the app which is what we want.
        raise e

    print(f"Initializing SoftHSM CA Backend (Module: {PKCS11_MODULE})")
    CA = SoftHsmCA(
        module_path=PKCS11_MODULE,
        slot=PKCS11_SLOT,
        key_label=PKCS11_KEY_LABEL,
        pin=PKCS11_PIN,
    )
else:
    print("Initializing File CA Backend via KeyManager")
    # Initialize KeyManager
    key_manager = KeyManager(CA_DIR, CA_MASTER_PASSWORD, backend_type="file")
    key_manager.ensure_active_key()
    
    # Get active key path for FileCA
    active_key_path = key_manager.get_active_key_path()
    CA = FileCA(ca_key_path=active_key_path, ca_key_password=CA_MASTER_PASSWORD)

def issue_ssh_cert(username, public_key, validity_minutes, principals):
    # Create temp file for user public key
    request_id = str(uuid.uuid4()) # Temporary ID for filename, backend generates real ID? 
    # Actually backend generates ID. But we need a path.
    
    temp_pub_path = os.path.join(TEMP_DIR, f"{request_id}.pub")
    
    try:
        # Write user's public key to temp file
        with open(temp_pub_path, 'w') as f:
            f.write(public_key)
            
        # Delegate to CA backend
        # Convert minutes to seconds
        valid_seconds = validity_minutes * 60
        
        cert_content, real_request_id = CA.issue_user_cert(temp_pub_path, principals, valid_seconds)
        
        return cert_content, real_request_id
        
    finally:
        if os.path.exists(temp_pub_path):
            os.remove(temp_pub_path)
        # Backend handles its own temp files cleanup


