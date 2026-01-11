import os
import json
import subprocess
import uuid
import datetime
import time
import secrets
import base64
import io
import tempfile
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth
import pyotp
import qrcode
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers import base64url_to_bytes, options_to_json
from webauthn.helpers.structs import AttestationConveyancePreference, AuthenticatorSelectionCriteria, UserVerificationRequirement

# Import Core
from .core import (
    BASE_DIR, CA_DIR, DATA_DIR, TEMP_DIR, PUBLIC_DIR,
    CA_KEY, CA_PUB, USERS_FILE, AUDIT_FILE,
    CA_MASTER_PASSWORD, ROLE_PRINCIPALS,
    get_users, get_audit_log, append_audit_log, verify_audit_chain,
    check_rate_limit, record_attempt, record_login_failure, clear_login_failures,
    derive_key_from_password, issue_ssh_cert,
    key_manager, CA, CA_MASTER_PASSWORD # Import key_manager and CA for rotation
)
from .webauthn_utils import save_challenge, get_challenge, delete_challenge
from .renewal import renewal_bp
from .config_auth import AUTH_MODE, AuthMode, validate_auth_config
from .auth_oidc import oidc_bp, init_oidc
from .policy import PolicyEngine, parse_duration
from .trust_budget import TrustBudgetLedger

app = Flask(__name__, static_folder=PUBLIC_DIR)
# Trust X-Forwarded-For headers from the Docker gateway/proxy
# x_for=1 means we trust the last proxy (nginx/docker gateway)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_secret_key')
app.register_blueprint(renewal_bp)

# Initialize Policy Engine
POLICY_FILE = os.path.join(BASE_DIR, '..', 'policy.yaml') # Assuming policy.yaml is in root
policy_engine = PolicyEngine(POLICY_FILE)

# Initialize Trust Budget Ledger (Experimental, Opt-in)
# This is a governance primitive for issuance-time accounting.
# Disabled by default unless explicitly configured in policy.
TRUST_BUDGET_DB = os.path.join(DATA_DIR, 'trust_budget.db')
trust_budget_ledger = TrustBudgetLedger(TRUST_BUDGET_DB)

# Initialize OIDC if enabled
# Initialize OIDC if enabled
validate_auth_config()
if AUTH_MODE == AuthMode.OIDC:
    init_oidc(app)
    app.register_blueprint(oidc_bp)

# --- Admin Auth ---
from functools import wraps

ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY')

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Check API Key (Machine Auth)
        if ADMIN_API_KEY:
            token = request.headers.get('X-Admin-Token')
            if token and token == ADMIN_API_KEY:
                return f(*args, **kwargs)
        
        # 2. Check Session (User Auth)
        if 'username' in session:
            users = get_users()
            user = next((u for u in users if u['username'] == session['username']), None)
            if user and (user.get('role') == 'admin' or 'admin' in user.get('roles', [])):
                return f(*args, **kwargs)
        
        return jsonify({"error": "Forbidden: Admin access required"}), 403
    return decorated_function

# --- Initialization ---
def initialize():
    # 1. Directories
    for directory in [CA_DIR, DATA_DIR, TEMP_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

    # 2. CA Key - Handled by KeyManager in core.py
    # We don't need to do anything here.

    # 3. Users File (Secure Initialization & TOTP)
    users_modified = False
    users = []
    
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                users = json.load(f)
        except (json.JSONDecodeError, IOError):
            users = []
    
    # Create admin if missing
    admin_user = next((u for u in users if u['username'] == 'admin'), None)
    if not admin_user:
        initial_password = secrets.token_urlsafe(16)
        password_hash = generate_password_hash(initial_password)
        admin_user = {
            "username": "admin", 
            "password_hash": password_hash,
            "role": "admin"
        }
        users.append(admin_user)
        users_modified = True
        
        print("\n" + "="*60)
        print("[IMPORTANT] Admin user created.")
        print(f"Username: admin")
        print(f"Password: {initial_password}")
        print("Please save this password immediately. It will not be shown again.")
        print("="*60 + "\n")
        
        with open('creds.txt', 'w') as f:
            f.write(f"Username: admin\nPassword: {initial_password}\n")

    # Generate TOTP secret if missing
    if 'totp_secret' not in admin_user:
        totp_secret = pyotp.random_base32()
        admin_user['totp_secret'] = totp_secret
        users_modified = True
        
        otp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name='admin', issuer_name='EphemeralSSH')
        
        print("\n" + "="*60)
        print("[MFA SETUP REQUIRED] TOTP Secret Generated for 'admin'")
        print(f"Secret Key: {totp_secret}")
        print(f"OTP Auth URI: {otp_uri}")
        print("(Scan this URI or manually enter the secret in Google Authenticator)")
        print("="*60 + "\n")

        with open('creds.txt', 'a') as f:
            f.write(f"TOTP Secret: {totp_secret}\nOTP URI: {otp_uri}\n")

    # Ensure admin has new fields
    if 'is_email_verified' not in admin_user:
        admin_user['is_email_verified'] = True
        admin_user['mfa_enabled'] = True
        users_modified = True

    if users_modified:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)

    # 4. Audit File (Ensure it exists)
    if not os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, 'w') as f:
            pass # Create empty file for appending
        print("Created empty audit file.")

initialize()

# --- Routes ---

# Serve Frontend
@app.route('/')
def serve_index():
    if 'username' not in session:
        return redirect('/login.html')
    return send_from_directory(PUBLIC_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(PUBLIC_DIR, path)

# Sign Up
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
        
    users = get_users()
    if any(u['username'] == username for u in users):
        return jsonify({"error": "User already exists"}), 400
        
    # Create user WITHOUT MFA
    password_hash = generate_password_hash(password)
    
    # Generate email verification token
    verification_token = str(uuid.uuid4())
    
    new_user = {
        "username": username,
        "password_hash": password_hash,
        "role": "developer",
        "is_email_verified": False,
        "mfa_enabled": False,
        "verification_token": verification_token
    }
    
    users.append(new_user)
    
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)
        
    # In a real app, send email here.
    print(f"--- EMAIL VERIFICATION ---")
    print(f"To: {username}")
    print(f"Link: http://localhost:3000/verify-email.html?token={verification_token}")
    print(f"--------------------------")
    
    return jsonify({
        "message": "Signup successful. Please check your email to verify your account.",
        "verificationLink": f"/verify-email.html?token={verification_token}" # For demo convenience
    })

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({"error": "Token required"}), 400
        
    users = get_users()
    user = next((u for u in users if u.get('verification_token') == token), None)
    
    if not user:
        return jsonify({"error": "Invalid token"}), 400
        
    user['is_email_verified'] = True
    user['verification_token'] = None # Consume token
    
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)
        
    return jsonify({"message": "Email verified successfully"})

@app.route('/api/setup-mfa/totp/generate', methods=['POST'])
def setup_mfa_totp_generate():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    username = session['username']
    # Generate secret
    totp_secret = pyotp.random_base32()
    otp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name='EphemeralSSH')
    
    # Create QR image
    img = qrcode.make(otp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    users = get_users()
    user = next((u for u in users if u['username'] == username), None)
    user['totp_secret'] = totp_secret
    
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)
    
    return jsonify({
        "secret": totp_secret,
        "qrImage": f"data:image/png;base64,{img_str}"
    })

@app.route('/api/setup-mfa/totp/verify', methods=['POST'])
def setup_mfa_totp_verify():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.get_json()
    code = data.get('code')
    username = session['username']
    
    users = get_users()
    user = next((u for u in users if u['username'] == username), None)
    
    totp_secret = user.get('totp_secret')
    if not totp_secret:
        return jsonify({"error": "Setup not initialized"}), 400
        
    totp = pyotp.TOTP(totp_secret)
    if totp.verify(code):
        user['mfa_enabled'] = True
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return jsonify({"message": "MFA Enabled"})
    else:
        return jsonify({"error": "Invalid code"}), 400

@app.route('/api/login', methods=['POST'])
def login():
    if AUTH_MODE == AuthMode.OIDC:
        return jsonify({"error": "Local login disabled. Use OIDC."}), 403

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    otp_code = data.get('otpCode')
    
    # Rate Limiting
    ip = request.remote_addr
    if not check_rate_limit(username, ip, 'login'):
        record_login_failure(username, ip)
        return jsonify({"error": "Too many login attempts. Please try again later."}), 429

    users = get_users()
    user = next((u for u in users if u['username'] == username), None)
    
    if user and check_password_hash(user['password_hash'], password):
        # 1. Check Email Verification
        if not user.get('is_email_verified', False):
             return jsonify({"error": "Email not verified"}), 403

        # 2. Check MFA Status
        if not user.get('mfa_enabled', False):
            # Pre-login session to allow MFA setup
            session['username'] = username
            return jsonify({"status": "mfa_setup_required"}), 200

        # 3. Verify MFA (TOTP)
        if otp_code:
            totp_secret = user.get('totp_secret')
            if totp_secret:
                totp = pyotp.TOTP(totp_secret)
                if totp.verify(otp_code):
                    session['username'] = username
                    record_attempt(username, ip, 'login') # Log successful attempt
                    
                    append_audit_log({
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                        "username": username,
                        "event": "login_success",
                        "method": "totp"
                    })
                    
                    return jsonify({"message": "Login successful"})
                else:
                    record_login_failure(username, ip)
                    return jsonify({"error": "Invalid MFA code"}), 401
            else:
                 return jsonify({"error": "TOTP not set up"}), 400
        else:
            return jsonify({"status": "mfa_required"}), 200
            
    else:
        record_login_failure(username, ip)
        return jsonify({"error": "Invalid credentials"}), 401
# SSO Routes (Legacy - Removed in favor of auth_oidc blueprint)
# The new OIDC routes are handled by oidc_bp registered above.

# Get Current User
@app.route('/api/me', methods=['GET'])
def me():
    if 'username' in session:
        # Evaluate policy for display
        user_context = {
            "username": session['username'],
            "email": session.get('user', {}).get('email'),
            "oidc_groups": session.get('user', {}).get('groups', []), # Assuming groups might be added later
            "auth_mode": session.get('auth_mode', 'local'),
            "ip": request.remote_addr,
            "current_time": datetime.datetime.utcnow(),
            "webauthn_id": session.get('webauthn_credential_id')
        }
        policy_result = policy_engine.evaluate(user_context)
        
        return jsonify({
            "username": session['username'],
            "auth_mode": session.get('auth_mode', 'local'),
            "email": session.get('user', {}).get('email'),
            "policy": {
                "role": policy_result['name'],
                "principals": policy_result['principals'],
                "max_duration": policy_result['max_duration']
            }
        })
    else:
        return jsonify({"error": "Unauthorized"}), 401
# Get CA Public Key
@app.route('/api/ca', methods=['GET'])
def get_ca():
    """Returns all trusted CA public keys (Active + Previous)."""
    try:
        if 'key_manager' in globals() and key_manager:
            keys = key_manager.get_all_public_keys()
            return "\n".join(keys), 200, {'Content-Type': 'text/plain'}
        else:
            # Fallback for legacy/HSM if key_manager not init
            if os.path.exists(CA_PUB):
                with open(CA_PUB, 'r') as f:
                    return f.read(), 200, {'Content-Type': 'text/plain'}
            return "CA Public Key not found", 404
    except Exception as e:
        return f"Error reading CA public keys: {e}", 500

@app.route('/api/ca/rotate', methods=['POST'])
@require_admin
def rotate_ca():
    """Rotates the CA key. Admin only."""
    # Auth handled by decorator

    try:
        if key_manager:
            success = key_manager.rotate()
            if success:
                # Re-initialize CA backend with new active key
                global CA
                active_key_path = key_manager.get_active_key_path()
                # Assuming FileCA for now as per KeyManager impl
                from server.ca.backends import FileCA
                CA = FileCA(ca_key_path=active_key_path, ca_key_password=CA_MASTER_PASSWORD)
                
                append_audit_log({
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "username": session.get('username', 'admin_api_key'),
                    "event": "ca_key_rotate",
                    "details": "Rotated CA key"
                })
                return jsonify({"message": "CA key rotated successfully"}), 200
            else:
                return jsonify({"error": "Rotation failed"}), 500
        else:
             return jsonify({"error": "Key rotation not supported (key_manager is None)"}), 501
    except Exception as e:
        return jsonify({"error": f"Rotation error: {e}"}), 500

@app.route('/api/ca/next', methods=['POST'])
@require_admin
def prepare_next_key():
    """Generates a new 'next' key for propagation. Admin only."""
    try:
        # Debug logging
        print(f"DEBUG: key_manager type: {type(key_manager)}")
        
        if key_manager:
            pub_key = key_manager.prepare_rotation()
            
            append_audit_log({
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "username": session.get('username', 'admin_api_key'),
                "event": "ca_key_prepare",
                "details": "Generated next CA key for propagation"
            })
            
            return jsonify({
                "message": "Next CA key generated successfully",
                "public_key": pub_key
            }), 200
        else:
             return jsonify({"error": "Key rotation not supported (key_manager is None)"}), 501
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Preparation error: {e}"}), 500

# Revocation Endpoints
from .revocation import revocation_manager

@app.route('/api/ca/revoke', methods=['POST'])
@require_admin
def revoke_cert():
    """Revokes a certificate by serial or username."""
    data = request.get_json()
    serial = data.get('serial')
    username = data.get('username')
    
    if not serial and not username:
        return jsonify({"error": "Must provide 'serial' or 'username'"}), 400
        
    revoked_count = 0
    
    try:
        if serial:
            revocation_manager.revoke_serial(serial)
            revoked_count += 1
            
        if username:
            # Look up serials for username in audit log
            audit_log = get_audit_log()
            for entry in audit_log:
                if entry.get('username') == username and entry.get('serial'):
                    # Check if entry is a cert issuance (has 'validityMinutes')
                    if 'validityMinutes' in entry:
                         revocation_manager.revoke_serial(entry['serial'])
                         revoked_count += 1
                         
        if revoked_count > 0:
            actor = session.get('username', 'admin_api_key')
            append_audit_log({
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "username": actor,
                "event": "cert_revocation",
                "details": f"Revoked {revoked_count} certificates for serial={serial}, username={username}"
            })
            return jsonify({"message": f"Revoked {revoked_count} certificates."}), 200
        else:
            return jsonify({"message": "No matching active certificates found to revoke."}), 404
            
    except Exception as e:
        return jsonify({"error": f"Revocation failed: {e}"}), 500

@app.route('/api/ca/krl', methods=['GET'])
def get_krl():
    """Returns the current KRL file."""
    krl_path = revocation_manager.get_krl_path()
    if os.path.exists(krl_path):
        return send_from_directory(os.path.dirname(krl_path), os.path.basename(krl_path), as_attachment=True)
    else:
        return "KRL not found", 404

# --- Ephemeral SUDO Endpoints ---
from .sudo_manager import sudo_manager

@app.route('/api/sudo/init', methods=['POST'])
def sudo_init():
    """
    Called by PAM module to initiate a sudo request.
    """
    # PAM module might not have a session. It should probably send the username it's trying to auth for.
    # And maybe a machine token? For prototype, we'll trust the input username but maybe require an API key?
    # Or just open for now (prototype).
    
    data = request.get_json()
    username = data.get('username')
    hostname = data.get('hostname')
    
    if not username:
        return jsonify({"error": "Username required"}), 400
    
    # Policy Engine Check: Is this user allowed to sudo?
    sudo_policy = policy_engine.config.get('sudo', {})
    allowed_users = sudo_policy.get('allowed_users', [])
    allowed_groups = sudo_policy.get('allowed_groups', [])
    
    # Check if user is in allowed_users or belongs to allowed_groups
    user_allowed = username in allowed_users
    
    # TODO: Check group membership via OIDC claims if available
    # For now, we allow if user is explicitly listed OR if there are no restrictions
    if not user_allowed and allowed_users:
        append_audit_log({
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "username": username,
            "event": "sudo_request_denied",
            "reason": "not_in_allowed_users",
            "hostname": hostname or "unknown"
        })
        return jsonify({"error": "User not authorized for sudo"}), 403
        
    request_id = sudo_manager.create_request(username, hostname)
    
    # Audit log: sudo request created
    append_audit_log({
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "username": username,
        "event": "sudo_request_created",
        "request_id": request_id,
        "hostname": hostname or "unknown"
    })
    
    # Generate Approval URL
    host_url = request.host_url.rstrip('/')
    approval_url = f"{host_url}/sudo_approve.html?id={request_id}"
    
    return jsonify({
        "request_id": request_id,
        "approval_url": approval_url,
        "message": "Sudo request initiated. Please approve in browser."
    })

@app.route('/api/sudo/poll', methods=['GET'])
def sudo_poll():
    """
    Called by PAM module to poll status.
    """
    request_id = request.args.get('id')
    if not request_id:
        return jsonify({"error": "Missing request_id"}), 400
        
    req = sudo_manager.get_request(request_id)
    if not req:
        return jsonify({"status": "expired"}), 404
        
    return jsonify({
        "status": req['status'],
        "username": req['username']
    })

@app.route('/api/sudo/user-state', methods=['GET'])
def sudo_user_state():
    """
    Return SUDO state for the logged-in user (pending, last_approved, last_denied).
    """
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    username = session['username']
    state = sudo_manager.get_user_sudo_state(username)
    return jsonify(state)

@app.route('/api/sudo/history', methods=['GET'])
def sudo_history():
    """
    Return SUDO history for the logged-in user.
    """
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    username = session['username']
    limit = request.args.get('limit', 20, type=int)
    history = sudo_manager.get_user_sudo_history(username, limit=limit)
    return jsonify({"history": history})

@app.route('/api/sudo/approve/options', methods=['POST'])
def sudo_approve_options():
    """
    Step 1: Generate WebAuthn options for SUDO approval.
    """
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    username = session['username']
    users = get_users()
    user = next((u for u in users if u['username'] == username), None)
    
    if not user or 'webauthn_credentials' not in user or not user['webauthn_credentials']:
        return jsonify({"error": "No WebAuthn credentials found. Please register a key first."}), 400
        
    allow_credentials = []
    for cred in user['webauthn_credentials']:
        allow_credentials.append(base64url_to_bytes(cred['credential_id']))
        
    options = generate_authentication_options(
        rp_id=request.host.split(":")[0],
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    
    save_challenge(username, options.challenge)
    return options_to_json(options)

@app.route('/api/sudo/approve/verify', methods=['POST'])
def sudo_approve_verify():
    """
    Step 2: Verify WebAuthn assertion and approve SUDO request.
    """
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    username = session['username']
    data = request.get_json()
    request_id = data.get('request_id')
    assertion_response = data.get('assertion')
    
    if not request_id or not assertion_response:
        return jsonify({"error": "Missing request_id or assertion"}), 400

    # 1. Verify WebAuthn Assertion
    raw_id = assertion_response.get('id')
    if not raw_id:
        return jsonify({"error": "Missing credential ID"}), 400

    users = get_users()
    target_user = next((u for u in users if u['username'] == username), None)
    if not target_user:
        return jsonify({"error": "User not found"}), 404
        
    target_cred = None
    if 'webauthn_credentials' in target_user:
        for c in target_user['webauthn_credentials']:
            # Handle potential padding differences
            if c['credential_id'] == raw_id or c['credential_id'] == raw_id + '=' or c['credential_id'] == raw_id + '==':
                target_cred = c
                break
    
    if not target_cred:
        return jsonify({"error": "Credential not found"}), 400
        
    challenge = get_challenge(username)
    if not challenge:
        return jsonify({"error": "No pending challenge"}), 400

    try:
        verification = verify_authentication_response(
            credential=assertion_response,
            expected_challenge=challenge,
            expected_origin=request.host_url.rstrip('/'),
            expected_rp_id=request.host.split(":")[0],
            credential_public_key=base64url_to_bytes(target_cred['public_key']),
            credential_current_sign_count=target_cred['sign_count'],
        )
        
        # Update sign count
        target_cred['sign_count'] = verification.new_sign_count
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
            
        delete_challenge(username)
        
        # 2. Approve SUDO Request
        success = sudo_manager.approve_request(request_id, username)
        
        if success:
            append_audit_log({
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "username": username,
                "event": "sudo_approval",
                "method": "webauthn",
                "details": f"Approved sudo for request {request_id}"
            })
            return jsonify({"message": "Sudo request approved"}), 200
        else:
            return jsonify({"error": "Approval failed (mismatch or expired)"}), 400
            
    except Exception as e:
        return jsonify({"error": f"Verification failed: {str(e)}"}), 400

# Get Audit Logs
@app.route('/api/audit', methods=['GET'])
def get_audit():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_audit_log())

@app.route('/api/audit/verify', methods=['POST'])
def verify_audit():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    result = verify_audit_chain()
    return jsonify(result)

# Request Certificate
@app.route('/api/cert', methods=['POST'])
def request_cert():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    username = session['username']
    
    # Rate Limiting for Cert Requests
    if not check_rate_limit(username, None, 'cert_request'):
        return jsonify({"error": "Too many certificate requests"}), 429
    
    record_attempt(username, None, 'cert_request')

    data = request.get_json()
    public_key = data.get('publicKey')
    validity_minutes = data.get('validityMinutes')

    if not public_key or not validity_minutes:
        return jsonify({"error": "Missing publicKey or validityMinutes"}), 400
    
    try:
        validity_minutes = int(validity_minutes)
        if validity_minutes not in [5, 15, 60]:
            raise ValueError
    except ValueError:
        return jsonify({"error": "Invalid validity period"}), 400

    try:
        # Determine principals and duration via Policy Engine
        users = get_users()
        user_obj = next((u for u in users if u['username'] == username), None)
        
        # Construct context
        user_context = {
            "username": username,
            "email": user_obj.get('email') if user_obj else None,
            "oidc_groups": session.get('user', {}).get('groups', []), # Future proofing
            "auth_mode": session.get('auth_mode', 'local'),
            "ip": request.remote_addr,
            "current_time": datetime.datetime.utcnow(),
            "webauthn_id": session.get('webauthn_credential_id')
        }
        
        policy_result = policy_engine.evaluate(user_context)
        principals = policy_result['principals']
        max_duration_minutes = parse_duration(policy_result['max_duration'])
        
        # Log Policy Match
        append_audit_log({
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event": "policy_match",
            "username": username,
            "rule": policy_result['name'],
            "principals": principals,
            "ttl_minutes": max_duration_minutes
        })
        
        # Enforce policy max duration
        if validity_minutes > max_duration_minutes:
            return jsonify({
                "error": f"Requested duration ({validity_minutes}m) exceeds policy limit ({max_duration_minutes}m) for role '{policy_result['name']}'"
            }), 403
        
        # Trust Budget Check (Experimental, Opt-in)
        # Only applied if the matched policy explicitly defines a trust_budget.
        trust_budget_receipt = None
        if 'trust_budget' in policy_result:
            tb_config = policy_result['trust_budget']
            budget_id = tb_config.get('budget_id', f"user:{username}")
            cost = tb_config.get('cost', 1)
            initial_balance = tb_config.get('initial_balance', 100)
            reset_hours = tb_config.get('reset_interval_hours')
            
            # Ensure budget exists
            trust_budget_ledger.get_or_create_budget(budget_id, initial_balance, reset_hours)
            
            # Check and deduct
            success, remaining, error_msg = trust_budget_ledger.check_and_deduct(
                budget_id, cost, username, request_id=None  # request_id assigned after issuance
            )
            
            if not success:
                append_audit_log({
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "event": "trust_budget_exhausted",
                    "username": username,
                    "budget_id": budget_id,
                    "cost": cost,
                    "remaining": remaining
                })
                return jsonify({"error": error_msg}), 403
            
            trust_budget_receipt = {
                "budget_id": budget_id,
                "cost": cost,
                "remaining": remaining,
                "experimental": True,
                "disclaimer": "Experimental. Opt-in. Governance primitive. May change or be removed."
            }
            
        cert_content, request_id = issue_ssh_cert(username, public_key, validity_minutes, principals)

        # Log to audit
        issued_at = datetime.datetime.utcnow()
        expires_at = issued_at + datetime.timedelta(minutes=validity_minutes)
        
        entry = {
            "id": request_id,
            "username": username,
            "principals": principals,
            "validityMinutes": validity_minutes,
            "issuedAt": issued_at.isoformat() + "Z",
            "expiresAt": expires_at.isoformat() + "Z",
            "serial": request_id
        }
        append_audit_log(entry)

        response_data = {"certificate": cert_content}
        if trust_budget_receipt:
            response_data["trust_budget"] = trust_budget_receipt
        
        return jsonify(response_data)

    except Exception as e:
        print(f"Cert generation error: {e}")
        return jsonify({"error": f"Failed to generate certificate: {str(e)}"}), 500

# --- WebAuthn Endpoints ---

@app.route('/api/webauthn/register/options', methods=['POST'])
def webauthn_register_options():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    username = session['username']
    users = get_users()
    user = next((u for u in users if u['username'] == username), None)
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Generate options
    options = generate_registration_options(
        rp_id=request.host.split(":")[0],
        rp_name="Ephemeral SSH",
        user_id=base64url_to_bytes(base64.urlsafe_b64encode(username.encode()).decode()),
        user_name=username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED
        ),
    )
    
    # Store challenge
    save_challenge(username, options.challenge)
    
    return options_to_json(options)

@app.route('/api/webauthn/register/verify', methods=['POST'])
def webauthn_register_verify():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    username = session['username']
    challenge = get_challenge(username)
    
    if not challenge:
        return jsonify({"error": "No pending challenge"}), 400
        
    try:
        data = request.get_json()
        verification = verify_registration_response(
            credential=data,
            expected_challenge=challenge,
            expected_origin=request.host_url.rstrip('/'), # e.g. http://localhost:3000
            expected_rp_id=request.host.split(":")[0],
        )
        
        # Save credential
        users = get_users()
        user_idx = next((i for i, u in enumerate(users) if u['username'] == username), -1)
        
        if user_idx == -1:
             return jsonify({"error": "User not found"}), 404
             
        if 'webauthn_credentials' not in users[user_idx]:
            users[user_idx]['webauthn_credentials'] = []
            
        users[user_idx]['webauthn_credentials'].append({
            "credential_id": base64.urlsafe_b64encode(verification.credential_id).decode().rstrip('='),
            "public_key": base64.urlsafe_b64encode(verification.credential_public_key).decode().rstrip('='),
            "sign_count": verification.sign_count,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z"
        })
        
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
            
        delete_challenge(username)
        return jsonify({"verified": True})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/webauthn/login/options', methods=['POST'])
def webauthn_login_options():
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Username required"}), 400
        
    users = get_users()
    user = next((u for u in users if u['username'] == username), None)
    
    if not user or 'webauthn_credentials' not in user or not user['webauthn_credentials']:
        return jsonify({"error": "No WebAuthn credentials found for this user"}), 400
        
    # Generate options
    allow_credentials = []
    for cred in user['webauthn_credentials']:
        allow_credentials.append(base64url_to_bytes(cred['credential_id']))
        
    options = generate_authentication_options(
        rp_id=request.host.split(":")[0],
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    
    save_challenge(username, options.challenge)
    return options_to_json(options)

@app.route('/api/webauthn/login/verify', methods=['POST'])
def webauthn_login_verify():
    data = request.get_json()
    
    raw_id = data.get('id')
    if not raw_id:
        return jsonify({"error": "Missing credential ID"}), 400

    users = get_users()
    target_user = None
    target_cred = None
    
    for u in users:
        if 'webauthn_credentials' in u:
            for c in u['webauthn_credentials']:
                # Credential ID in JSON is base64url encoded
                # We need to handle padding potentially if stored without it
                if c['credential_id'] == raw_id or c['credential_id'] == raw_id + '=' or c['credential_id'] == raw_id + '==':
                    target_user = u
                    target_cred = c
                    break
        if target_user:
            break
            
    if not target_user:
        return jsonify({"error": "Credential not found"}), 400
        
    username = target_user['username']
    challenge = get_challenge(username)
    
    if not challenge:
        return jsonify({"error": "No pending challenge for user"}), 400

    try:
        verification = verify_authentication_response(
            credential=data,
            expected_challenge=challenge,
            expected_origin=request.host_url.rstrip('/'),
            expected_rp_id=request.host.split(":")[0],
            credential_public_key=base64url_to_bytes(target_cred['public_key']),
            credential_current_sign_count=target_cred['sign_count'],
        )
        
        # Update sign count
        target_cred['sign_count'] = verification.new_sign_count
        
        # Save user
        user_idx = next((i for i, u in enumerate(users) if u['username'] == username), -1)
        users[user_idx] = target_user 
        
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
            
        # Login
        session['username'] = username
        session['webauthn'] = True
        # Store credential ID for policy checks
        session['webauthn_credential_id'] = target_cred['credential_id']
        delete_challenge(username)
        
        append_audit_log({
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "username": username,
            "provider": "webauthn",
            "event": "webauthn_login"
        })
        
        return jsonify({"verified": True})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# --- Policy Management Endpoints ---

@app.route('/api/policy/reload', methods=['POST'])
@require_admin
def policy_reload():
    # Auth handled by decorator
        
    policy_engine.reload()
    return jsonify({"message": "Policy reloaded"})

@app.route('/api/policy/dryrun', methods=['POST'])
@require_admin
def policy_dryrun():
    # Auth handled by decorator
        
    data = request.get_json()
    # Allow overriding context for testing
    context = {
        "username": data.get("username", "test_user"),
        "email": data.get("email"),
        "oidc_groups": data.get("oidc_groups", []),
        "auth_mode": data.get("auth_mode", "local"),
        "ip": data.get("ip", "127.0.0.1"),
        "webauthn_id": data.get("webauthn_id")
    }
    
    # Handle time override if provided
    if "current_time" in data:
        try:
            context["current_time"] = datetime.datetime.fromisoformat(data["current_time"])
        except ValueError:
            pass
            
    result = policy_engine.evaluate(context)
    return jsonify(result)

if __name__ == '__main__':
    print("DEBUG: Registered sudo routes:")
    for rule in app.url_map.iter_rules():
        if 'sudo' in rule.rule:
            print(f"  {rule.rule} -> {rule.endpoint}")
    app.run(port=3000, host='0.0.0.0')
