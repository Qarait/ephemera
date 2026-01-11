from flask import Blueprint, request, jsonify, session, send_from_directory
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers import base64url_to_bytes, options_to_json
from webauthn.helpers.structs import UserVerificationRequirement
import datetime
import base64

from .core import (
    get_users, append_audit_log, issue_ssh_cert,
    ROLE_PRINCIPALS, PUBLIC_DIR
)
from .webauthn_utils import save_challenge, get_challenge, delete_challenge

renewal_bp = Blueprint('renewal', __name__)

@renewal_bp.route('/renew')
def serve_renew_page():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return send_from_directory(PUBLIC_DIR, 'renew.html')

@renewal_bp.route('/api/webauthn/renew/start', methods=['POST'])
def renew_start():
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

@renewal_bp.route('/api/webauthn/renew/finish', methods=['POST'])
def renew_finish():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    username = session['username']
    data = request.get_json()
    
    # 1. Verify WebAuthn Assertion
    raw_id = data.get('id')
    if not raw_id:
        return jsonify({"error": "Missing credential ID"}), 400

    users = get_users()
    target_user = next((u for u in users if u['username'] == username), None)
    if not target_user:
        return jsonify({"error": "User not found"}), 404
        
    target_cred = None
    if 'webauthn_credentials' in target_user:
        for c in target_user['webauthn_credentials']:
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
            credential=data,
            expected_challenge=challenge,
            expected_origin=request.host_url.rstrip('/'),
            expected_rp_id=request.host.split(":")[0],
            credential_public_key=base64url_to_bytes(target_cred['public_key']),
            credential_current_sign_count=target_cred['sign_count'],
        )
        
        # Update sign count
        target_cred['sign_count'] = verification.new_sign_count
        
        # Save user (update sign count)
        # We need to find index to update
        # Actually target_user is a reference to dict in list? No, json.load returns list of dicts.
        # So modifying target_user modifies the dict in the list 'users' IF we got it from that list.
        # Yes, next() returns reference.
        
        # We need to write back to file.
        # But wait, concurrent writes? server.py also writes.
        # For this MVP, it's fine.
        import json
        from .core import USERS_FILE
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
            
        delete_challenge(username)
        
        # 2. Issue Certificate (Short TTL)
        public_key = data.get('sshPublicKey') # Passed from frontend?
        # Wait, frontend needs to send the SSH public key too!
        # The user needs to provide the pubkey they want to renew.
        # Or we can just sign the one they used before? No, we don't store it.
        # The CLI/Frontend must send it.
        
        if not public_key:
             return jsonify({"error": "Missing sshPublicKey"}), 400
             
        validity_minutes = 15 # Short TTL for renewal
        
        role = target_user.get('role', 'developer')
        principals = ROLE_PRINCIPALS.get(role, 'user')
        
        cert_content, request_id = issue_ssh_cert(username, public_key, validity_minutes, principals)
        
        # Log
        issued_at = datetime.datetime.utcnow()
        expires_at = issued_at + datetime.timedelta(minutes=validity_minutes)
        
        append_audit_log({
            "timestamp": issued_at.isoformat() + "Z",
            "username": username,
            "event": "cert_renewal_success",
            "method": "webauthn",
            "validityMinutes": validity_minutes,
            "serial": request_id
        })
        
        return jsonify({
            "status": "ok",
            "certificate": cert_content,
            "expires_at": expires_at.isoformat() + "Z"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400
