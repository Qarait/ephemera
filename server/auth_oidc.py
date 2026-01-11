from flask import Blueprint, url_for, session, redirect, current_app, jsonify
from authlib.integrations.flask_client import OAuth
import json
from server.config_auth import AUTH_MODE, AuthMode, OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_SCOPES
from server.core import get_users, USERS_FILE

oidc_bp = Blueprint('oidc', __name__)
oauth = OAuth()

def init_oidc(app):
    """
    Initializes the OIDC client if OIDC mode is enabled.
    """
    if AUTH_MODE != AuthMode.OIDC:
        return

    oauth.init_app(app)
    
    # Register the OIDC client
    # Authlib will automatically fetch the server metadata from the issuer URL
    # if server_metadata_url is provided.
    oauth.register(
        name='ephemera_oidc',
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{OIDC_ISSUER_URL}/.well-known/openid-configuration",
        client_kwargs={'scope': OIDC_SCOPES}
    )

@oidc_bp.route('/auth/login')
def login():
    if AUTH_MODE != AuthMode.OIDC:
        return jsonify({"error": "OIDC authentication is not enabled"}), 404
        
    redirect_uri = url_for('oidc.callback', _external=True)
    return oauth.ephemera_oidc.authorize_redirect(redirect_uri)

@oidc_bp.route('/auth/callback')
def callback():
    if AUTH_MODE != AuthMode.OIDC:
        return jsonify({"error": "OIDC authentication is not enabled"}), 404

    try:
        token = oauth.ephemera_oidc.authorize_access_token()
        user_info = token.get('userinfo')
        
        # If userinfo is not in the token, fetch it
        if not user_info:
             user_info = oauth.ephemera_oidc.userinfo()

        # Store user identity in session
        # We normalize the user structure to be consistent
        user_data = {
            'auth_mode': AuthMode.OIDC,
            'sub': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('preferred_username') or user_info.get('name'),
        }
        session['user'] = user_data
        
        # COMPATIBILITY: Ensure user exists in users.json and set session['username']
        # This allows existing WebAuthn and Cert logic to work unchanged.
        # We use 'oidc:<sub_or_email>' as the unique username.
        unique_handle = f"oidc:{user_info.get('sub')}"
        email = user_info.get('email')
        
        users = get_users()
        # Check if user exists by handle
        user = next((u for u in users if u['username'] == unique_handle), None)
        
        if not user:
            # Create new user stub for holding WebAuthn creds
            user = {
                "username": unique_handle,
                "email": email,
                "role": "developer", # Default role
                "mfa_enabled": False, # Will be enabled after they register WebAuthn
                "auth_source": "oidc",
                "oidc_sub": user_info.get('sub'),
                "is_email_verified": True # Trusted from IdP
            }
            users.append(user)
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f, indent=2)
                
        session['username'] = unique_handle
        session['auth_mode'] = AuthMode.OIDC

        # Redirect to the main dashboard
        return redirect('/')
        
    except Exception as e:
        current_app.logger.error(f"OIDC Callback Error: {e}")
        return jsonify({"error": "Authentication failed", "details": str(e)}), 500

@oidc_bp.route('/auth/logout')
def logout():
    session.pop('user', None)
    return redirect('/')
