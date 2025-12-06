import os
import sys

class AuthMode:
    LOCAL = "local"
    OIDC = "oidc"

# Default to local mode for backward compatibility
AUTH_MODE = os.environ.get("EPHEMERA_AUTH_MODE", AuthMode.LOCAL).lower()

# OIDC Configuration
OIDC_ISSUER_URL = os.environ.get("OIDC_ISSUER_URL")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI") # e.g., http://localhost:3000/auth/callback
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid email profile")

def validate_auth_config():
    """
    Validates that the necessary configuration is present for the selected AUTH_MODE.
    Exits the application if configuration is invalid.
    """
    if AUTH_MODE == AuthMode.OIDC:
        missing = []
        if not OIDC_ISSUER_URL: missing.append("OIDC_ISSUER_URL")
        if not OIDC_CLIENT_ID: missing.append("OIDC_CLIENT_ID")
        if not OIDC_CLIENT_SECRET: missing.append("OIDC_CLIENT_SECRET")
        
        if missing:
            print(f"CRITICAL: AUTH_MODE is set to 'oidc', but the following environment variables are missing: {', '.join(missing)}")
            sys.exit(1)
        print(f"Auth Config: OIDC Mode enabled (Issuer: {OIDC_ISSUER_URL})")
    else:
        print("Auth Config: Local Mode enabled")
