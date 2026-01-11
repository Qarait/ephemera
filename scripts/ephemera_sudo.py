#!/usr/bin/env python3
"""
Ephemera SUDO Authentication Script
Called by pam_exec to handle WebAuthn-based sudo approval.

Usage: pam_exec.so /usr/local/bin/ephemera_sudo.py
"""
import os
import sys
import time
import requests

EPHEMERA_SERVER = os.environ.get('EPHEMERA_SERVER', 'http://ephemera:3000')
POLL_INTERVAL = 2
TIMEOUT = 60  # seconds

# Security: Enforce HTTPS or localhost-only connections
# Prevents credentials from being sent in plaintext over the network
def _validate_server_url(url):
    """Ensure server URL uses HTTPS or is localhost (for dev)."""
    if url.startswith('https://'):
        return True
    if url.startswith('http://localhost') or url.startswith('http://127.0.0.1'):
        return True
    if url.startswith('http://ephemera:'):
        # Allow Docker internal network (ephemera service name)
        return True
    return False

if not _validate_server_url(EPHEMERA_SERVER):
    print("[Ephemera] SECURITY ERROR: EPHEMERA_SERVER must use HTTPS or localhost", file=sys.stderr)
    print("[Ephemera] Refusing to send credentials over insecure connection", file=sys.stderr)
    sys.exit(1)


def main():
    # PAM passes username via PAM_USER environment variable
    username = os.environ.get('PAM_USER')
    hostname = os.environ.get('HOSTNAME', 'unknown')
    
    if not username:
        print("[Ephemera] Error: No PAM_USER set", file=sys.stderr)
        sys.exit(1)
    
    # 1. Initiate SUDO request
    try:
        res = requests.post(f"{EPHEMERA_SERVER}/api/sudo/init", json={
            "username": username,
            "hostname": hostname
        }, timeout=10)
        
        if res.status_code != 200:
            print(f"[Ephemera] Error: {res.text}", file=sys.stderr)
            sys.exit(1)
            
        data = res.json()
        request_id = data['request_id']
        approval_url = data['approval_url']
        
    except requests.RequestException as e:
        print(f"[Ephemera] Server unreachable: {e}", file=sys.stderr)
        sys.exit(1)
    
    # 2. Display approval URL
    print("\n[Ephemera] SUDO Request Initiated")
    print(f"[Ephemera] Request ID: {request_id}")
    print(f"[Ephemera] Approve at: {approval_url}")
    print("[Ephemera] Waiting for WebAuthn approval...")
    
    # 3. Poll for approval
    elapsed = 0
    while elapsed < TIMEOUT:
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
        
        try:
            res = requests.get(f"{EPHEMERA_SERVER}/api/sudo/poll", params={"id": request_id}, timeout=5)
            
            if res.status_code == 200:
                status = res.json().get('status')
                if status == 'approved':
                    print("[Ephemera] Access GRANTED.")
                    sys.exit(0)  # PAM_SUCCESS
                elif status == 'denied':
                    print("[Ephemera] Access DENIED.", file=sys.stderr)
                    sys.exit(1)  # PAM_AUTH_ERR
            elif res.status_code == 404:
                print("[Ephemera] Request expired.", file=sys.stderr)
                sys.exit(1)
                
        except requests.RequestException:
            pass  # Retry on network error
    
    # Timeout
    print("[Ephemera] Approval timed out.", file=sys.stderr)
    sys.exit(1)

if __name__ == '__main__':
    main()
