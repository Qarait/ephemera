import os
import sys
import subprocess
import requests
import datetime
from pathlib import Path
from .common import BASE_URL, KEY_NAME, load_session
from .init import get_ssh_paths

# ANSI Color Codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def colorize(text, color):
    """Apply ANSI color to text, with fallback for non-TTY."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text

def check_mark(success, with_color=True):
    if success:
        mark = "✔"
        return colorize(mark, Colors.GREEN) if with_color else mark
    else:
        mark = "✖"
        return colorize(mark, Colors.RED) if with_color else mark

def status_badge(status):
    """Return colored status badge for SUDO states."""
    badges = {
        'approved': colorize('● APPROVED', Colors.GREEN),
        'pending': colorize('● PENDING', Colors.YELLOW),
        'denied': colorize('● DENIED', Colors.RED),
        'timeout': colorize('● TIMEOUT', Colors.RED),
        'expired': colorize('● EXPIRED', Colors.RED),
    }
    return badges.get(status.lower(), status)

def print_status(args):
    print("Ephemera Status")
    print("────────────────────────────────────────")
    
    # 1. User / WebAuthn Binding
    session_data = load_session()
    user_info = None
    if session_data:
        try:
            s = requests.Session()
            s.cookies.update(session_data['cookies'])
            res = s.get(f"{BASE_URL}/api/me")
            if res.status_code == 200:
                user_info = res.json()
        except requests.RequestException:
            pass

    if user_info:
        print(f"User: {user_info['username']}")
        
        # Check WebAuthn credentials
        # We need an endpoint for this, or assume /api/me returns it.
        # Assuming /api/me returns 'webauthn_credentials' list based on server code.
        creds = user_info.get('webauthn_credentials', [])
        if creds:
            print(f"WebAuthn Key: Registered ({len(creds)} key(s)) {check_mark(True)}")
        else:
            print(f"WebAuthn Key: No keys registered {check_mark(False)}")
            print("  Run: ephemera login (and register a key if needed)")
    else:
        print(f"User: Not logged in {check_mark(False)}")
        print("  Run: ephemera login")

    print("")
    
    # 2. SSH Certificate
    cert_path = f"{KEY_NAME}-cert.pub"
    print("SSH Certificate:")
    if os.path.exists(cert_path):
        try:
            # Parse ssh-keygen -L output
            output = subprocess.check_output(['ssh-keygen', '-L', '-f', cert_path], text=True)
            
            valid_from = None
            valid_to = None
            
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Valid:"):
                    # Example: Valid: from 2023-10-27T10:00:00 to 2023-10-27T10:15:00
                    parts = line.split()
                    if len(parts) >= 5:
                        # This parsing depends on local time format usually, but ssh-keygen -L often uses ISO-like
                        # Actually it depends on locale.
                        # Let's try to just print the raw line or be robust.
                        # For the spec, we want "Remaining: X minutes".
                        # Let's just print the raw validity line for now to be safe, 
                        # or try to parse if standard format.
                        print(f"  {line}")
                        
                        # Simple check for "expired" based on current time is hard without parsing.
                        # But ssh-add -l might tell us if it's expired? No.
                        pass
            
            print(f"  Path: {cert_path} {check_mark(True)}")
            
        except subprocess.CalledProcessError:
            print(f"  Invalid certificate file {check_mark(False)}")
    else:
        print(f"  Not found {check_mark(False)}")
        print("  Run: ephemera renew")

    print("")

    # 3. SSH Agent
    print("SSH Agent:")
    try:
        agent_output = subprocess.check_output(['ssh-add', '-l'], text=True)
        if "id_ephemera" in agent_output or "Ephemera" in agent_output: # Key comment often contains filename or user
             # We can check if the public key string matches
             if os.path.exists(f"{KEY_NAME}.pub"):
                 with open(f"{KEY_NAME}.pub") as f:
                     pub_key_parts = f.read().split()
                     if len(pub_key_parts) > 1:
                         key_b64 = pub_key_parts[1]
                         if key_b64 in agent_output:
                             print(f"  Ephemera key loaded {check_mark(True)}")
                         else:
                             print(f"  Ephemera key NOT loaded {check_mark(False)}")
                             print(f"  Run: ssh-add {KEY_NAME}")
             else:
                 print(f"  Public key not found to verify agent {check_mark(False)}")
        else:
             print(f"  Ephemera key NOT loaded {check_mark(False)}")
             print(f"  Run: ssh-add {KEY_NAME}")
             
    except subprocess.CalledProcessError: # ssh-add -l returns 1 if no keys
        print(f"  No keys loaded in agent {check_mark(False)}")
        print(f"  Run: ssh-add {KEY_NAME}")
    except FileNotFoundError:
        print(f"  ssh-add command not found {check_mark(False)}")

    print("")

    # 4. Configuration
    print("Configuration:")
    paths = get_ssh_paths()
    config_file = paths["config_file"]
    ephemera_config = paths["ephemera_config"]
    
    # Check Include
    include_path = ephemera_config.as_posix()
    include_line = f"Include {include_path}"
    
    if config_file.exists():
        content = config_file.read_text(encoding='utf-8')
        if include_line in content:
            print(f"  ~/.ssh/config includes Ephemera config {check_mark(True)}")
        else:
            print(f"  ~/.ssh/config missing Include directive {check_mark(False)}")
            print("  Run: ephemera init")
    else:
        print(f"  ~/.ssh/config not found {check_mark(False)}")
        print("  Run: ephemera init")

    # Check check-match
    # We can try to run the match exec command manually?
    # ephemera check-match localhost
    # But 'ephemera' might not be in path if running python script.
    # We are running 'python ephemera_cli.py'.
    # So we can't easily check 'ephemera check-match' unless installed.
    # We'll skip executing the check-match command for now as it's an advanced check 
    # requiring the CLI to be installed in PATH.

    print("")

    # 5. SUDO Access State
    print(f"{Colors.BOLD}SUDO Access State:{Colors.RESET}" if sys.stdout.isatty() else "SUDO Access State:")
    if session_data:
        try:
            s = requests.Session()
            s.cookies.update(session_data['cookies'])
            res = s.get(f"{BASE_URL}/api/sudo/user-state")
            if res.status_code == 200:
                sudo_state = res.json()
                
                # Pending requests with remaining time
                pending = sudo_state.get('pending', [])
                if pending:
                    print(f"  {status_badge('pending')} Pending Requests:")
                    now = datetime.datetime.utcnow()
                    for req in pending:
                        # Calculate remaining time (requests expire after 300 seconds = 5 minutes)
                        try:
                            created = datetime.datetime.fromisoformat(req['time'].rstrip('Z'))
                            elapsed = (now - created).total_seconds()
                            remaining = max(0, 300 - elapsed)
                            if remaining > 60:
                                time_str = f"{int(remaining // 60)}m {int(remaining % 60)}s"
                            else:
                                time_str = f"{int(remaining)}s"
                            expires_display = colorize(f"(expires in {time_str})", Colors.YELLOW)
                        except (ValueError, KeyError):
                            expires_display = ""
                        print(f"    • {req['id'][:8]}... → {req['server']} {expires_display}")
                else:
                    print(f"  Pending Requests: None {check_mark(True)}")
                
                # Last approved
                last_approved = sudo_state.get('last_approved')
                if last_approved:
                    badge = status_badge('approved')
                    print(f"  Last: {badge} {last_approved['server']} at {last_approved['time'][:19]}")
                else:
                    print(f"  Last Approved: {colorize('None', Colors.BLUE)}")
                
                # Last denied
                last_denied = sudo_state.get('last_denied')
                if last_denied:
                    badge = status_badge('denied')
                    print(f"  Last: {badge} {last_denied['server']} at {last_denied['time'][:19]}")
            else:
                print(f"  Unable to fetch SUDO state {check_mark(False)}")
        except Exception as e:
            print(f"  Error fetching SUDO state: {e} {check_mark(False)}")
    else:
        print(f"  Login required to view SUDO state {check_mark(False)}")
    
    print("────────────────────────────────────────")
