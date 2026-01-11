#!/usr/bin/env python3
__version__ = "3.0.0"
import argparse
import requests
import json
import os
import subprocess
import sys
import getpass
import webbrowser
from cli.common import BASE_URL, CONFIG_DIR, SESSION_FILE, KEY_NAME, ensure_config_dir, save_session, load_session
from cli.server_setup import generate_setup_script
from pathlib import Path
from server.backup_manager import create_backup, restore_backup

# Assuming API_URL is the same as BASE_URL for this context
API_URL = BASE_URL

def handle_backup_create(args):
    """Creates encrypted backup."""
    print("Creating encrypted backup...")
    print(f"Configuration: K={args.k}, N={args.n}")
    
    try:
        enc_path, shards = create_backup(Path(args.out_dir), args.k, args.n)
        print(f"Success! Backup created at: {enc_path}")
        print(f"Password split into {len(shards)} shards.")
        print("Store these shards securely in separate locations.")
    except Exception as e:
        print(f"Error creating backup: {e}")
        sys.exit(1)

def handle_backup_restore(args):
    """Restores from encrypted backup."""
    print("Restoring from backup...")
    
    try:
        restore_backup(Path(args.backup), [Path(p) for p in args.shards], Path(args.out_dir))
        print(f"Success! Files restored to: {args.out_dir}")
    except Exception as e:
        print(f"Error restoring backup: {e}")
        sys.exit(1)

def ensure_logged_in():
    """Helper to check if a session exists."""
    if not load_session():
        print("Not logged in. Run 'ephemera login' first.")
        sys.exit(1)

def load_config():
    """Loads configuration, primarily for the base URL."""
    # For this CLI, the base URL is a constant, but in a more complex
    # setup, it might be loaded from a config file or session.
    # We'll return a dict that mimics a config object.
    return {"url": BASE_URL}

def login(args):
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    otp = input("TOTP Code: ")
    
    s = requests.Session()
    try:
        res = s.post(f"{BASE_URL}/api/login", json={
            "username": username,
            "password": password,
            "otpCode": otp
        })
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to server.")
        return

    if res.status_code == 200:
        print("Login successful!")
        save_session(username, s.cookies.get_dict())
    else:
        print(f"Login failed: {res.text}")

def get_cert(args):
    session_data = load_session()
    if not session_data:
        print("Not logged in. Run 'ephemera login' first.")
        return

    ensure_config_dir()
    
    # Generate key if not exists
    if not os.path.exists(KEY_NAME):
        print("Generating SSH key pair...")
        subprocess.check_call(['ssh-keygen', '-t', 'ed25519', '-f', KEY_NAME, '-N', ''])
    
    with open(f"{KEY_NAME}.pub", 'r') as f:
        pub_key = f.read().strip()
        
    print("Requesting certificate...")
    s = requests.Session()
    s.cookies.update(session_data['cookies'])
    
    res = s.post(f"{BASE_URL}/api/cert", json={
        "publicKey": pub_key,
        "validityMinutes": 5
    })
    
    if res.status_code == 200:
        response_data = res.json()
        cert = response_data.get('certificate')
        with open(f"{KEY_NAME}-cert.pub", 'w') as f:
            f.write(cert)
        print(f"Certificate saved to {KEY_NAME}-cert.pub")
        
        # Inspect cert to show principals
        print("\nCertificate Details:")
        subprocess.call(['ssh-keygen', '-L', '-f', f"{KEY_NAME}-cert.pub"])
        
        # Trust Budget Receipt (Experimental, Opt-in)
        if 'trust_budget' in response_data:
            tb = response_data['trust_budget']
            print("\n--- Trust Budget Receipt ---")
            print(f"Budget ID: {tb.get('budget_id')}")
            print(f"Cost: {tb.get('cost')} points")
            print(f"Remaining: {tb.get('remaining')} points")
            print(f"[{tb.get('disclaimer')}]")
            print("----------------------------")
    else:
        print(f"Certificate request failed: {res.text}")

def ssh_connect(args):
    if not os.path.exists(KEY_NAME) or not os.path.exists(f"{KEY_NAME}-cert.pub"):
        print("No certificate found. Run 'ephemera cert' first.")
        return
        
    target = args.target
    # Parse user@host:port
    user = "user" # Default
    port = "22"
    host = target
    
    if '@' in target:
        user, host = target.split('@')
    
    # For this demo, we know the port is 2222 on localhost
    if host == "localhost" or host == "127.0.0.1":
        port = "2222"
        
    cmd = [
        'ssh',
        '-p', port,
        '-i', KEY_NAME,
        '-o', f'CertificateFile={KEY_NAME}-cert.pub',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=nul', # Windows specific
        f'{user}@{host}'
    ]
    
    print(f"Connecting to {user}@{host}:{port}...")
    subprocess.call(cmd)

def renew(args):
    print("Opening browser for WebAuthn renewal...")
    print(f"Please complete the renewal process at: {BASE_URL}/renew")
    webbrowser.open(f"{BASE_URL}/renew")

def dryrun_policy(args):
    """Test policy evaluation for a user context."""
    ensure_logged_in()
    
    payload = {
        "username": args.username,
        "email": args.email,
        "ip": args.ip,
        "current_time": args.time
    }
    
    session_data = load_session()
    if not session_data:
        print("Not logged in. Run 'ephemera login' first.")
        return

    s = requests.Session()
    s.cookies.update(session_data['cookies'])

    try:
        response = s.post(f"{API_URL}/api/policy/dryrun", json=payload)
        if response.status_code == 200:
            result = response.json()
            print(f"Policy Match: {result['name']}")
            print(f"Principals: {', '.join(result['principals'])}")
            print(f"Max Duration: {result['max_duration']}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Connection failed: {e}")

def reload_policy(args):
    """Reload the server policy file."""
    ensure_logged_in()

    session_data = load_session()
    if not session_data:
        print("Not logged in. Run 'ephemera login' first.")
        return

    s = requests.Session()
    s.cookies.update(session_data['cookies'])

    try:
        response = s.post(f"{API_URL}/api/policy/reload")
        if response.status_code == 200:
            print("Policy reloaded successfully.")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Connection failed: {e}")

def handle_server_setup(args):
    """Fetches CA key and generates bootstrap script."""
    config = load_config()
    if not config:
        print("Error: Not authenticated. Run 'ephemera login' first.")
        return

    url = config.get('url')
    
    try:
        print(f"Fetching CA Public Key from {url}...")
        response = requests.get(f"{url}/api/ca")
        if response.status_code == 200:
            ca_pub_key = response.text.strip()
            script = generate_setup_script(ca_pub_key)
            
            if args.out:
                with open(args.out, 'w') as f:
                    f.write(script)
                print(f"Bootstrap script saved to {args.out}")
                print("Run it on your server with: sudo bash " + args.out)
            else:
                print(script)
        else:
            print(f"Error fetching CA key: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error: {e}")

def handle_rotate_ca(args):
    """Rotates the CA key."""
    ensure_logged_in()
    
    print("WARNING: You are about to rotate the CA key.")
    print("The current active key will become 'previous' (verify-only).")
    print("A new key will be generated and become 'active' (signing).")
    print("All existing certificates will remain valid until they expire.")
    
    confirm = input("Are you sure you want to proceed? [y/N]: ")
    if confirm.lower() != 'y':
        print("Aborted.")
        return

    session_data = load_session()
    s = requests.Session()
    s.cookies.update(session_data['cookies'])
    
    try:
        response = s.post(f"{API_URL}/api/ca/rotate")
        if response.status_code == 200:
            print("Success: CA key rotated.")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Connection failed: {e}")

def handle_revoke(args):
    """Revokes a certificate."""
    ensure_logged_in()
    
    identifier = args.identifier
    print(f"Revoking certificates for: {identifier}")
    
    confirm = input("Are you sure? This action cannot be undone. [y/N]: ")
    if confirm.lower() != 'y':
        print("Aborted.")
        return

    session_data = load_session()
    s = requests.Session()
    s.cookies.update(session_data['cookies'])
    
    # Determine if identifier is serial or username
    # Simple heuristic: serials are usually UUIDs (long, dashes) or integers. Usernames are shorter.
    # But let's just try sending both or let server decide?
    # Server expects 'serial' or 'username'.
    
    payload = {}
    # UUID check or just assume username if not UUID-like?
    # Let's just send it as 'username' if it looks like a username, 'serial' otherwise?
    # Or try both? No, that might be ambiguous.
    # Let's assume username unless it looks like a UUID.
    import uuid
    try:
        uuid.UUID(identifier)
        payload['serial'] = identifier
    except ValueError:
        payload['username'] = identifier

    try:
        response = s.post(f"{API_URL}/api/ca/revoke", json=payload)
        if response.status_code == 200:
            print(f"Success: {response.json().get('message')}")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Connection failed: {e}")

def handle_next_key(args):
    """Generates a next key for propagation."""
    ensure_logged_in()
    
    print("Generating Next CA Key (Propagation Phase)...")
    
    session_data = load_session()
    s = requests.Session()
    s.cookies.update(session_data['cookies'])
    
    try:
        response = s.post(f"{API_URL}/api/ca/next")
        if response.status_code == 200:
            data = response.json()
            pub_key = data.get('public_key')
            print(f"\nSUCCESS: {data.get('message')}")
            print("\n[IMPORTANT] Add the following key to 'TrustedUserCAKeys' on ALL target servers:")
            print("-" * 60)
            print(pub_key)
            print("-" * 60)
            print("\nOnce propagated, run 'ephemera rotate-ca' to switch to this key.")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Connection failed: {e}")

def handle_sudo_approve(args):
    """Approve a pending sudo request via WebAuthn."""
    ensure_logged_in()
    
    request_id = args.request_id
    
    print(f"\n[Ephemera] Approving SUDO request: {request_id}")
    print("[Ephemera] Opening browser for WebAuthn approval...")
    
    # Open browser to approval page
    approval_url = f"{BASE_URL}/sudo_approve.html?id={request_id}"
    webbrowser.open(approval_url)
    
    print("\n[Ephemera] Touch your security key in the browser.")
    print("[Ephemera] The sudo command will resume automatically once approved.")

def main():
    parser = argparse.ArgumentParser(description="Ephemera CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    subparsers.add_parser("login", help="Login to Ephemera")
    subparsers.add_parser("cert", help="Request a new certificate")
    subparsers.add_parser("renew", help="Renew certificate via WebAuthn")
    
    ssh_parser = subparsers.add_parser("ssh", help="SSH into a target")
    ssh_parser.add_argument("target", help="Target host (e.g. user@localhost)")
    
    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize SSH configuration")
    init_parser.add_argument("--rollback", action="store_true", help="Remove Ephemera configuration")

    # Status command
    subparsers.add_parser("status", help="Show Ephemera certificate and agent status")
    
    # Sudo approve command
    sudo_parser = subparsers.add_parser("sudo-approve", help="Approve pending sudo request via WebAuthn")
    sudo_parser.add_argument("request_id", help="The request ID from the sudo prompt")

    # Policy dryrun command
    dryrun_parser = subparsers.add_parser("policy-dryrun", help="Test policy evaluation for a user context.")
    dryrun_parser.add_argument('--username', required=True, help='Username to test')
    dryrun_parser.add_argument('--email', help='Email to test')
    dryrun_parser.add_argument('--ip', default='127.0.0.1', help='Source IP to test')
    dryrun_parser.add_argument('--time', help='Time to test (ISO format)')

    subparsers.add_parser('policy-reload', help='Reload policy from disk (Admin only)')
    
    # Server Setup Command
    parser_server_setup = subparsers.add_parser('server-setup', help='Generate server bootstrap script')
    parser_server_setup.add_argument('--out', '-o', help='Output file for the script (default: stdout)')

    # CA Rotation Command
    subparsers.add_parser('rotate-ca', help='Rotate CA key (Admin only)')

    # Policy Validation Command
    parser_validate = subparsers.add_parser('policy-validate', help='Validate a policy.yaml file')
    parser_validate.add_argument('file', help='Path to policy.yaml file')

    # Revoke Command
    parser_revoke = subparsers.add_parser('revoke', help='Revoke a certificate (Admin only)')
    parser_revoke.add_argument('identifier', help='Serial number or Username to revoke')

    # SUDO History Command
    parser_sudo_history = subparsers.add_parser('sudo-history', help='View SUDO access history')
    parser_sudo_history.add_argument('--limit', '-n', type=int, default=20, help='Number of events to show (default: 20)')

    # Encrypted Backup Commands
    parser_backup = subparsers.add_parser('backup-create', help='Create encrypted backup with Shamir password')
    parser_backup.add_argument('--k', type=int, default=3, help='Threshold needed to restore (default: 3)')
    parser_backup.add_argument('--n', type=int, default=5, help='Total shards to generate (default: 5)')
    parser_backup.add_argument('--out-dir', required=True, help='Directory to write backup and shards to')

    parser_restore = subparsers.add_parser('backup-restore', help='Restore from encrypted backup')
    parser_restore.add_argument('--backup', required=True, help='Path to ephemera_backup.enc')
    parser_restore.add_argument('--shards', nargs='+', required=True, help='List of shard files')
    parser_restore.add_argument('--out-dir', required=True, help='Directory to restore files to')

    args = parser.parse_args()
    
    if args.command == "login":
        login(args)
    elif args.command == "cert":
        get_cert(args)
    elif args.command == "renew":
        renew(args)
    elif args.command == "ssh":
        ssh_connect(args)
    elif args.command == "init":
        from cli.init import init_ssh_config
        init_ssh_config(rollback=args.rollback)
    elif args.command == "status":
        from cli.status import print_status
        print_status(args)
    elif args.command == "policy-dryrun":
        dryrun_policy(args)
    elif args.command == 'policy-reload':
        reload_policy(args)
    elif args.command == 'server-setup':
        handle_server_setup(args)
    elif args.command == 'rotate-ca':
        handle_rotate_ca(args)
    elif args.command == 'policy-validate':
        from cli.policy_validate import validate_policy_file
        if not validate_policy_file(args.file):
            sys.exit(1)
    elif args.command == 'revoke':
        handle_revoke(args)
    elif args.command == 'next-key':
        handle_next_key(args)
    elif args.command == 'sudo-approve':
        handle_sudo_approve(args)
    elif args.command == 'sudo-history':
        from cli.sudo_history import print_sudo_history
        print_sudo_history(args)
    elif args.command == 'backup-create':
        handle_backup_create(args)
    elif args.command == 'backup-restore':
        handle_backup_restore(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
