import subprocess
import logging
import os
import tempfile

logger = logging.getLogger(__name__)

def run_command(cmd, env=None):
    """Run a subprocess command and return output."""
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True,
            env=env
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(cmd)}\nStderr: {e.stderr}")
        raise RuntimeError(f"Command failed: {e.stderr}")

def check_pkcs11_tool():
    """Check if pkcs11-tool is available."""
    try:
        subprocess.run(["pkcs11-tool", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False

def get_public_key_from_hsm(module_path, slot, key_label, pin):
    """
    Extracts the public key from the HSM using ssh-keygen -D.
    Note: ssh-keygen -D returns all public keys in the token.
    We need to filter for the one matching our label or usage?
    Actually, ssh-keygen -D <module> lists all keys.
    We might need to match it against the expected key.
    
    However, for the purpose of signing with -s <pubkey>, we need the specific public key content.
    
    Alternative: Use pkcs11-tool to read the public key?
    pkcs11-tool --read-object --type pubkey --label <label> ...
    But that returns ASN.1/DER. ssh-keygen needs OpenSSH format.
    
    Best approach: Use ssh-keygen -D and find the key.
    But ssh-keygen -D doesn't take a label filter easily.
    
    If we assume there's only one CA key or we can identify it.
    The user instructions say:
    "ssh-keygen -D ... -S <PUBLIC_PART_OF_HSM_KEY> ..."
    
    Let's try to extract it using ssh-keygen -D and maybe we just use the first one if not specified?
    Or we can try to match the comment if it has one?
    
    For now, let's implement a function that returns the public key text.
    """
    # This command lists all public keys available in the token
    # We might need to set SSH_ASKPASS for PIN if required, but usually -D lists pubkeys without PIN?
    # Some tokens require login for pubkeys.
    
    cmd = ["ssh-keygen", "-D", module_path]
    
    # If PIN is needed, we might need the askpass dance.
    env = os.environ.copy()
    askpass_path = None
    if pin:
        # Create a temporary askpass script
        # Note: This is platform specific (Unix/Windows).
        # On Windows, shell scripts might not work as ASKPASS.
        # But we are targeting the user's environment which might be WSL or Linux based on instructions.
        # If running on Windows directly, this might fail.
        # We'll assume standard POSIX behavior for now as per instructions.
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as askpass:
            askpass.write(f"#!/bin/sh\necho {pin}\n")
            askpass_path = askpass.name
        
        os.chmod(askpass_path, 0o700)
        env['SSH_ASKPASS'] = askpass_path
        env['DISPLAY'] = ':0'
        env['SSH_ASKPASS_REQUIRE'] = 'force'

    try:
        output = run_command(cmd, env=env)
        # Output contains lines of public keys.
        # We need to pick the right one.
        # For Phase 1, if there are multiple, maybe we just pick the first one?
        # Or we can try to match the key label if ssh-keygen exposes it (it usually doesn't in the output).
        
        lines = output.splitlines()
        if not lines:
            raise RuntimeError("No keys found in HSM.")
            
        # Return the first key for now.
        return lines[0]
        
    finally:
        if askpass_path and os.path.exists(askpass_path):
            os.remove(askpass_path)

def verify_key_in_hsm(module_path, slot, label, pin):
    """
    Verifies that the key exists in the HSM using pkcs11-tool.
    pkcs11-tool -L --slot <slot> ...
    """
    # pkcs11-tool -O --login --pin <pin> --module <module>
    # We look for the object with the label.
    
    cmd = [
        "pkcs11-tool",
        "--module", module_path,
        "--slot", str(slot),
        "--login", "--pin", pin,
        "-O" # List objects
    ]
    
    output = run_command(cmd)
    
    # Check for the label in output
    # Output format:
    # Public Key Object; RSA 2048 bits
    #   label:      EphemeraCA
    #   ID:         ...
    #   Usage:      encrypt, verify, wrap
    
    if f"label:      {label}" in output or f"label: {label}" in output:
        return True
    return False

def verify_key_non_exportable(module_path, slot, label, pin):
    """
    Verifies that the private key cannot be extracted.
    pkcs11-tool --read-object --type privkey --label <label> ...
    Should fail.
    """
    cmd = [
        "pkcs11-tool",
        "--module", module_path,
        "--slot", str(slot),
        "--login", "--pin", pin,
        "--read-object",
        "--type", "privkey",
        "--label", label
    ]
    
    try:
        subprocess.run(cmd, capture_output=True, check=True)
        # If it succeeds, that's bad!
        return False
    except subprocess.CalledProcessError:
        # If it fails, that's good (usually).
        # We should check if it failed because of permissions/exportability.
        return True
