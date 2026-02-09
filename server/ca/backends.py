from abc import ABC, abstractmethod
import subprocess
import tempfile
import os
import logging
import uuid
from server.crypto import decrypt_ca_key

logger = logging.getLogger(__name__)

class BaseCA(ABC):
    @abstractmethod
    def issue_user_cert(self, user_pubkey_path: str, principals: list[str], valid_for_seconds: int) -> tuple[str, str]:
        """
        Given a user public key path and principals, returns (cert_text, request_id).
        """
        pass

class FileCA(BaseCA):
    def __init__(self, ca_key_path: str, ca_key_password: str = None):
        self.ca_key_path = ca_key_path
        self.ca_key_password = ca_key_password

    def issue_user_cert(self, user_pubkey_path, principals, valid_for_seconds):
        """
        Issues an SSH certificate using a file-based CA key.
        """
        # Generate a unique serial number (or request ID)
        request_id = str(uuid.uuid4())
        
        # Calculate validity interval
        # ssh-keygen -V format: +5m (5 minutes from now)
        # We convert seconds to minutes for simplicity if possible, or use seconds format if supported?
        # ssh-keygen -V +5m is supported. +300s might not be standard in all versions?
        # Actually +5m is standard. Let's convert seconds to minutes (rounding up?).
        # Or better, use absolute timestamps? 
        # The prompt suggested +{valid_for_seconds}s. Let's try that.
        validity_spec = f"+{valid_for_seconds}s"
        
        # Decrypt CA key to temp file securely if needed
        temp_ca_fd, temp_ca_path = tempfile.mkstemp()
        
        try:
            # Check for encrypted key
            ca_key_enc = f"{self.ca_key_path}.enc"
            if os.path.exists(ca_key_enc):
                if not self.ca_key_password:
                    raise RuntimeError("CA key is encrypted but no password provided.")
                
                decrypted_ca = decrypt_ca_key(ca_key_enc, self.ca_key_password)
                with os.fdopen(temp_ca_fd, 'wb') as f:
                    f.write(decrypted_ca)
                signing_key_path = temp_ca_path
            elif os.path.exists(self.ca_key_path):
                # Unencrypted key (fallback/dev)
                signing_key_path = self.ca_key_path
                os.close(temp_ca_fd) # Close unused temp fd
                os.remove(temp_ca_path) # Remove unused temp file
            else:
                os.close(temp_ca_fd)
                os.remove(temp_ca_path)
                raise RuntimeError(f"CA key not found at {self.ca_key_path}")

            # Prepare command with the correct key path
            # Generate a 64-bit random serial number for the certificate
            import secrets
            serial = secrets.randbits(64)
            
            cmd = [
                'ssh-keygen',
                '-s', signing_key_path,
                '-I', f"ephemera-{request_id}",
                '-n', ",".join(principals),
                '-V', validity_spec,
                '-z', str(serial), 
                user_pubkey_path
            ]
            
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"ssh-keygen failed: {e.stderr}")
            raise RuntimeError(f"Certificate issuance failed: {e.stderr}")
        finally:
            # Cleanup temp key if we created one
            if signing_key_path == temp_ca_path and os.path.exists(temp_ca_path):
                os.remove(temp_ca_path)

from server.hsm.pkcs11_utils import get_public_key_from_hsm

class SoftHsmCA(BaseCA):
    def __init__(self, module_path: str, slot: str, key_label: str, pin: str):
        self.module_path = module_path
        self.slot = slot
        self.key_label = key_label
        self.pin = pin
        self.temp_pub_key_path = None
        
        # Extract public key to temp file on init
        try:
            pub_key_content = get_public_key_from_hsm(module_path, slot, key_label, pin)
            
            # Create a persistent temp file for the public key
            # We keep it for the lifetime of the process? Or just create it.
            # ssh-keygen -s needs a file path.
            fd, path = tempfile.mkstemp(prefix="ephemera_ca_pub_", suffix=".pub")
            with os.fdopen(fd, 'w') as f:
                f.write(pub_key_content)
            self.temp_pub_key_path = path
            logger.info(f"Extracted HSM public key to {self.temp_pub_key_path}")
            
        except Exception as e:
            logger.error(f"Failed to extract public key from HSM: {e}")
            raise RuntimeError(f"Failed to extract public key from HSM: {e}")

    def __del__(self):
        # Cleanup temp file
        if self.temp_pub_key_path and os.path.exists(self.temp_pub_key_path):
            try:
                os.remove(self.temp_pub_key_path)
            except OSError:
                pass

    def issue_user_cert(self, user_pubkey_path, principals, valid_for_seconds):
        """
        Issues an SSH certificate using SoftHSM (PKCS#11).
        Uses ssh-keygen -D <module> -s <pub_key_file> ...
        """
        validity_spec = f"+{valid_for_seconds}s"
        request_id = str(uuid.uuid4())

        # Build ssh-keygen command
        # Syntax: ssh-keygen -D <module> -s <ca_pub_key_file> ...
        
        env = os.environ.copy()
        askpass_path = None
        
        if self.pin:
            # Create a temporary askpass script
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as askpass:
                askpass.write(f"#!/bin/sh\necho {self.pin}\n")
                askpass_path = askpass.name
            
            os.chmod(askpass_path, 0o700)
            env['SSH_ASKPASS'] = askpass_path
            env['DISPLAY'] = ':0' 
            env['SSH_ASKPASS_REQUIRE'] = 'force' 
        
        # Prepare command
        # Generate a 64-bit random serial number for the certificate
        import secrets
        serial = secrets.randbits(64)
        
        cmd = [
            "ssh-keygen",
            "-D", self.module_path,
            "-s", self.temp_pub_key_path,
            "-I", f"ephemera-{request_id}",
            "-n", ",".join(principals),
            "-V", validity_spec,
            "-z", str(serial),
            "-f", user_pubkey_path
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, env=env, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"SoftHSM signing failed: {e.stderr}")
            if askpass_path and os.path.exists(askpass_path):
                os.remove(askpass_path)
            raise RuntimeError(f"SoftHSM signing failed: {e.stderr}")
            
        if askpass_path and os.path.exists(askpass_path):
            os.remove(askpass_path)

        cert_file = user_pubkey_path + "-cert.pub"
        if not os.path.exists(cert_file):
             raise RuntimeError("Certificate file was not created.")

        with open(cert_file, "r", encoding="utf-8") as f:
            cert_text = f.read().strip()

        return cert_text, request_id
