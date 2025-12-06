import os
import json
import subprocess
import logging
import shutil
import tempfile
from .core import CA_DIR, DATA_DIR, CA_KEY, CA_MASTER_PASSWORD, key_manager
from .crypto import decrypt_ca_key

REVOCATION_LIST_FILE = os.path.join(DATA_DIR, 'revocation_list.json')
KRL_FILE = os.path.join(CA_DIR, 'revoked.krl')

class RevocationManager:
    def __init__(self):
        self.revoked_serials = self._load_revocation_list()

    def _load_revocation_list(self):
        if os.path.exists(REVOCATION_LIST_FILE):
            try:
                with open(REVOCATION_LIST_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading revocation list: {e}")
                return []
        return []

    def _save_revocation_list(self):
        try:
            with open(REVOCATION_LIST_FILE, 'w') as f:
                json.dump(self.revoked_serials, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving revocation list: {e}")

    def revoke_serial(self, serial):
        if serial not in self.revoked_serials:
            self.revoked_serials.append(serial)
            self._save_revocation_list()
        
        # Always regenerate KRL to ensure it exists and is up to date
        return self.generate_krl()

    def generate_krl(self):
        """
        Generates the KRL file using ssh-keygen.
        """
        if not self.revoked_serials:
            pass

        ca_key_path = key_manager.get_active_key_path()
        
        temp_key_path = None
        temp_pub_path = None
        
        try:
            # 1. Get Private Key (Decrypted if needed)
            if os.path.exists(ca_key_path):
                # Check if it's encrypted content
                with open(ca_key_path, 'rb') as f:
                    content = f.read()
                    if b'ENCRYPTED' in content or b'Proc-Type: 4,ENCRYPTED' in content:
                        # Assume it's our custom format if possible, or try to decrypt
                        # But decrypt_ca_key expects salt+data. Standard PEM is different.
                        # If we encounter this, we might fail if we use decrypt_ca_key.
                        # For now, assume plain if not .enc, or if it is encrypted, we can't handle standard PEM easily here.
                        # But let's try to treat it as plain and let ssh-keygen handle it (it might prompt for passphrase).
                        fd, temp_key_path = tempfile.mkstemp()
                        os.close(fd)
                        shutil.copy(ca_key_path, temp_key_path)
                        signing_key_base = temp_key_path
                    else:
                        # Plaintext key
                        fd, temp_key_path = tempfile.mkstemp()
                        os.close(fd)
                        shutil.copy(ca_key_path, temp_key_path)
                        signing_key_base = temp_key_path
            elif os.path.exists(ca_key_path + ".enc"):
                # Encrypted file exists
                decrypted_bytes = decrypt_ca_key(ca_key_path + ".enc", CA_MASTER_PASSWORD)
                fd, temp_key_path = tempfile.mkstemp()
                with os.fdopen(fd, 'wb') as tmp:
                    tmp.write(decrypted_bytes)
                signing_key_base = temp_key_path
            else:
                logging.error(f"Key file not found at {ca_key_path} or {ca_key_path}.enc")
                return False

            # 2. Setup Public Key
            temp_pub_path = signing_key_base + ".pub"
            from .core import CA_PUB
            shutil.copy(CA_PUB, temp_pub_path)
            
            # Normalize paths for Windows
            krl_file_safe = KRL_FILE.replace('\\', '/')
            temp_pub_safe = temp_pub_path.replace('\\', '/')
            
            # 3. Generate KRL
            cmd = [
                'ssh-keygen',
                '-k',
                '-f', krl_file_safe,
                '-s', temp_pub_safe,
            ]
            
            for serial in self.revoked_serials:
                cmd.extend(['-z', str(serial)])
                
            if not self.revoked_serials:
                 cmd = ['ssh-keygen', '-k', '-f', krl_file_safe, '-s', temp_pub_safe]
            
            subprocess.check_call(cmd)
            return True
            
        except Exception as e:
            logging.error(f"Error generating KRL: {e}")
            return False
        finally:
            if temp_key_path and os.path.exists(temp_key_path):
                try: os.remove(temp_key_path)
                except: pass
            if temp_pub_path and os.path.exists(temp_pub_path):
                try: os.remove(temp_pub_path)
                except: pass

    def get_krl_path(self):
        return KRL_FILE

revocation_manager = RevocationManager()
