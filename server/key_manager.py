import os
import json
import shutil
import logging
import datetime
import subprocess
from server.crypto import encrypt_ca_key

logger = logging.getLogger(__name__)

class KeyManager:
    def __init__(self, ca_dir, master_password, backend_type="file", hsm_config=None):
        self.ca_dir = ca_dir
        self.keys_dir = os.path.join(ca_dir, 'keys') # Subdir for rotated keys
        self.metadata_file = os.path.join(self.keys_dir, 'metadata.json')
        self.master_password = master_password
        self.backend_type = backend_type
        self.hsm_config = hsm_config or {}
        
        # Legacy paths for migration
        self.legacy_key = os.path.join(ca_dir, 'ca_key')
        self.legacy_pub = os.path.join(ca_dir, 'ca_key.pub')
        
        self._init_storage()

    def _init_storage(self):
        """Initialize storage and migrate legacy keys if needed."""
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
            
        if not os.path.exists(self.metadata_file):
            # Check for legacy key to migrate
            if os.path.exists(self.legacy_key) or os.path.exists(f"{self.legacy_key}.enc"):
                self._migrate_legacy()
            else:
                # Fresh install - will be handled by ensure_active_key
                self._save_metadata({
                    "active": None,
                    "previous": None,
                    "history": []
                })

    def _save_metadata(self, data):
        with open(self.metadata_file, 'w') as f:
            json.dump(data, f, indent=2)

    def get_metadata(self):
        if not os.path.exists(self.metadata_file):
            return {}
        with open(self.metadata_file, 'r') as f:
            return json.load(f)

    def _migrate_legacy(self):
        """Migrate existing ca_key to keys/v1 structure."""
        logger.info("Migrating legacy CA key to KeyManager structure...")
        
        v1_id = "v1_legacy"
        v1_key_path = os.path.join(self.keys_dir, v1_id)
        v1_pub_path = os.path.join(self.keys_dir, f"{v1_id}.pub")
        
        # Copy private key (handle encrypted vs plain)
        if os.path.exists(f"{self.legacy_key}.enc"):
            shutil.copy(f"{self.legacy_key}.enc", f"{v1_key_path}.enc")
        elif os.path.exists(self.legacy_key):
            shutil.copy(self.legacy_key, v1_key_path)
            # Encrypt it in new location if it wasn't
            encrypt_ca_key(v1_key_path, self.master_password)
            
        # Copy public key
        if os.path.exists(self.legacy_pub):
            shutil.copy(self.legacy_pub, v1_pub_path)
            
        # Update metadata
        self._save_metadata({
            "active": v1_id,
            "previous": None,
            "history": [{"id": v1_id, "created_at": datetime.datetime.utcnow().isoformat()}]
        })
        logger.info("Migration complete.")

    def get_active_key_path(self):
        """Returns the path to the active private key (without .enc extension)."""
        meta = self.get_metadata()
        active_id = meta.get("active")
        if not active_id:
            return None
        return os.path.join(self.keys_dir, active_id)

    def get_all_public_keys(self):
        """Returns a list of all trusted public key strings (active + previous + next)."""
        meta = self.get_metadata()
        keys = []
        
        # Helper to read key
        def read_pub(key_id):
            path = os.path.join(self.keys_dir, f"{key_id}.pub")
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return f.read().strip()
            return None

        if meta.get("active"):
            k = read_pub(meta.get("active"))
            if k: keys.append(k)
            
        if meta.get("previous"):
            k = read_pub(meta.get("previous"))
            if k: keys.append(k)

        if meta.get("next"):
            k = read_pub(meta.get("next"))
            if k: keys.append(k)
            
        return keys

    def prepare_rotation(self):
        """
        Generates a new key and stores it as 'next' (Propagation Phase).
        Returns the public key content of the new key.
        """
        meta = self.get_metadata()
        
        # If next already exists, return it
        if meta.get("next"):
            logger.info(f"Next key already exists: {meta.get('next')}")
            return self._read_pub_key(meta.get("next"))
            
        # Generate new key ID
        new_id = f"v{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        new_key_path = os.path.join(self.keys_dir, new_id)
        
        logger.info(f"Preparing new CA key (Next): {new_id}")
        
        if self.backend_type == "softhsm":
             raise NotImplementedError("HSM rotation not yet implemented")
        else:
            # File Backend Generation
            try:
                subprocess.check_call([
                    'ssh-keygen', '-t', 'ed25519',
                    '-f', new_key_path, '-N', ''
                ])
                # Encrypt immediately
                encrypt_ca_key(new_key_path, self.master_password)
                
                # Update Metadata
                meta["next"] = new_id
                # Add to history? Maybe only when it becomes active? 
                # Or track creation now. Let's track creation in history when active or separate list?
                # For simplicity, just store in 'next' field for now.
                self._save_metadata(meta)
                
                return self._read_pub_key(new_id)
            except Exception as e:
                logger.error(f"Prepare rotation failed: {e}")
                raise e

    def _read_pub_key(self, key_id):
        path = os.path.join(self.keys_dir, f"{key_id}.pub")
        if os.path.exists(path):
            with open(path, 'r') as f:
                return f.read().strip()
        return None

    def rotate(self):
        """
        Rotates the CA key.
        1. If 'next' exists: Promote Next -> Active, Active -> Previous.
        2. If no 'next': Generate New -> Active, Active -> Previous (Immediate Rotation).
        """
        meta = self.get_metadata()
        old_active = meta.get("active")
        next_key = meta.get("next")
        
        new_id = None
        
        if next_key:
            # Promote Next
            logger.info(f"Promoting 'next' key {next_key} to 'active'")
            new_id = next_key
            meta["next"] = None # Clear next
        else:
            # Immediate Rotation (Generate new)
            new_id = f"v{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            new_key_path = os.path.join(self.keys_dir, new_id)
            
            logger.info(f"Rotating CA key (Immediate). New ID: {new_id}")
            
            if self.backend_type == "softhsm":
                raise NotImplementedError("HSM rotation not yet implemented")
            
            try:
                subprocess.check_call([
                    'ssh-keygen', '-t', 'ed25519',
                    '-f', new_key_path, '-N', ''
                ])
                encrypt_ca_key(new_key_path, self.master_password)
            except Exception as e:
                logger.error(f"Rotation failed: {e}")
                return False

        # Update Metadata
        meta["previous"] = old_active
        meta["active"] = new_id
        meta["history"].append({"id": new_id, "created_at": datetime.datetime.utcnow().isoformat()})
        self._save_metadata(meta)
        
        logger.info(f"Rotation successful. Active: {new_id}, Previous: {old_active}")
        return True

    def ensure_active_key(self):
        """Ensures an active key exists. If not, generates one."""
        if not self.get_active_key_path():
            logger.info("No active key found. Generating initial key...")
            self.rotate()
