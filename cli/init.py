import os
import platform
import shutil
from pathlib import Path

def get_ssh_paths():
    """
    Returns a dictionary containing relevant SSH paths based on the OS.
    """
    home = Path.home()
    ssh_dir = home / ".ssh"
    config_file = ssh_dir / "config"
    ephemera_dir = ssh_dir / "ephemera"
    ephemera_config = ephemera_dir / "config"
    
    return {
        "ssh_dir": ssh_dir,
        "config_file": config_file,
        "ephemera_dir": ephemera_dir,
        "ephemera_config": ephemera_config
    }

def init_ssh_config(rollback=False):
    """
    Initializes or rolls back the Ephemera SSH configuration.
    """
    paths = get_ssh_paths()
    ssh_dir = paths["ssh_dir"]
    config_file = paths["config_file"]
    ephemera_dir = paths["ephemera_dir"]
    ephemera_config = paths["ephemera_config"]

    # Normalize path for Include directive (OpenSSH requires forward slashes)
    include_path = ephemera_config.as_posix()
    include_line = f"Include {include_path}"

    if rollback:
        print("Rolling back Ephemera configuration...")
        
        # 1. Remove Include line from ~/.ssh/config
        if config_file.exists():
            try:
                content = config_file.read_text(encoding='utf-8')
                lines = content.splitlines()
                # Remove exact match or match with trailing whitespace
                new_lines = [line for line in lines if line.strip() != include_line]
                
                if len(lines) != len(new_lines):
                    # Reconstruct with original line endings if possible, or just \n
                    config_file.write_text("\n".join(new_lines) + "\n", encoding='utf-8')
                    print(f"Removed Include directive from {config_file}")
                else:
                    print(f"No Include directive found in {config_file}")
            except Exception as e:
                print(f"Error modifying {config_file}: {e}")

        # 2. Delete ~/.ssh/ephemera/config
        if ephemera_config.exists():
            try:
                ephemera_config.unlink()
                print(f"Deleted {ephemera_config}")
            except Exception as e:
                print(f"Error deleting {ephemera_config}: {e}")

        # 3. Remove ~/.ssh/ephemera/ directory if empty
        if ephemera_dir.exists():
            try:
                if not any(ephemera_dir.iterdir()):
                    ephemera_dir.rmdir()
                    print(f"Removed empty directory {ephemera_dir}")
                else:
                    print(f"Directory {ephemera_dir} not empty, skipping removal.")
            except Exception as e:
                print(f"Error removing directory {ephemera_dir}: {e}")
                
        print("Rollback complete.")
        return

    # --- Initialization ---
    print("Initializing Ephemera SSH configuration...")

    # 1. Create ~/.ssh/ephemera/
    if not ephemera_dir.exists():
        try:
            ephemera_dir.mkdir(parents=True, exist_ok=True)
            print(f"Created directory {ephemera_dir}")
        except Exception as e:
            print(f"Error creating directory {ephemera_dir}: {e}")
            return

    # 2. Write ~/.ssh/ephemera/config
    # Use POSIX paths for IdentityFile/CertificateFile too
    id_file = (ephemera_dir / "id_ed25519").as_posix()
    cert_file = (ephemera_dir / "id_ed25519-cert.pub").as_posix()
    
    config_content = f"""# Ephemera Auto-Generated Config
Match exec "ephemera check-match %h"
    IdentityFile {id_file}
    CertificateFile {cert_file}
"""
    
    try:
        ephemera_config.write_text(config_content, encoding='utf-8')
        print(f"Written configuration to {ephemera_config}")
    except Exception as e:
        print(f"Error writing {ephemera_config}: {e}")
        return

    # 3. Prepend Include to ~/.ssh/config
    if not ssh_dir.exists():
        ssh_dir.mkdir(parents=True, exist_ok=True)

    current_content = ""
    if config_file.exists():
        try:
            current_content = config_file.read_text(encoding='utf-8')
        except Exception as e:
            print(f"Error reading {config_file}: {e}")
            return

    # Check if already included
    if include_line in current_content:
        print(f"Include directive already present in {config_file}")
    else:
        try:
            # Prepend with a newline to ensure separation
            new_content = f"{include_line}\n{current_content}"
            config_file.write_text(new_content, encoding='utf-8')
            print(f"Prepended Include directive to {config_file}")
        except Exception as e:
            print(f"Error updating {config_file}: {e}")
            return

    print("Initialization complete.")
