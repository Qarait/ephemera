import os
import json
import requests

BASE_URL = "http://localhost:3000"
# Use ~/.ssh/ephemera to match init.py structure
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".ssh", "ephemera")
SESSION_FILE = os.path.join(CONFIG_DIR, "session.json")
# Use standard key name
KEY_NAME = os.path.join(CONFIG_DIR, "id_ed25519")

def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

def save_session(username, cookies):
    ensure_config_dir()
    with open(SESSION_FILE, 'w') as f:
        json.dump({"username": username, "cookies": cookies}, f)
    print(f"Session saved for {username}.")

def load_session():
    if not os.path.exists(SESSION_FILE):
        return None
    try:
        with open(SESSION_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None
