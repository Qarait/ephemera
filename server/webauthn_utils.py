"""
Challenge storage for WebAuthn authentication.
Uses JSON file storage instead of shelve/pickle to avoid deserialization attacks.
"""
import os
import json
import datetime
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
CHALLENGE_STORE = os.path.join(DATA_DIR, 'challenges.json')

# Thread lock for concurrent access safety
_lock = threading.Lock()

def _ensure_data_dir():
    """Ensure the data directory exists."""
    os.makedirs(DATA_DIR, exist_ok=True)

def _load_challenges():
    """Load challenges from JSON file."""
    if not os.path.exists(CHALLENGE_STORE):
        return {}
    try:
        with open(CHALLENGE_STORE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

def _save_challenges(data):
    """Save challenges to JSON file."""
    _ensure_data_dir()
    with open(CHALLENGE_STORE, 'w') as f:
        json.dump(data, f)

def save_challenge(username, challenge):
    """Store a challenge for a user."""
    with _lock:
        data = _load_challenges()
        data[username] = {
            'challenge': challenge,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        _save_challenges(data)

def get_challenge(username):
    """Retrieve a challenge for a user, checking expiration."""
    with _lock:
        data = _load_challenges()
        entry = data.get(username)
        if not entry:
            return None
        
        # Check expiration (3 minutes)
        timestamp = datetime.datetime.fromisoformat(entry['timestamp'])
        if datetime.datetime.utcnow() - timestamp > datetime.timedelta(minutes=3):
            # Cleanup expired challenge
            del data[username]
            _save_challenges(data)
            return None
        
        return entry['challenge']

def delete_challenge(username):
    """Delete a challenge for a user."""
    with _lock:
        data = _load_challenges()
        if username in data:
            del data[username]
            _save_challenges(data)
