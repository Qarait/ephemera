import os
import shelve
import base64
import datetime
from webauthn.helpers import base64url_to_bytes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
CHALLENGE_STORE = os.path.join(DATA_DIR, 'challenges')

def save_challenge(username, challenge):
    with shelve.open(CHALLENGE_STORE) as db:
        # Store challenge with timestamp
        db[username] = {
            'challenge': challenge,
            'timestamp': datetime.datetime.utcnow()
        }

def get_challenge(username):
    with shelve.open(CHALLENGE_STORE) as db:
        data = db.get(username)
        if not data:
            return None
            
        # Check expiration (3 minutes)
        if datetime.datetime.utcnow() - data['timestamp'] > datetime.timedelta(minutes=3):
            del db[username] # Cleanup expired
            return None
            
        return data['challenge']

def delete_challenge(username):
    with shelve.open(CHALLENGE_STORE) as db:
        if username in db:
            del db[username]
