import unittest
import sys
import os
import json
import datetime
import shelve
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server import webauthn_utils
from server.renewal import renewal_bp
from flask import Flask, session

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(renewal_bp)
        self.app.secret_key = 'test_secret'
        self.client = self.app.test_client()
        
        # Clear challenge store
        if os.path.exists(webauthn_utils.CHALLENGE_STORE + '.dat'):
            os.remove(webauthn_utils.CHALLENGE_STORE + '.dat')
        if os.path.exists(webauthn_utils.CHALLENGE_STORE + '.bak'):
            os.remove(webauthn_utils.CHALLENGE_STORE + '.bak')
        if os.path.exists(webauthn_utils.CHALLENGE_STORE + '.dir'):
            os.remove(webauthn_utils.CHALLENGE_STORE + '.dir')

    def test_challenge_expiration(self):
        """Test that expired challenges are rejected"""
        username = 'testuser'
        challenge = b'test_challenge'
        
        # Save challenge
        webauthn_utils.save_challenge(username, challenge)
        
        # Manually modify the timestamp to be 5 minutes ago
        with shelve.open(webauthn_utils.CHALLENGE_STORE) as db:
            data = db[username]
            data['timestamp'] = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
            db[username] = data
            
        # Try to get challenge
        retrieved = webauthn_utils.get_challenge(username)
        self.assertIsNone(retrieved, "Expired challenge should return None")

    def test_replay_attack(self):
        """Test that a challenge cannot be used twice"""
        username = 'testuser'
        challenge = b'test_challenge'
        
        # Save challenge
        webauthn_utils.save_challenge(username, challenge)
        
        # First retrieval
        retrieved1 = webauthn_utils.get_challenge(username)
        self.assertEqual(retrieved1, challenge)
        
        # Simulate successful use (delete)
        webauthn_utils.delete_challenge(username)
        
        # Second retrieval (Replay attempt)
        retrieved2 = webauthn_utils.get_challenge(username)
        self.assertIsNone(retrieved2, "Challenge should be gone after use")

    @patch('server.renewal.get_users')
    @patch('server.renewal.verify_authentication_response')
    @patch('server.renewal.issue_ssh_cert')
    @patch('server.renewal.append_audit_log')
    def test_invalid_credential_id(self, mock_log, mock_issue, mock_verify, mock_get_users):
        """Test rejection of incorrect credential ID"""
        username = 'testuser'
        
        # Mock user with a specific credential ID
        mock_user = {
            'username': username,
            'webauthn_credentials': [{
                'credential_id': 'valid_id',
                'public_key': 'pubkey',
                'sign_count': 0
            }]
        }
        mock_get_users.return_value = [mock_user]
        
        # Save challenge
        webauthn_utils.save_challenge(username, b'challenge')
        
        with self.client.session_transaction() as sess:
            sess['username'] = username
            
        # Attempt renewal with INVALID credential ID
        payload = {
            'id': 'invalid_id', # Mismatch
            'rawId': 'invalid_id',
            'response': {},
            'type': 'public-key',
            'sshPublicKey': 'ssh-ed25519 ...'
        }
        
        res = self.client.post('/api/webauthn/renew/finish', json=payload)
        
        self.assertEqual(res.status_code, 400)
        self.assertIn(b'Credential not found', res.data)
        
        # Verify cert was NOT issued
        mock_issue.assert_not_called()

if __name__ == '__main__':
    unittest.main()
