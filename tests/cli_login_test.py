import sys
import os
import pyotp
from unittest.mock import patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import ephemera_cli

def test_login():
    totp = pyotp.TOTP('7IFS52L4GCNMH37AMIZR3ZWFRDJYVB5H')
    code = totp.now()
    
    print(f"Generated TOTP: {code}")
    
    with patch('builtins.input', side_effect=['admin', code]), \
         patch('getpass.getpass', return_value='OIs5ENM2-RJlyHWgj4jX0g'):
        
        # We need to mock args
        class Args:
            pass
        args = Args()
        
        ephemera_cli.login(args)

if __name__ == "__main__":
    test_login()
