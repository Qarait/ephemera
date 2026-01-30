#!/usr/bin/env python3
"""
GateBridge Canonicalization Unit Tests

Verifies that the canonicalization rules in gatebridge.py match
the behavior expected by the YAML policy engine.

These tests ensure that:
- YAML engine inputs and GateBridge canonical outputs are comparable
- No systematic false mismatches due to normalization differences
"""

import unittest
import sys
import os
from datetime import datetime, timezone

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.gatebridge import _canonicalize_context, _convert_to_gatebridge_request


class TestCanonicalization(unittest.TestCase):
    """Test canonicalization rules match policy engine expectations."""
    
    def test_email_lowercased(self):
        """Emails should be lowercased for consistent matching."""
        ctx = {"email": "User@Company.COM", "username": "test"}
        canonical = _canonicalize_context(ctx)
        self.assertEqual(canonical["email"], "user@company.com")
    
    def test_username_lowercased(self):
        """Usernames should be lowercased for consistent matching."""
        ctx = {"username": "TestUser", "email": "test@example.com"}
        canonical = _canonicalize_context(ctx)
        self.assertEqual(canonical["username"], "testuser")
    
    def test_ip_normalization(self):
        """IPs should be normalized via ipaddress module."""
        # Standard IPv4
        ctx = {"ip": "192.168.1.1", "username": "test"}
        canonical = _canonicalize_context(ctx)
        self.assertEqual(canonical["source_ip"], "192.168.1.1")
        
        # IPv4 with leading zeros - ipaddress module rejects these,
        # so fallback to strip().lower() is used
        ctx = {"ip": "192.168.001.001", "username": "test"}
        canonical = _canonicalize_context(ctx)
        # Fallback: strip and lowercase
        self.assertEqual(canonical["source_ip"], "192.168.001.001")
    
    def test_time_normalization(self):
        """Time should include precomputed facts."""
        fixed_time = datetime(2025, 1, 30, 14, 30, 0, tzinfo=timezone.utc)
        ctx = {"current_time": fixed_time, "username": "test"}
        canonical = _canonicalize_context(ctx)
        
        self.assertEqual(canonical["hour_utc"], 14)
        self.assertEqual(canonical["weekday_utc"], "thursday")
        self.assertEqual(canonical["is_business_hours"], True)
        self.assertEqual(canonical["current_time"], "14:30")
    
    def test_weekend_not_business_hours(self):
        """Weekends should not be business hours."""
        # Saturday
        fixed_time = datetime(2025, 2, 1, 14, 0, 0, tzinfo=timezone.utc)
        ctx = {"current_time": fixed_time, "username": "test"}
        canonical = _canonicalize_context(ctx)
        
        self.assertEqual(canonical["weekday_utc"], "saturday")
        self.assertEqual(canonical["is_business_hours"], False)
    
    def test_outside_hours_not_business(self):
        """Outside 9-17 UTC should not be business hours."""
        # 8 AM UTC on Wednesday
        fixed_time = datetime(2025, 1, 29, 8, 0, 0, tzinfo=timezone.utc)
        ctx = {"current_time": fixed_time, "username": "test"}
        canonical = _canonicalize_context(ctx)
        
        self.assertEqual(canonical["is_business_hours"], False)
    
    def test_oidc_groups_sorted(self):
        """OIDC groups should be sorted and lowercased."""
        ctx = {"oidc_groups": ["DevOps", "admin", "USERS"], "username": "test"}
        canonical = _canonicalize_context(ctx)
        self.assertEqual(canonical["oidc_groups"], ["admin", "devops", "users"])
    
    def test_empty_context(self):
        """Empty context should not crash."""
        ctx = {}
        canonical = _canonicalize_context(ctx)
        self.assertEqual(canonical["username"], "")
        self.assertEqual(canonical["email"], "")
        self.assertIsNotNone(canonical["hour_utc"])
    
    def test_gatebridge_request_format(self):
        """Canonical context should convert to GateBridge request format."""
        canonical = {
            "username": "testuser",
            "email": "test@example.com",
            "oidc_groups": ["admin"],
            "source_ip": "192.168.1.1",
            "current_time": "14:30",
            "hour_utc": 14,
            "weekday_utc": "thursday",
            "is_business_hours": True,
            "webauthn_id": "abc123"
        }
        request = _convert_to_gatebridge_request(canonical)
        
        self.assertEqual(request["subject"], "testuser")
        self.assertEqual(request["email"], "test@example.com")
        self.assertEqual(request["source_ip"], "192.168.1.1")
        self.assertEqual(request["current_time"], "14:30")
        self.assertEqual(request["is_business_hours"], True)


class TestWildcardSemantics(unittest.TestCase):
    """Test that wildcard semantics are understood."""
    
    def test_fnmatch_email_pattern(self):
        """Document expected fnmatch behavior for emails."""
        import fnmatch
        
        # Pattern from policy: *@contractor.com
        pattern = "*@contractor.com"
        
        # Should match
        self.assertTrue(fnmatch.fnmatch("user@contractor.com", pattern))
        self.assertTrue(fnmatch.fnmatch("a.b.c@contractor.com", pattern))
        
        # Should NOT match
        self.assertFalse(fnmatch.fnmatch("user@other.com", pattern))
        self.assertFalse(fnmatch.fnmatch("user@contractor.com.evil.com", pattern))


class TestCIDRSemantics(unittest.TestCase):
    """Test that CIDR matching semantics are understood."""
    
    def test_ipaddress_cidr(self):
        """Document expected ipaddress module CIDR behavior."""
        import ipaddress
        
        network = ipaddress.ip_network("10.0.0.0/24")
        
        # Should be in network
        self.assertIn(ipaddress.ip_address("10.0.0.1"), network)
        self.assertIn(ipaddress.ip_address("10.0.0.255"), network)
        
        # Should NOT be in network
        self.assertNotIn(ipaddress.ip_address("10.0.1.1"), network)
        self.assertNotIn(ipaddress.ip_address("192.168.1.1"), network)


if __name__ == "__main__":
    unittest.main()
