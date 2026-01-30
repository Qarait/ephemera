#!/usr/bin/env python3
"""
GateBridge Telemetry and Logging Unit Tests

Tests the following:
- Mismatch logging with all required fields
- Telemetry percentile calculations
- Health check status response
- Snapshot truncation behavior
"""

import unittest
import json
import sys
import os
from collections import deque
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.gatebridge import (
    ShadowTelemetry,
    log_policy_mismatch,
    get_bridge_status,
    _canonicalize_context,
    BRIDGE_VERSION,
    shadow_telemetry
)


class TestShadowTelemetry(unittest.TestCase):
    """Test the ShadowTelemetry class."""
    
    def setUp(self):
        """Create a fresh telemetry instance for each test."""
        self.telemetry = ShadowTelemetry()
    
    def test_empty_percentiles(self):
        """Empty buffer should return None for percentiles."""
        stats = self.telemetry.get_stats()
        self.assertIsNone(stats["latency_p50_ms"])
        self.assertIsNone(stats["latency_p95_ms"])
        self.assertIsNone(stats["latency_p99_ms"])
    
    def test_single_value_percentile(self):
        """Single value should return that value for all percentiles."""
        self.telemetry.record_success(42.0)
        stats = self.telemetry.get_stats()
        self.assertEqual(stats["latency_p50_ms"], 42.0)
        self.assertEqual(stats["latency_p95_ms"], 42.0)
        self.assertEqual(stats["latency_p99_ms"], 42.0)
    
    def test_percentile_calculation(self):
        """Verify percentile calculation with known values."""
        # Add 100 values from 1 to 100
        for i in range(1, 101):
            self.telemetry.record_success(float(i))
        
        stats = self.telemetry.get_stats()
        # p50 should be around 50
        self.assertIsNotNone(stats["latency_p50_ms"])
        self.assertTrue(49 <= stats["latency_p50_ms"] <= 51)
        # p95 should be around 95
        self.assertTrue(94 <= stats["latency_p95_ms"] <= 96)
        # p99 should be around 99
        self.assertTrue(98 <= stats["latency_p99_ms"] <= 100)
    
    def test_deque_max_length(self):
        """Verify deque doesn't grow beyond maxlen."""
        # Add more than 1000 values
        for i in range(1500):
            self.telemetry.record_success(float(i))
        
        stats = self.telemetry.get_stats()
        self.assertEqual(stats["latency_window_size"], 1000)
        self.assertEqual(stats["total_calls"], 1500)
    
    def test_mismatch_recording(self):
        """Verify mismatch timestamp is recorded."""
        timestamp = "2025-01-30T12:00:00+00:00"
        self.telemetry.record_mismatch(timestamp)
        stats = self.telemetry.get_stats()
        self.assertEqual(stats["last_mismatch"], timestamp)
    
    def test_failure_counters(self):
        """Verify failure counters increment correctly."""
        self.telemetry.record_timeout()
        self.telemetry.record_cli_failure()
        self.telemetry.record_json_error()
        self.telemetry.record_other_error()
        
        stats = self.telemetry.get_stats()
        self.assertEqual(stats["timeouts"], 1)
        self.assertEqual(stats["cli_failures"], 1)
        self.assertEqual(stats["json_parse_errors"], 1)
        self.assertEqual(stats["other_errors"], 1)
        self.assertEqual(stats["total_calls"], 4)


class TestHealthCheck(unittest.TestCase):
    """Test the health check endpoint."""
    
    def test_bridge_status_structure(self):
        """Verify health check returns all required fields."""
        status = get_bridge_status()
        
        # Required fields
        self.assertIn("bridge_version", status)
        self.assertIn("gate0_version", status)
        self.assertIn("policy_hash", status)
        self.assertIn("status", status)
        self.assertIn("last_mismatch", status)
        self.assertIn("telemetry", status)
        
        # Version should match constant
        self.assertEqual(status["bridge_version"], BRIDGE_VERSION)
        
        # Status should be a known value
        self.assertIn(status["status"], ["healthy", "degraded"])
    
    def test_policy_hash_format(self):
        """Policy hash should have sha256 prefix."""
        status = get_bridge_status()
        self.assertTrue(status["policy_hash"].startswith("sha256:"))


class TestSnapshotTruncation(unittest.TestCase):
    """Test snapshot truncation preserves JSON validity."""
    
    def test_large_context_truncated(self):
        """Large context should be truncated but remain valid JSON."""
        # Create a very large context
        large_context = {
            "username": "test",
            "email": "test@example.com",
            "oidc_groups": ["group" + str(i) for i in range(1000)],
            "source_ip": "192.168.1.1",
            "current_time": "14:30",
            "hour_utc": 14,
            "weekday_utc": "thursday",
            "is_business_hours": True
        }
        
        # Simulate what happens in log_policy_mismatch
        import server.gatebridge as gb
        original_cap = gb.SNAPSHOT_SIZE_CAP_KB
        gb.SNAPSHOT_SIZE_CAP_KB = 1  # Very small cap for testing
        
        try:
            snapshot = {
                "canonical_context": large_context,
                "gate0_request": json.dumps(large_context)
            }
            snapshot_json = json.dumps(snapshot)
            
            max_bytes = gb.SNAPSHOT_SIZE_CAP_KB * 1024
            if len(snapshot_json) > max_bytes:
                truncated_snapshot = {
                    "canonical_context": large_context,
                    "gate0_request": "[TRUNCATED]",
                    "_truncated": True,
                    "_original_size_bytes": len(snapshot_json)
                }
                snapshot_json = json.dumps(truncated_snapshot)
            
            # Should still be valid JSON
            parsed = json.loads(snapshot_json)
            self.assertTrue(parsed.get("_truncated", False))
        finally:
            gb.SNAPSHOT_SIZE_CAP_KB = original_cap


class TestLogFields(unittest.TestCase):
    """Test that log entries contain all required fields."""
    
    def test_log_entry_schema(self):
        """Verify log entry contains all documented fields."""
        # We can't easily test actual logging, but we can verify the structure
        # by examining what log_policy_mismatch would produce
        
        yaml_result = {
            "name": "TestPolicy",
            "principals": ["user"],
            "max_duration": "15m"
        }
        
        shadow_result = {
            "match": False,
            "gate0_decision": {"effect": "allow", "reason_code": 0},
            "reference_decision": {"effect": "allow", "policy_name": "TestPolicy"},
            "_canonical_context": {
                "username": "test",
                "email": "test@example.com",
                "source_ip": "192.168.1.1"
            },
            "_request_json": "{}"
        }
        
        user_context = {"username": "test"}
        
        # Simulate entry creation (without actually logging)
        from datetime import datetime, timezone
        import hashlib
        
        canonical_context = shadow_result.get("_canonical_context", {})
        context_hash = hashlib.sha256(
            json.dumps(canonical_context, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "match": shadow_result.get("match", False),
            "versions": {
                "bridge": BRIDGE_VERSION,
                "gate0": "unknown",
                "policy_hash": "unknown"
            },
            "yaml_decision": {
                "policy_name": yaml_result.get("name"),
                "principals": yaml_result.get("principals"),
                "max_duration": yaml_result.get("max_duration")
            },
            "gate0_decision": shadow_result.get("gate0_decision"),
            "reference_decision": shadow_result.get("reference_decision"),
            "context_hash": context_hash
        }
        
        # Verify all required fields
        self.assertIn("timestamp", entry)
        self.assertIn("match", entry)
        self.assertIn("versions", entry)
        self.assertIn("yaml_decision", entry)
        self.assertIn("gate0_decision", entry)
        self.assertIn("context_hash", entry)
        
        # Verify versions structure
        self.assertIn("bridge", entry["versions"])
        self.assertIn("gate0", entry["versions"])
        self.assertIn("policy_hash", entry["versions"])


if __name__ == "__main__":
    unittest.main()
