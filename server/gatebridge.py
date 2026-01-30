"""
GateBridge Shadow Evaluation Wrapper (v1.0.0)

This module provides a Python interface to the GateBridge CLI for shadow policy evaluation.
Shadow mode is OBSERVATIONAL ONLY — Gate0 decisions never affect production behavior.

Key properties:
- Fail-open: Any failure returns None, never blocks cert issuance
- No retries: Single attempt per evaluation
- No fallbacks: If Gate0 fails, we just don't have shadow data
- No consensus: YAML decision is always authoritative

Canonicalization Rules (v1.0.0):
- Emails: lowercased
- Usernames: lowercased
- IPs: normalized via ipaddress module
- Time: UTC, with precomputed hour/weekday/business_hours facts
- Wildcard semantics: fnmatch-compatible
- CIDR: Python ipaddress module behavior
"""

import subprocess
import json
import logging
import os
import hashlib
import ipaddress
import time as time_module
from collections import deque
from datetime import datetime, timezone
from typing import Optional, List
from dataclasses import dataclass, field
from threading import Lock

# --- Bridge Version ---
BRIDGE_VERSION = "1.0.0"

# --- Configuration ---
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_CLI_PATH = os.path.join(_BASE_DIR, '..', 'bin', 'gatebridge.exe')
GATEBRIDGE_CLI = os.environ.get('GATEBRIDGE_CLI', _DEFAULT_CLI_PATH)
SHADOW_TIMEOUT_SECONDS = 5
SHADOW_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
SHADOW_LOG_FILE = os.path.join(SHADOW_LOG_DIR, 'policy-shadow.log')
SHADOW_DEBUG_FILE = os.path.join(SHADOW_LOG_DIR, 'shadow-debug.log')

# Log volume controls
SNAPSHOT_ON_MISMATCH_ONLY = True
SNAPSHOT_SIZE_CAP_KB = 16

# Business hours definition (UTC)
BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 17
BUSINESS_DAYS = {"monday", "tuesday", "wednesday", "thursday", "friday"}

# --- Shadow Telemetry ---
# Percentiles computed over last 1000 shadow calls (rolling window).

@dataclass
class ShadowTelemetry:
    """Tracks shadow evaluation metrics for operational visibility."""
    total_calls: int = 0
    successful: int = 0
    timeouts: int = 0
    cli_failures: int = 0
    json_parse_errors: int = 0
    other_errors: int = 0
    last_mismatch_timestamp: Optional[str] = None
    latency_ms: deque = field(default_factory=lambda: deque(maxlen=1000))
    _lock: Lock = field(default_factory=Lock, repr=False)
    
    def record_success(self, latency: float):
        with self._lock:
            self.total_calls += 1
            self.successful += 1
            self.latency_ms.append(latency)
    
    def record_timeout(self):
        with self._lock:
            self.total_calls += 1
            self.timeouts += 1
    
    def record_cli_failure(self):
        with self._lock:
            self.total_calls += 1
            self.cli_failures += 1
    
    def record_json_error(self):
        with self._lock:
            self.total_calls += 1
            self.json_parse_errors += 1
    
    def record_other_error(self):
        with self._lock:
            self.total_calls += 1
            self.other_errors += 1
    
    def record_mismatch(self, timestamp: str):
        with self._lock:
            self.last_mismatch_timestamp = timestamp
    
    def _percentile(self, data: List[float], p: int) -> Optional[float]:
        if not data:
            return None
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * p / 100
        f = int(k)
        c = f + 1
        if c >= len(sorted_data):
            return sorted_data[f]
        return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)
    
    def get_stats(self) -> dict:
        with self._lock:
            latencies = list(self.latency_ms)
            return {
                "total_calls": self.total_calls,
                "successful": self.successful,
                "timeouts": self.timeouts,
                "cli_failures": self.cli_failures,
                "json_parse_errors": self.json_parse_errors,
                "other_errors": self.other_errors,
                "success_rate": (self.successful / self.total_calls * 100) if self.total_calls > 0 else 0,
                "timeout_rate": (self.timeouts / self.total_calls * 100) if self.total_calls > 0 else 0,
                "latency_p50_ms": self._percentile(latencies, 50),
                "latency_p95_ms": self._percentile(latencies, 95),
                "latency_p99_ms": self._percentile(latencies, 99),
                "latency_window_size": len(latencies),
                "last_mismatch": self.last_mismatch_timestamp
            }

# Global telemetry instance
shadow_telemetry = ShadowTelemetry()

# --- Logging Setup ---
shadow_debug_logger = logging.getLogger('gatebridge_debug')
shadow_debug_logger.setLevel(logging.DEBUG)

shadow_policy_logger = logging.getLogger('gatebridge_policy')
shadow_policy_logger.setLevel(logging.INFO)


def _ensure_log_dir():
    """Create logs directory if it doesn't exist."""
    if not os.path.exists(SHADOW_LOG_DIR):
        try:
            os.makedirs(SHADOW_LOG_DIR)
        except OSError:
            pass


def _setup_file_handlers():
    """Setup file handlers for shadow logging."""
    _ensure_log_dir()
    
    if not shadow_debug_logger.handlers:
        try:
            debug_handler = logging.FileHandler(SHADOW_DEBUG_FILE)
            debug_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            shadow_debug_logger.addHandler(debug_handler)
        except Exception:
            pass
    
    if not shadow_policy_logger.handlers:
        try:
            policy_handler = logging.FileHandler(SHADOW_LOG_FILE)
            policy_handler.setFormatter(logging.Formatter('%(message)s'))
            shadow_policy_logger.addHandler(policy_handler)
        except Exception:
            pass


_setup_file_handlers()


# --- Policy Hash Cache ---
_policy_hash_cache = {}


def _get_policy_hash(policy_path: str) -> str:
    """Compute SHA256 hash of policy file. Cached per path/mtime."""
    try:
        mtime = os.path.getmtime(policy_path)
        cache_key = f"{policy_path}:{mtime}"
        if cache_key in _policy_hash_cache:
            return _policy_hash_cache[cache_key]
        
        with open(policy_path, 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()[:16]
        _policy_hash_cache[cache_key] = h
        return h
    except Exception:
        return "unknown"


def _get_gate0_version() -> str:
    """Attempt to get Gate0 CLI version."""
    try:
        result = subprocess.run(
            [GATEBRIDGE_CLI, "--version"],
            capture_output=True,
            text=True,
            timeout=2
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


# --- Canonicalization ---

def _canonicalize_context(user_context: dict) -> dict:
    """
    Canonicalize user context for deterministic comparison.
    
    Rules:
    - Emails/usernames: lowercased
    - IPs: normalized via ipaddress module
    - Time: UTC with precomputed facts
    """
    # Get current time (UTC)
    current_time = user_context.get("current_time")
    if current_time is None:
        current_time = datetime.now(timezone.utc)
    elif not hasattr(current_time, 'tzinfo') or current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    
    now_utc = current_time.astimezone(timezone.utc)
    weekday = now_utc.strftime("%A").lower()
    hour_utc = now_utc.hour
    is_business_hours = (
        weekday in BUSINESS_DAYS and
        BUSINESS_HOURS_START <= hour_utc < BUSINESS_HOURS_END
    )
    
    # Normalize IP
    ip_raw = user_context.get("ip", "")
    ip_normalized = ""
    if ip_raw:
        try:
            ip_normalized = str(ipaddress.ip_address(ip_raw))
        except ValueError:
            ip_normalized = ip_raw.strip().lower()
    
    # Normalize email/username
    email = (user_context.get("email") or "").lower().strip()
    username = (user_context.get("username") or "").lower().strip()
    
    # Normalize OIDC groups
    oidc_groups = user_context.get("oidc_groups", [])
    if oidc_groups:
        oidc_groups = sorted([g.lower().strip() for g in oidc_groups])
    
    return {
        "username": username,
        "email": email,
        "oidc_groups": oidc_groups,
        "auth_mode": user_context.get("auth_mode", "local"),
        "source_ip": ip_normalized,
        "webauthn_id": user_context.get("webauthn_id"),
        # Precomputed time facts for Gate0
        "now_utc_rfc3339": now_utc.isoformat(),
        "hour_utc": hour_utc,
        "weekday_utc": weekday,
        "is_business_hours": is_business_hours,
        # Legacy format for Gate0 CLI
        "current_time": now_utc.strftime("%H:%M")
    }


def _convert_to_gatebridge_request(canonical_context: dict) -> dict:
    """
    Convert canonical context to GateBridge CLI request format.
    """
    return {
        "subject": canonical_context.get("username", ""),
        "oidc_groups": canonical_context.get("oidc_groups", []),
        "email": canonical_context.get("email", ""),
        "local_username": canonical_context.get("username", ""),
        "source_ip": canonical_context.get("source_ip", ""),
        "current_time": canonical_context.get("current_time"),
        "hour_utc": canonical_context.get("hour_utc"),
        "weekday_utc": canonical_context.get("weekday_utc"),
        "is_business_hours": canonical_context.get("is_business_hours"),
        "webauthn_id": canonical_context.get("webauthn_id")
    }


# --- Shadow Evaluation ---

def shadow_evaluate(policy_path: str, user_context: dict) -> Optional[dict]:
    """
    Run GateBridge shadow evaluation via CLI subprocess.
    
    OBSERVATIONAL ONLY: Never affects production behavior.
    - Returns None on any failure (fail-open)
    - No retries, no fallbacks
    - Tracks latency for percentile reporting
    """
    start_time = time_module.perf_counter()
    
    try:
        # Canonicalize context
        canonical_context = _canonicalize_context(user_context)
        request_json = json.dumps(_convert_to_gatebridge_request(canonical_context))
        
        result = subprocess.run(
            [GATEBRIDGE_CLI, "shadow", policy_path, "-"],
            input=request_json,
            capture_output=True,
            text=True,
            timeout=SHADOW_TIMEOUT_SECONDS
        )
        
        latency_ms = (time_module.perf_counter() - start_time) * 1000
        
        if result.returncode == 2:
            shadow_telemetry.record_cli_failure()
            shadow_debug_logger.warning(f"GateBridge CLI error: {result.stderr}")
            return None
        
        try:
            output = json.loads(result.stdout)
            shadow_telemetry.record_success(latency_ms)
            # Attach canonical context for logging
            output["_canonical_context"] = canonical_context
            output["_request_json"] = request_json
            return output
        except json.JSONDecodeError as e:
            shadow_telemetry.record_json_error()
            shadow_debug_logger.error(f"GateBridge JSON parse error: {e}, stdout: {result.stdout[:200]}")
            return None
            
    except subprocess.TimeoutExpired:
        shadow_telemetry.record_timeout()
        shadow_debug_logger.warning(f"GateBridge timeout after {SHADOW_TIMEOUT_SECONDS}s")
        return None
    except FileNotFoundError:
        shadow_telemetry.record_cli_failure()
        shadow_debug_logger.error(f"GateBridge CLI not found: {GATEBRIDGE_CLI}")
        return None
    except Exception as e:
        shadow_telemetry.record_other_error()
        shadow_debug_logger.error(f"GateBridge unexpected error: {type(e).__name__}: {e}")
        return None


# --- Logging ---

def log_policy_mismatch(yaml_result: dict, shadow_result: dict, user_context: dict, policy_path: str):
    """
    Log a policy evaluation result to the shadow log file.
    
    Log volume controls:
    - Always: hashes, versions, decisions
    - Full snapshot: only on mismatch, truncated to SNAPSHOT_SIZE_CAP_KB
    """
    is_mismatch = not shadow_result.get("match", True)
    timestamp = datetime.now(timezone.utc).isoformat()
    
    if is_mismatch:
        shadow_telemetry.record_mismatch(timestamp)
    
    # Get canonical context from shadow result
    canonical_context = shadow_result.get("_canonical_context", {})
    request_json = shadow_result.get("_request_json", "")
    
    # Compute context hash
    context_hash = hashlib.sha256(
        json.dumps(canonical_context, sort_keys=True).encode()
    ).hexdigest()[:16]
    
    entry = {
        "timestamp": timestamp,
        "match": shadow_result.get("match", False),
        # Version locking
        "versions": {
            "bridge": BRIDGE_VERSION,
            "gate0": _get_gate0_version(),
            "policy_hash": _get_policy_hash(policy_path)
        },
        # Decisions (always logged)
        "yaml_decision": {
            "policy_name": yaml_result.get("name"),
            "principals": yaml_result.get("principals"),
            "max_duration": yaml_result.get("max_duration")
        },
        "gate0_decision": shadow_result.get("gate0_decision"),
        "reference_decision": shadow_result.get("reference_decision"),
        # Context hash (always logged)
        "context_hash": context_hash,
        "stats": shadow_result.get("stats")
    }
    
    # Full snapshot only on mismatch (with size cap)
    if is_mismatch or not SNAPSHOT_ON_MISMATCH_ONLY:
        snapshot = {
            "canonical_context": canonical_context,
            "gate0_request": request_json
        }
        snapshot_json = json.dumps(snapshot)
        
        # Check if truncation needed
        max_bytes = SNAPSHOT_SIZE_CAP_KB * 1024
        if len(snapshot_json) > max_bytes:
            # Truncate by removing request_json first, then canonical_context fields
            # to maintain valid JSON structure
            truncated_snapshot = {
                "canonical_context": canonical_context,
                "gate0_request": "[TRUNCATED]",
                "_truncated": True,
                "_original_size_bytes": len(snapshot_json)
            }
            snapshot_json = json.dumps(truncated_snapshot)
            
            # If still too large, truncate canonical_context to essentials
            if len(snapshot_json) > max_bytes:
                minimal_context = {
                    "username": canonical_context.get("username"),
                    "email": canonical_context.get("email"),
                    "source_ip": canonical_context.get("source_ip"),
                    "hour_utc": canonical_context.get("hour_utc")
                }
                truncated_snapshot = {
                    "canonical_context": minimal_context,
                    "gate0_request": "[TRUNCATED]",
                    "_truncated": True,
                    "_original_size_bytes": len(json.dumps(snapshot))
                }
                snapshot_json = json.dumps(truncated_snapshot)
        
        entry["snapshot"] = snapshot_json
    
    try:
        shadow_policy_logger.info(json.dumps(entry))
    except Exception as e:
        shadow_debug_logger.error(f"Failed to log policy mismatch: {e}")


# --- Health Check ---

def get_bridge_status(policy_path: str = None) -> dict:
    """
    Get current bridge status for health check endpoint.
    
    Returns:
        {
            "bridge_version": "1.0.0",
            "gate0_version": "v0.2.1",
            "policy_hash": "sha256:8f4b...",
            "status": "healthy",
            "last_mismatch": "2025-01-30T10:00:00Z",
            "telemetry": {...}
        }
    """
    stats = shadow_telemetry.get_stats()
    
    # Determine health status
    status = "healthy"
    if stats["cli_failures"] > 0 and stats["successful"] == 0:
        status = "degraded"
    elif stats["timeout_rate"] and stats["timeout_rate"] > 10:
        status = "degraded"
    
    policy_hash = "unknown"
    if policy_path:
        policy_hash = _get_policy_hash(policy_path)
    
    return {
        "bridge_version": BRIDGE_VERSION,
        "gate0_version": _get_gate0_version(),
        "policy_hash": f"sha256:{policy_hash}",
        "status": status,
        "last_mismatch": stats.get("last_mismatch"),
        "telemetry": stats
    }


def get_shadow_telemetry() -> dict:
    """Get current shadow evaluation telemetry stats."""
    return shadow_telemetry.get_stats()
