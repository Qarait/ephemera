"""
GateBridge Shadow Evaluation Wrapper

This module provides a Python interface to the GateBridge CLI for shadow policy evaluation.
Shadow mode is OBSERVATIONAL ONLY — Gate0 decisions never affect production behavior.

Key properties:
- Fail-open: Any failure returns None, never blocks cert issuance
- No retries: Single attempt per evaluation
- No fallbacks: If Gate0 fails, we just don't have shadow data
- No consensus: YAML decision is always authoritative

Future considerations:
- Shadow evaluation may be sampled or rate-limited to avoid performance overhead
- Consider async execution if synchronous overhead becomes measurable
"""

import subprocess
import json
import logging
import os
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field
from threading import Lock

# --- Shadow Failure Telemetry ---
# Separate from policy-shadow.log to track operational health

@dataclass
class ShadowTelemetry:
    """Tracks shadow evaluation failures for operational visibility."""
    total_calls: int = 0
    successful: int = 0
    timeouts: int = 0
    cli_failures: int = 0
    json_parse_errors: int = 0
    other_errors: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)
    
    def record_success(self):
        with self._lock:
            self.total_calls += 1
            self.successful += 1
    
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
    
    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_calls": self.total_calls,
                "successful": self.successful,
                "timeouts": self.timeouts,
                "cli_failures": self.cli_failures,
                "json_parse_errors": self.json_parse_errors,
                "other_errors": self.other_errors,
                "success_rate": (self.successful / self.total_calls * 100) if self.total_calls > 0 else 0
            }

# Global telemetry instance
shadow_telemetry = ShadowTelemetry()

# --- Logging Setup ---

# Debug logger for shadow failures (separate channel)
shadow_debug_logger = logging.getLogger('gatebridge_debug')
shadow_debug_logger.setLevel(logging.DEBUG)

# Policy mismatch logger (the actual data we care about)
shadow_policy_logger = logging.getLogger('gatebridge_policy')
shadow_policy_logger.setLevel(logging.INFO)

# Configuration
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_CLI_PATH = os.path.join(_BASE_DIR, '..', 'bin', 'gatebridge.exe')
GATEBRIDGE_CLI = os.environ.get('GATEBRIDGE_CLI', _DEFAULT_CLI_PATH)
SHADOW_TIMEOUT_SECONDS = 5
SHADOW_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
SHADOW_LOG_FILE = os.path.join(SHADOW_LOG_DIR, 'policy-shadow.log')
SHADOW_DEBUG_FILE = os.path.join(SHADOW_LOG_DIR, 'shadow-debug.log')


def _ensure_log_dir():
    """Create logs directory if it doesn't exist."""
    if not os.path.exists(SHADOW_LOG_DIR):
        try:
            os.makedirs(SHADOW_LOG_DIR)
        except OSError:
            pass  # Fail silently, logging will just not work


def _setup_file_handlers():
    """Setup file handlers for shadow logging."""
    _ensure_log_dir()
    
    # Debug handler (operational failures)
    if not shadow_debug_logger.handlers:
        try:
            debug_handler = logging.FileHandler(SHADOW_DEBUG_FILE)
            debug_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            shadow_debug_logger.addHandler(debug_handler)
        except Exception:
            pass  # Fail silently
    
    # Policy handler (mismatches) - JSON Lines format
    if not shadow_policy_logger.handlers:
        try:
            policy_handler = logging.FileHandler(SHADOW_LOG_FILE)
            policy_handler.setFormatter(logging.Formatter('%(message)s'))  # Raw JSON
            shadow_policy_logger.addHandler(policy_handler)
        except Exception:
            pass  # Fail silently


# Initialize handlers on module load
_setup_file_handlers()


def shadow_evaluate(policy_path: str, user_context: dict) -> Optional[dict]:
    """
    Run GateBridge shadow evaluation via CLI subprocess.
    
    OBSERVATIONAL ONLY: This function never affects production behavior.
    - Returns None on any failure (fail-open)
    - No retries
    - No fallbacks
    - Swallows all exceptions
    
    Args:
        policy_path: Path to the YAML policy file
        user_context: User context dict matching Ephemera's policy evaluation format
    
    Returns:
        dict with shadow evaluation result, or None on failure
        {
            "reference_decision": {"effect": "allow", "policy_name": "..."},
            "gate0_decision": {"effect": "allow", "reason_code": 0},
            "match": true/false,
            "stats": {...}
        }
    """
    try:
        # Convert user_context to GateBridge request format
        request_json = json.dumps(_convert_to_gatebridge_request(user_context))
        
        result = subprocess.run(
            [GATEBRIDGE_CLI, "shadow", policy_path, "-"],
            input=request_json,
            capture_output=True,
            text=True,
            timeout=SHADOW_TIMEOUT_SECONDS
        )
        
        if result.returncode == 2:
            # Error exit code
            shadow_telemetry.record_cli_failure()
            shadow_debug_logger.warning(f"GateBridge CLI error: {result.stderr}")
            return None
        
        # Parse output (returncode 0 = match, 1 = mismatch, both are valid)
        try:
            output = json.loads(result.stdout)
            shadow_telemetry.record_success()
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


def _convert_to_gatebridge_request(user_context: dict) -> dict:
    """
    Convert Ephemera user_context to GateBridge request format.
    
    Ephemera context:
    {
        "username": "...",
        "email": "...",
        "oidc_groups": [...],
        "auth_mode": "local" | "oidc",
        "ip": "1.2.3.4",
        "current_time": datetime_obj,
        "webauthn_id": "..."
    }
    
    GateBridge request:
    {
        "subject": "...",
        "oidc_groups": [...],
        "email": "...",
        "local_username": "...",
        "source_ip": "...",
        "current_time": "HH:MM",
        "webauthn_id": "..."
    }
    """
    current_time = user_context.get("current_time")
    time_str = None
    if current_time:
        if hasattr(current_time, 'strftime'):
            time_str = current_time.strftime("%H:%M")
        elif isinstance(current_time, str):
            time_str = current_time
    
    return {
        "subject": user_context.get("username", ""),
        "oidc_groups": user_context.get("oidc_groups", []),
        "email": user_context.get("email", ""),
        "local_username": user_context.get("username", ""),
        "source_ip": user_context.get("ip", ""),
        "current_time": time_str,
        "webauthn_id": user_context.get("webauthn_id")
    }


def log_policy_mismatch(yaml_result: dict, shadow_result: dict, user_context: dict):
    """
    Log a policy mismatch to the shadow log file.
    
    Format: JSON Lines (one JSON object per line)
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "match": shadow_result.get("match", False),
        "yaml_decision": {
            "policy_name": yaml_result.get("name"),
            "principals": yaml_result.get("principals"),
            "max_duration": yaml_result.get("max_duration")
        },
        "gate0_decision": shadow_result.get("gate0_decision"),
        "reference_decision": shadow_result.get("reference_decision"),
        "context": {
            "username": user_context.get("username"),
            "email": user_context.get("email"),
            "ip": user_context.get("ip"),
            "auth_mode": user_context.get("auth_mode")
        },
        "stats": shadow_result.get("stats")
    }
    
    try:
        shadow_policy_logger.info(json.dumps(entry))
    except Exception as e:
        shadow_debug_logger.error(f"Failed to log policy mismatch: {e}")


def get_shadow_telemetry() -> dict:
    """
    Get current shadow evaluation telemetry stats.
    Useful for monitoring/admin endpoints.
    """
    return shadow_telemetry.get_stats()
