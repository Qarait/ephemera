#!/usr/bin/env python3
"""
GateBridge Replay Test — Reproducibility from Shadow Logs

This script loads canonical snapshots from policy-shadow.log and replays them
through both the YAML engine and Gate0 CLI to verify that mismatches are reproducible.

Usage:
    python replay_shadow_case.py [path/to/policy-shadow.log] [--case N]
    
    Default: server/logs/policy-shadow.log
    --case N: Replay only the Nth mismatch (0-indexed)
"""

import json
import sys
import os
import argparse
import subprocess
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.policy import PolicyEngine
from server.gatebridge import GATEBRIDGE_CLI, _convert_to_gatebridge_request


def load_log_entries(path: str) -> list:
    """Load JSON Lines log file."""
    entries = []
    if not os.path.exists(path):
        return entries
    
    with open(path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError as e:
                print(f"Warning: Line {line_num} parse error: {e}", file=sys.stderr)
    
    return entries


def extract_mismatches(entries: list) -> list:
    """Filter to only mismatches with snapshots."""
    mismatches = []
    for entry in entries:
        if not entry.get("match", True) and "snapshot" in entry:
            mismatches.append(entry)
    return mismatches


def replay_yaml_engine(canonical_context: dict, policy_path: str) -> dict:
    """Re-run the YAML policy engine with the canonical context."""
    engine = PolicyEngine(policy_path)
    
    # Convert canonical context back to user_context format
    user_context = {
        "username": canonical_context.get("username"),
        "email": canonical_context.get("email"),
        "oidc_groups": canonical_context.get("oidc_groups", []),
        "auth_mode": canonical_context.get("auth_mode", "local"),
        "ip": canonical_context.get("source_ip"),
        "current_time": datetime.fromisoformat(canonical_context.get("now_utc_rfc3339", datetime.utcnow().isoformat())),
        "webauthn_id": canonical_context.get("webauthn_id")
    }
    
    return engine.evaluate(user_context)


def replay_gate0(canonical_context: dict, policy_path: str) -> dict:
    """Re-run Gate0 CLI with the canonical context."""
    request = _convert_to_gatebridge_request(canonical_context)
    request_json = json.dumps(request)
    
    try:
        result = subprocess.run(
            [GATEBRIDGE_CLI, "eval", policy_path, "-"],
            input=request_json,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 2:
            return {"error": result.stderr, "returncode": 2}
        
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


def replay_case(entry: dict, policy_path: str, case_num: int):
    """Replay a single mismatch case."""
    print(f"\n{'='*70}")
    print(f"Case {case_num}: {entry.get('timestamp', 'unknown')}")
    print(f"{'='*70}")
    
    # Parse snapshot
    snapshot_raw = entry.get("snapshot", "{}")
    if snapshot_raw.endswith("...[TRUNCATED]"):
        print("WARNING: Snapshot was truncated, replay may be incomplete")
        snapshot_raw = snapshot_raw.replace("...[TRUNCATED]", "}")
    
    try:
        snapshot = json.loads(snapshot_raw)
    except json.JSONDecodeError:
        print("ERROR: Could not parse snapshot")
        return False
    
    canonical_context = snapshot.get("canonical_context", {})
    
    print(f"\n## Original Logged Decisions")
    print(f"  YAML: {entry.get('yaml_decision', {}).get('policy_name', 'unknown')}")
    print(f"  Gate0: {entry.get('gate0_decision', {})}")
    print(f"  Match: {entry.get('match', 'unknown')}")
    
    print(f"\n## Canonical Context")
    print(f"  Username: {canonical_context.get('username')}")
    print(f"  Email: {canonical_context.get('email')}")
    print(f"  IP: {canonical_context.get('source_ip')}")
    print(f"  Time: {canonical_context.get('now_utc_rfc3339')}")
    print(f"  Hour: {canonical_context.get('hour_utc')}")
    print(f"  Weekday: {canonical_context.get('weekday_utc')}")
    print(f"  Business Hours: {canonical_context.get('is_business_hours')}")
    
    print(f"\n## Replay Results")
    
    # Replay YAML
    yaml_result = replay_yaml_engine(canonical_context, policy_path)
    print(f"  YAML Replay: {yaml_result.get('name', 'unknown')}")
    
    # Replay Gate0
    gate0_result = replay_gate0(canonical_context, policy_path)
    if "error" in gate0_result:
        print(f"  Gate0 Replay: ERROR - {gate0_result.get('error')}")
    else:
        print(f"  Gate0 Replay: {gate0_result}")
    
    # Check if mismatch is reproducible
    original_yaml = entry.get("yaml_decision", {}).get("policy_name")
    replay_yaml = yaml_result.get("name")
    
    if original_yaml == replay_yaml:
        print(f"\n  ✅ YAML decision matches original")
    else:
        print(f"\n  ⚠️  YAML decision differs: original={original_yaml}, replay={replay_yaml}")
    
    print()
    return True


def main():
    parser = argparse.ArgumentParser(description="GateBridge Replay Test")
    parser.add_argument("logfile", nargs="?", help="Path to policy-shadow.log")
    parser.add_argument("--case", type=int, help="Replay only case N (0-indexed)")
    parser.add_argument("--policy", default=None, help="Path to policy.yaml")
    args = parser.parse_args()
    
    # Determine log path
    if args.logfile:
        log_path = args.logfile
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_path = os.path.join(script_dir, "server", "logs", "policy-shadow.log")
    
    # Determine policy path
    if args.policy:
        policy_path = args.policy
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        policy_path = os.path.join(script_dir, "policy.yaml")
    
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(policy_path):
        print(f"Policy file not found: {policy_path}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loading: {log_path}")
    print(f"Policy: {policy_path}")
    
    entries = load_log_entries(log_path)
    mismatches = extract_mismatches(entries)
    
    print(f"Found {len(entries)} total entries, {len(mismatches)} mismatches with snapshots")
    
    if not mismatches:
        print("No mismatches to replay.")
        sys.exit(0)
    
    if args.case is not None:
        if args.case < 0 or args.case >= len(mismatches):
            print(f"Case {args.case} out of range (0-{len(mismatches)-1})")
            sys.exit(1)
        replay_case(mismatches[args.case], policy_path, args.case)
    else:
        for i, entry in enumerate(mismatches[:10]):  # Limit to first 10
            replay_case(entry, policy_path, i)
        
        if len(mismatches) > 10:
            print(f"\n... and {len(mismatches) - 10} more. Use --case N to replay specific cases.")


if __name__ == "__main__":
    main()
