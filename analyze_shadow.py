#!/usr/bin/env python3
"""
GateBridge Mismatch Analyzer — Phase 2 Edition

Parses policy-shadow.log and produces:
- Divergence statistics
- Semantic gap clustering (CIDR, time range, fnmatch, unknown)
- Context-aware heuristics
- Time-series bucketing
- CSV export for deeper analysis

Usage:
    python analyze_shadow.py [path/to/policy-shadow.log] [--csv output.csv] [--json]
    
    Default: server/logs/policy-shadow.log
"""

import json
import sys
import os
import csv
import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any


# --- Semantic Gap Categories ---
class SemanticGap:
    CIDR = "cidr"              # Simplified CIDR matching
    TIME_RANGE = "time_range"  # Overnight or edge cases
    FNMATCH = "fnmatch"        # Wildcard pattern matching
    OIDC_GROUPS = "oidc"       # Group membership logic
    WEBAUTHN = "webauthn"      # WebAuthn ID matching
    EFFECT = "effect"          # Allow vs deny (most serious)
    UNKNOWN = "unknown"        # Cannot determine


@dataclass
class MismatchDetail:
    """Detailed info about a single mismatch."""
    timestamp: str
    suspected_gap: str
    yaml_policy: Optional[str]
    gate0_reason: int
    context: Dict[str, Any]
    raw_entry: Dict[str, Any]


@dataclass
class MismatchSummary:
    total_entries: int = 0
    matches: int = 0
    mismatches: int = 0
    
    # Semantic gap clusters
    gap_clusters: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Root cause categories (legacy)
    effect_mismatch: int = 0
    policy_name_mismatch: int = 0
    reason_code_mismatch: int = 0
    
    # Context patterns
    oidc_related: int = 0
    email_related: int = 0
    ip_related: int = 0
    time_related: int = 0
    webauthn_related: int = 0
    
    # Time-series buckets (hourly)
    hourly_buckets: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Detailed mismatch records
    mismatch_details: List[MismatchDetail] = field(default_factory=list)
    
    def divergence_rate(self) -> float:
        if self.total_entries == 0:
            return 0.0
        return (self.mismatches / self.total_entries) * 100


def parse_log_file(path: str) -> List[Dict]:
    """Parse JSON Lines log file."""
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


def detect_semantic_gap(entry: Dict) -> str:
    """
    Heuristically detect which semantic gap caused the mismatch.
    
    Logic:
    1. If effects differ (allow vs deny) -> EFFECT
    2. If IP was in context and non-trivial -> CIDR
    3. If time was in context -> TIME_RANGE
    4. If email patterns were involved -> FNMATCH
    5. If OIDC groups were involved -> OIDC_GROUPS
    6. If WebAuthn was involved -> WEBAUTHN
    7. Otherwise -> UNKNOWN
    """
    gate0 = entry.get("gate0_decision", {})
    ref = entry.get("reference_decision", {})
    context = entry.get("context", {})
    stats = entry.get("stats", {})
    
    # Effect mismatch is most serious
    if gate0.get("effect") != ref.get("effect"):
        return SemanticGap.EFFECT
    
    # Check context fields to guess which matcher failed
    ip = context.get("ip", "")
    
    # CIDR: non-localhost IP with CIDR-like patterns
    if ip and ip != "127.0.0.1" and ip != "localhost":
        # Heuristic: if IP has dots and isn't obviously simple
        if "." in ip:
            return SemanticGap.CIDR
    
    # Time range: if current_time was provided
    if context.get("current_time") or entry.get("yaml_decision", {}).get("hours"):
        return SemanticGap.TIME_RANGE
    
    # OIDC groups
    if context.get("oidc_groups"):
        return SemanticGap.OIDC_GROUPS
    
    # Email (fnmatch patterns)
    if context.get("email") and "*" in str(entry.get("yaml_decision", {})):
        return SemanticGap.FNMATCH
    
    # WebAuthn
    if context.get("webauthn_id"):
        return SemanticGap.WEBAUTHN
    
    return SemanticGap.UNKNOWN


def get_hour_bucket(timestamp: str) -> str:
    """Extract hour bucket from ISO timestamp."""
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:00")
    except:
        return "unknown"


def analyze_entry(entry: Dict, summary: MismatchSummary):
    """Analyze a single log entry and update summary."""
    summary.total_entries += 1
    
    # Time-series bucketing
    timestamp = entry.get("timestamp", "")
    hour_bucket = get_hour_bucket(timestamp)
    summary.hourly_buckets[hour_bucket] += 1
    
    if entry.get("match", True):
        summary.matches += 1
        return
    
    summary.mismatches += 1
    
    # Detect semantic gap
    gap = detect_semantic_gap(entry)
    summary.gap_clusters[gap] += 1
    
    # Legacy categorization
    yaml_decision = entry.get("yaml_decision", {})
    gate0_decision = entry.get("gate0_decision", {})
    reference_decision = entry.get("reference_decision", {})
    context = entry.get("context", {})
    
    gate0_effect = gate0_decision.get("effect", "unknown")
    ref_effect = reference_decision.get("effect", "unknown")
    
    if gate0_effect != ref_effect:
        summary.effect_mismatch += 1
    elif yaml_decision.get("policy_name") != reference_decision.get("policy_name"):
        summary.policy_name_mismatch += 1
    else:
        summary.reason_code_mismatch += 1
    
    # Context pattern analysis
    if context.get("oidc_groups"):
        summary.oidc_related += 1
    if context.get("email"):
        summary.email_related += 1
    if context.get("ip") and context.get("ip") != "127.0.0.1":
        summary.ip_related += 1
    if context.get("webauthn_id"):
        summary.webauthn_related += 1
    
    # Store detailed record
    summary.mismatch_details.append(MismatchDetail(
        timestamp=timestamp,
        suspected_gap=gap,
        yaml_policy=yaml_decision.get("policy_name"),
        gate0_reason=gate0_decision.get("reason_code", -1),
        context=context,
        raw_entry=entry
    ))


def print_report(summary: MismatchSummary, entries: List[Dict]):
    """Print analysis report."""
    print("=" * 70)
    print("GateBridge Shadow Evaluation Report — Phase 2")
    print("=" * 70)
    print()
    
    # Overview
    print("## Overview")
    print(f"  Total evaluations:  {summary.total_entries}")
    print(f"  Matches:            {summary.matches}")
    print(f"  Mismatches:         {summary.mismatches}")
    print(f"  Divergence rate:    {summary.divergence_rate():.2f}%")
    print()
    
    if summary.mismatches == 0:
        print("✅ No divergences detected. Gate0 is semantically equivalent.")
        print()
        print("## Time-Series (Hourly)")
        for bucket in sorted(summary.hourly_buckets.keys())[-10:]:
            print(f"  {bucket}: {summary.hourly_buckets[bucket]} evaluations")
        return
    
    # Semantic Gap Clustering (NEW)
    print("## Semantic Gap Clustering")
    print("  (Suspected root cause based on context heuristics)")
    print()
    for gap, count in sorted(summary.gap_clusters.items(), key=lambda x: -x[1]):
        pct = (count / summary.mismatches) * 100
        bar = "█" * int(pct / 5)
        print(f"  {gap:12} {count:4} ({pct:5.1f}%) {bar}")
    print()
    
    # Root cause breakdown (legacy)
    print("## Root Cause Breakdown")
    print(f"  Effect mismatch (allow/deny):  {summary.effect_mismatch}")
    print(f"  Policy name mismatch:          {summary.policy_name_mismatch}")
    print(f"  Reason code mismatch:          {summary.reason_code_mismatch}")
    print()
    
    # Context patterns
    print("## Context Patterns in Mismatches")
    print(f"  OIDC-related:    {summary.oidc_related}")
    print(f"  Email-related:   {summary.email_related}")
    print(f"  IP-related:      {summary.ip_related}")
    print(f"  WebAuthn-related: {summary.webauthn_related}")
    print()
    
    # Time-series (last 10 hours)
    if summary.hourly_buckets:
        print("## Time-Series (Last 10 Hours)")
        sorted_buckets = sorted(summary.hourly_buckets.keys())[-10:]
        for bucket in sorted_buckets:
            count = summary.hourly_buckets[bucket]
            mismatches_in_hour = sum(
                1 for d in summary.mismatch_details 
                if get_hour_bucket(d.timestamp) == bucket
            )
            if count > 0:
                rate = (mismatches_in_hour / count) * 100
                print(f"  {bucket}: {count:4} evals, {mismatches_in_hour:3} mismatches ({rate:.1f}%)")
        print()
    
    # Sample mismatches by gap type
    print("## Sample Mismatches (by gap type)")
    shown_gaps = set()
    for detail in summary.mismatch_details[:10]:
        if detail.suspected_gap not in shown_gaps:
            shown_gaps.add(detail.suspected_gap)
            print(f"\n  --- {detail.suspected_gap.upper()} ---")
            print(f"  Timestamp:   {detail.timestamp}")
            print(f"  YAML Policy: {detail.yaml_policy or 'default'}")
            print(f"  Gate0 Code:  {detail.gate0_reason}")
            print(f"  Context:     user={detail.context.get('username', '?')}, ip={detail.context.get('ip', '?')}")
    print()
    
    # Recommendations
    print("## Recommendations")
    if summary.effect_mismatch > 0:
        print("  🚨 CRITICAL: Effect mismatches detected — Gate0 disagrees on allow/deny")
    if summary.gap_clusters.get(SemanticGap.CIDR, 0) > 0:
        print("  ⚠️  CIDR mismatches detected — upgrade to full bit-mask CIDR matching")
    if summary.gap_clusters.get(SemanticGap.TIME_RANGE, 0) > 0:
        print("  ⚠️  Time range mismatches — check overnight range handling")
    if summary.gap_clusters.get(SemanticGap.FNMATCH, 0) > 0:
        print("  ⚠️  fnmatch mismatches — verify wildcard semantics")
    if summary.gap_clusters.get(SemanticGap.UNKNOWN, 0) > summary.mismatches * 0.3:
        print("  🔍 Many unknown gaps — need deeper investigation")
    if summary.divergence_rate() < 1.0:
        print("  ✅ Divergence rate under 1% — approaching production readiness")
    elif summary.divergence_rate() < 5.0:
        print("  🔶 Divergence rate under 5% — focus on top gap clusters")
    else:
        print("  ❌ Divergence rate above 5% — significant translation issues")


def export_csv(summary: MismatchSummary, output_path: str):
    """Export mismatch details to CSV for deeper analysis."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'timestamp', 'suspected_gap', 'yaml_policy', 'gate0_reason',
            'username', 'email', 'ip', 'oidc_groups', 'webauthn_id'
        ])
        for d in summary.mismatch_details:
            writer.writerow([
                d.timestamp,
                d.suspected_gap,
                d.yaml_policy or 'default',
                d.gate0_reason,
                d.context.get('username', ''),
                d.context.get('email', ''),
                d.context.get('ip', ''),
                ','.join(d.context.get('oidc_groups', [])) if d.context.get('oidc_groups') else '',
                d.context.get('webauthn_id', '')
            ])
    print(f"Exported {len(summary.mismatch_details)} mismatches to {output_path}")


def export_json(summary: MismatchSummary):
    """Export summary as JSON for machine consumption."""
    output = {
        "overview": {
            "total_entries": summary.total_entries,
            "matches": summary.matches,
            "mismatches": summary.mismatches,
            "divergence_rate": summary.divergence_rate()
        },
        "gap_clusters": dict(summary.gap_clusters),
        "root_cause": {
            "effect_mismatch": summary.effect_mismatch,
            "policy_name_mismatch": summary.policy_name_mismatch,
            "reason_code_mismatch": summary.reason_code_mismatch
        },
        "context_patterns": {
            "oidc_related": summary.oidc_related,
            "email_related": summary.email_related,
            "ip_related": summary.ip_related,
            "webauthn_related": summary.webauthn_related
        },
        "hourly_buckets": dict(summary.hourly_buckets)
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="GateBridge Mismatch Analyzer")
    parser.add_argument("logfile", nargs="?", help="Path to policy-shadow.log")
    parser.add_argument("--csv", metavar="FILE", help="Export mismatches to CSV")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of report")
    args = parser.parse_args()
    
    # Determine log path
    if args.logfile:
        log_path = args.logfile
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_path = os.path.join(script_dir, "server", "logs", "policy-shadow.log")
    
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}", file=sys.stderr)
        print("Usage: python analyze_shadow.py [path/to/policy-shadow.log]", file=sys.stderr)
        sys.exit(1)
    
    if not args.json:
        print(f"Analyzing: {log_path}")
        print()
    
    entries = parse_log_file(log_path)
    
    if not entries:
        if args.json:
            print('{"error": "No entries found"}')
        else:
            print("No entries found in log file.")
        sys.exit(0)
    
    summary = MismatchSummary()
    for entry in entries:
        analyze_entry(entry, summary)
    
    if args.json:
        export_json(summary)
    else:
        print_report(summary, entries)
    
    if args.csv:
        export_csv(summary, args.csv)


if __name__ == "__main__":
    main()
