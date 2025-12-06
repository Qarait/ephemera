import yaml
import ipaddress
import os
import sys
from datetime import datetime

def parse_duration(duration_str):
    """
    Parses a duration string like '15m', '1h' into minutes.
    Returns None if parsing fails.
    """
    try:
        if duration_str.endswith('m'):
            return int(duration_str[:-1])
        elif duration_str.endswith('h'):
            return int(duration_str[:-1]) * 60
        elif duration_str.endswith('s'):
            return max(1, int(duration_str[:-1]) // 60)
        else:
            return int(duration_str)
    except:
        return None

def validate_cidr(cidr):
    try:
        ipaddress.ip_network(cidr)
        return True
    except ValueError:
        return False

def validate_time_range(time_range):
    try:
        start_str, end_str = time_range.split("-")
        datetime.strptime(start_str.strip(), "%H:%M")
        datetime.strptime(end_str.strip(), "%H:%M")
        return True
    except ValueError:
        return False

def validate_policy_file(path):
    print(f"Validating policy file: {path}")
    
    if not os.path.exists(path):
        print(f"ERROR: File not found: {path}")
        return False

    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"ERROR: Invalid YAML syntax: {e}")
        return False
    except Exception as e:
        print(f"ERROR: Could not read file: {e}")
        return False

    if not data:
        print("ERROR: Policy file is empty.")
        return False

    errors = []
    warnings = []

    # 1. Validate Default Policy
    default = data.get("default")
    if not default:
        warnings.append("Missing 'default' policy. System will use internal hardcoded defaults (sandbox, 15m).")
    else:
        if "principals" not in default:
            errors.append("Default policy missing 'principals'.")
        if "max_duration" in default:
            if parse_duration(default["max_duration"]) is None:
                errors.append(f"Default policy has invalid max_duration: {default['max_duration']}")

    # 2. Validate Policies List
    policies = data.get("policies")
    if not isinstance(policies, list):
        errors.append("'policies' must be a list.")
    else:
        for i, rule in enumerate(policies):
            rule_name = rule.get("name", f"Rule #{i+1}")
            
            # Check Principals
            if "principals" not in rule:
                errors.append(f"[{rule_name}] Missing 'principals'.")
            elif not isinstance(rule["principals"], list):
                errors.append(f"[{rule_name}] 'principals' must be a list.")

            # Check Duration
            if "max_duration" in rule:
                if parse_duration(rule["max_duration"]) is None:
                    errors.append(f"[{rule_name}] Invalid max_duration: {rule['max_duration']}")

            # Check Match Conditions
            match = rule.get("match")
            if match:
                if not isinstance(match, dict):
                    errors.append(f"[{rule_name}] 'match' must be a dictionary.")
                else:
                    # Source IP
                    if "source_ip" in match:
                        for cidr in match["source_ip"]:
                            if not validate_cidr(cidr):
                                errors.append(f"[{rule_name}] Invalid CIDR in source_ip: {cidr}")
                    
                    # Hours
                    if "hours" in match:
                        for tr in match["hours"]:
                            if not validate_time_range(tr):
                                errors.append(f"[{rule_name}] Invalid time range in hours: {tr} (Expected HH:MM-HH:MM)")

    # Report Results
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f" - {w}")

    if errors:
        print("\nERRORS FOUND:")
        for e in errors:
            print(f" - {e}")
        print("\nValidation FAILED.")
        return False
    else:
        print("\nValidation PASSED.")
        return True
