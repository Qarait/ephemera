import yaml
import fnmatch
import os
import logging
import ipaddress
from datetime import datetime

class PolicyEngine:
    def __init__(self, path):
        self.path = path
        self.default = {"principals": ["sandbox"], "max_duration": "15m"}
        self.policies = []
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            print(f"WARNING: Policy file not found at {self.path}. Using default fallback.")
            return

        try:
            with open(self.path, "r") as f:
                data = yaml.safe_load(f)
                if not data:
                    print(f"WARNING: Policy file {self.path} is empty.")
                    return

                self.default = data.get("default", self.default)
                self.policies = data.get("policies", [])
                print(f"Policy Engine: Loaded {len(self.policies)} policies from {self.path}")
        except Exception as e:
            print(f"CRITICAL: Failed to load policy file: {e}")
            raise e # Fail fast

    def reload(self):
        """Reloads the policy file from disk."""
        print(f"Policy Engine: Reloading policies from {self.path}...")
        self.load()

    def evaluate(self, user_context):
        """
        Evaluates the user context against loaded policies.
        
        user_context = {
          "username": "...",
          "email": "...",
          "oidc_groups": [...],
          "auth_mode": "local" | "oidc",
          "ip": "1.2.3.4",
          "current_time": datetime_obj,
          "webauthn_id": "..."
        }
        """
        username = user_context.get("username") or ""
        email = user_context.get("email") or ""
        oidc_groups = set(user_context.get("oidc_groups", []))
        user_ip = user_context.get("ip")
        # Ensure we have a datetime object, default to UTC now
        current_time = user_context.get("current_time", datetime.utcnow())
        webauthn_id = user_context.get("webauthn_id")

        for rule in self.policies:
            match = rule.get("match", {})
            matched = False

            # 1. Match OIDC Groups (if any match)
            if "oidc_groups" in match:
                rule_groups = set(match["oidc_groups"])
                if oidc_groups & rule_groups:
                    matched = True

            # 2. Match Emails (Exact or Wildcard?) 
            # The spec said "emails: ['cto@company.com']" (exact) and "*@contractor.com" (wildcard)
            # Let's support fnmatch for emails too for flexibility
            if not matched and "emails" in match:
                for pattern in match["emails"]:
                    if fnmatch.fnmatch(email, pattern):
                        matched = True
                        break

            # 3. Match Local Usernames (Wildcard)
            if not matched and "local_usernames" in match:
                for pattern in match["local_usernames"]:
                    if fnmatch.fnmatch(username, pattern):
                        matched = True
                        break

            # 4. Match Source IP (CIDR)
            if matched and "source_ip" in match and user_ip:
                ip_matched = False
                try:
                    u_ip = ipaddress.ip_address(user_ip)
                    for cidr in match["source_ip"]:
                        if u_ip in ipaddress.ip_network(cidr):
                            ip_matched = True
                            break
                except ValueError:
                    pass # Invalid IP in context or policy
                
                if not ip_matched:
                    matched = False

            # 5. Match Time (Hours)
            if matched and "hours" in match:
                time_matched = False
                now_time = current_time.time()
                for time_range in match["hours"]:
                    try:
                        start_str, end_str = time_range.split("-")
                        start_time = datetime.strptime(start_str.strip(), "%H:%M").time()
                        end_time = datetime.strptime(end_str.strip(), "%H:%M").time()
                        
                        if start_time <= end_time:
                            if start_time <= now_time <= end_time:
                                time_matched = True
                                break
                        else: # Crosses midnight
                            if now_time >= start_time or now_time <= end_time:
                                time_matched = True
                                break
                    except ValueError:
                        pass # Invalid time format
                
                if not time_matched:
                    matched = False

            # 6. Match WebAuthn ID
            if matched and "webauthn_ids" in match:
                if not webauthn_id or webauthn_id not in match["webauthn_ids"]:
                    matched = False

            if matched:
                return {
                    "name": rule.get("name", "Unknown"),
                    "principals": rule.get("principals", []),
                    "max_duration": rule.get("max_duration", "15m")
                }

        # No match found, return default
        return {
            "name": "Default",
            "principals": self.default.get("principals", []),
            "max_duration": self.default.get("max_duration", "15m")
        }

def parse_duration(duration_str):
    """
    Parses a duration string like '15m', '1h' into minutes.
    Defaults to 15 minutes if parsing fails.
    """
    try:
        if duration_str.endswith('m'):
            return int(duration_str[:-1])
        elif duration_str.endswith('h'):
            return int(duration_str[:-1]) * 60
        elif duration_str.endswith('s'):
            return max(1, int(duration_str[:-1]) // 60) # Minimum 1 minute
        else:
            return int(duration_str) # Assume minutes
    except:
        return 15
