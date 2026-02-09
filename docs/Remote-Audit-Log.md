# Remote Audit Log (Black Box) Setup

To ensure a tamper-evident audit trail, Ephemera is configured to forward logs to a remote "Black Box" server (e.g., a Raspberry Pi) via UDP. This server must be configured as a **receive-only sink** with strict network isolation.

## 1. Ephemera Configuration (Sender)

In `docker-compose.yml`, the `ephemera` service is configured to send logs to the Black Box:

```yaml
logging:
  driver: syslog
  options:
    syslog-address: "udp://192.168.1.50:514"
```

## 2. Black Box Configuration (Receiver)

**Target Device**: Raspberry Pi (or similar) at `192.168.1.50`.

### Syslog Configuration (`/etc/rsyslog.conf`)

Configure `rsyslog` to accept UDP traffic and write to a dedicated file:

```conf
# Enable UDP reception
$ModLoad imudp
$UDPServerRun 514

# All received logs go to a write-only file
$template BlackBoxFormat,"%timestamp% %hostname% %syslogtag% %msg%\n"
local1.*    -/var/log/ephemera/blackbox.log
```

Restart rsyslog:
```bash
sudo systemctl restart rsyslog
```

### Network Security (Firewall)

The Black Box must be isolated to prevent compromise spreading from the Ephemera server.

**1. Deny SSH from Ephemera**
Prevent the Ephemera server from accessing the Black Box via SSH:
```bash
sudo ufw deny from <Ephemera-IP> to any port 22
```

**2. Block Outbound Traffic**
Ensure the Black Box cannot exfiltrate logs (data diode behavior):
```bash
sudo ufw default deny outgoing
```

**3. Allow UDP Syslog**
```bash
sudo ufw allow 514/udp
```

## 3. Security Model

```text
       Ephemera Server
       (Compromised?)  
             |
             | UDP (fire-and-forget)
             v
     ┌────────────────────┐
     │  Black Box Logger  │
     │  (Pi, no SSH back) │
     └────────────────────┘
```

**Attacker Constraints:**
*   **Cannot wipe logs**: Logs are stored off-host immediately.
*   **Cannot connect to Pi**: SSH is blocked from the source.
*   **Cannot influence storage**: The flow is one-way (UDP).

## 4. Audit Chain Verification

Ephemera's audit log is a Merkle-style hash chain. Each entry contains:
- `prev_hash`: SHA256 hash of the previous entry
- `hash`: SHA256 of the current entry (excluding the `hash` field itself)

### Trust Anchor (Genesis)

The first entry in the chain uses a genesis anchor of `0000000000000000000000000000000000000000000000000000000000000000` (64 zeros) as its `prev_hash`. This is the root of the chain.

### Verification Methods

**Via API (requires session):**
```bash
curl -X POST http://localhost:3000/api/audit/verify \
  -H "Cookie: session=<your-session>" 
```

**Via Python (standalone):**
```python
import json, hashlib

def verify_audit_file(path):
    prev_hash = "0" * 64
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if not line.strip(): continue
            entry = json.loads(line)
            stored_hash = entry.pop('hash', None)
            if entry.get('prev_hash') != prev_hash:
                print(f"CHAIN BREAK at line {i+1}")
                return False
            calculated = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest()
            if calculated != stored_hash:
                print(f"INTEGRITY FAILURE at line {i+1}")
                return False
            prev_hash = stored_hash
    print(f"Verified {i+1} entries successfully")
    return True
```

### Truncation Detection

To detect if entries have been deleted from the local log:

1. **Compare entry count** between Black Box and local log
2. **Compare head hash** — the most recent `hash` on both systems should match
3. **Periodic anchoring** — push the latest `hash` to external WORM storage (S3 Glacier, tape, or signed git tag)

> [!TIP]
> **Recommended Pattern**: Schedule a daily job that reads the last hash from the local audit log and appends it to an external, append-only location. Any truncation will cause a mismatch on the next comparison.

### Future Enhancement

Signed checkpoints (a hash signed by the CA key and pushed to multiple locations) are planned for a future release to provide cryptographic non-repudiation of the audit state.
