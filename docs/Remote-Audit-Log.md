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
