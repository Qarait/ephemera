# Ephemera — Zero-Trust SSH Certificate Authority

![Release](https://img.shields.io/github/v/release/ephemerassh/ephemera)
![License](https://img.shields.io/github/license/ephemerassh/ephemera)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey)
![CI Status](https://github.com/ephemerassh/ephemera/actions/workflows/ci.yml/badge.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-yellow.svg)

**Ephemera** is a sovereign, air-gapped SSH Certificate Authority that enforces **Zero Trust** principles for your infrastructure. It eliminates static SSH keys, enforces MFA for every session, and provides tamper-proof audit trails.

> [!NOTE]
> **Canonical Source**: [Codeberg](https://codeberg.org/Qarait1/ephemera)  
> **GitHub Mirror**: [GitHub](https://github.com/Qarait/ephemera) (for availability and hosting)

![Architecture Diagram](assets/diagrams/ephemera_v2_architecture.png)

## 🌟 Killer Features

### 🔐 Just-in-Time Access
No more permanent keys. Certificates expire in **5 minutes** by default. Developers request access only when needed.

### 👆 WebAuthn MFA Enforcement
Every SSH session requires a physical touch (YubiKey, TouchID). Phishing-resistant authentication is baked in.

### 🛡️ Sovereign Disaster Recovery
**Shamir's Secret Sharing** splits your encrypted backup password into physical shards. No single person can compromise the CA, but a quorum can restore it.

### 📜 Tamper-Proof Audit Logs
All actions are logged to a **Merkle-chained** ledger. Logs are immutable and can be verified cryptographically.

### ⚡ Just-in-Time Sudo
Privilege escalation (`sudo`) is no longer static. It requires a fresh MFA approval and is logged centrally.

![Sudo Hang](assets/screenshots/sudo_hang.png)

## Quick Start

### 1. Server Setup (Docker)

**Prerequisites:** Docker and Docker Compose.

1.  **Start the service:**
    ```bash
    docker compose up --build -d
    ```

2.  **Access the Dashboard:**
    Open [http://localhost:3000](http://localhost:3000) in your browser.

3.  **Login:**
    -   **Username:** `admin`
    -   **Password:** (Check the Docker logs for the initial one-time password)
        ```bash
        docker compose logs ephemera | grep "Password:"
        ```

### 2. Client Setup (The Magic)

```bash
# Install the CLI
pip install ephemera-cli  # (Coming soon to PyPI)

# Initialize your SSH config
ephemera init

# Login to the CA
ephemera login

# Issue your first certificate
ephemera renew

# Check your status
ephemera status

# Connect securely!
ssh user@your-server
```

## Disaster Recovery (Encrypted Backup)

Ephemera provides a secure backup mechanism that encrypts your critical data (CA keys, database) with a random password, and then splits that password into Shamir shards. This ensures that no single person can restore the backup, but a quorum can.

### Create Backup
```bash
# Create encrypted backup and split password into 5 shards (threshold 3)
ephemera backup-create --k 3 --n 5 --out-dir ./backup
```
This produces:
- `ephemera_backup.enc` (The encrypted archive)
- `backup_shard_1_of_5.json`, etc. (The password shards)

**Note:** Store the shards in separate, secure locations. Store the encrypted backup file safely (it is useless without the shards).

### Restore Backup
```bash
# Restore using the encrypted file and any 3 shards
ephemera backup-restore --backup ./backup/ephemera_backup.enc --shards ./backup/backup_shard_1_of_5.json ./backup/backup_shard_2_of_5.json ./backup/backup_shard_4_of_5.json --out-dir ./restored
```

## Configuration Example (`policy.yaml`)

Ephemera uses a powerful YAML-based policy engine for Role-Based Access Control (RBAC).

```yaml
# Define Roles
roles:
  developer:
    can_request_cert: true
    max_cert_duration: 300  # 5 minutes
    allowed_principals: ["dev-user"]
    
  admin:
    can_request_cert: true
    max_cert_duration: 3600 # 1 hour
    allowed_principals: ["root", "admin"]
    can_approve_sudo: true

# Define Rules
rules:
  # Developers can only access dev servers
  - role: developer
    resource: "dev-*"
    action: "ssh"
    effect: allow

  # Admins can access everything with MFA
  - role: admin
    resource: "*"
    action: "ssh"
    effect: allow
    conditions:
      mfa_required: true
```

## Documentation
- See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.
- See [SECURITY_MODEL.md](SECURITY_MODEL.md) for threat assumptions and trust boundaries.
- See [docs/](docs/) for additional guides.

## Security
Please see [SECURITY.md](SECURITY.md) for responsible disclosure information.

> [!TIP]
> **Threat model and security assumptions are documented [here](SECURITY_MODEL.md). Feedback and critique are welcome.**
