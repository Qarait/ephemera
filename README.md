# Ephemera — Zero-Trust SSH Certificate Authority

[![CI Status](https://github.com/ephemerassh/ephemera/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ephemerassh/ephemera/actions/workflows/ci.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11722/badge)](https://www.bestpractices.dev/projects/11722)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/e51bc11fac8a4f63a61b07200581bdd2)](https://app.codacy.com/gh/Qarait/ephemera/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
![Release](https://img.shields.io/github/v/release/ephemerassh/ephemera)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Fuzz Soak](https://img.shields.io/badge/Fuzz_Soak-1M_Iterations_Passed-success)](./docs/audit/million_fuzz.log)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-yellow.svg)

**Ephemera** is a lightweight, self-hosted SSH Certificate Authority designed to enforce Zero-Trust access for infrastructure. It replaces static SSH keys with short-lived certificates, integrates hardware-backed WebAuthn MFA, and maintains cryptographically verifiable audit trails.

> [!NOTE]
> **Canonical Source**: [Codeberg](https://codeberg.org/Qarait/ephemera)  
> **GitHub Mirror**: [GitHub](https://github.com/Qarait/ephemera) (for availability and hosting)

## High-Level Architecture

```mermaid
graph LR
    subgraph Client["User (Operator)"]
        SSH["SSH Client"]
        HW["Hardware Key<br/>WebAuthn / YubiKey"]
    end

    subgraph Auth["Authentication Boundary"]
        MFA["WebAuthn MFA<br/><i>Human presence required</i>"]
        OIDC["OIDC<br/><i>Optional</i>"]
    end

    subgraph CA["Ephemera SSH Certificate Authority"]
        CORE["Self-hosted CA<br/>Air-gap capable"]
        POLICY["Policy Engine<br/><i>Governance at issuance</i>"]
        BUDGET["Trust Budgeting<br/><i>Optional</i>"]
    end

    subgraph Targets["Target Servers"]
        NATIVE["Native OpenSSH<br/>TrustedUserCAKeys"]
        NOAGENT["No agents<br/>No SSH proxy"]
    end

    subgraph Audit["Audit & Recovery"]
        LOG["Tamper-Evident<br/>Audit Log"]
        BACKUP["Encrypted Backups<br/>Shamir Recovery"]
    end

    Client --> Auth
    Auth -->|"Short-lived cert"| CA
    CA -->|"Certificate expires<br/>automatically"| Targets
    CA -.->|"Post-fact integrity"| Audit

    style Auth fill:#e8f5e9,stroke:#2e7d32
    style CA fill:#e3f2fd,stroke:#1565c0
    style Audit fill:#fff3e0,stroke:#ef6c00
```

**What Ephemera does:** Governs who may receive access and for how long.  
**What Ephemera does NOT do:** Runtime monitoring, MITM proxying, command inspection.  
**Enforcement:** Entirely within native OpenSSH — no Ephemera agent on target servers.  
**Key rotation:** Not needed — certificates expire automatically.

## What Ephemera Is

Ephemera is a self-hosted SSH Certificate Authority built on native OpenSSH features.
It replaces long-lived SSH keys with short-lived certificates issued just-in-time,
with explicit physical presence and auditable privilege escalation.

It is designed for teams that want centralized SSH governance without
MITM proxies, custom protocols, or cloud dependencies.

## What Ephemera Is Not

**Traffic Guarding**: Ephemera does not act as an SSH proxy or MITM gateway.
**Native Integration**: It is not a PAM replacement.
**Zero Monitoring**: It does not perform runtime monitoring or behavior analysis.
**Sovereign Hosting**: It is a self-hosted tool, not a cloud service.
**Explicit Focus**: It is not a SIEM or general detection platform.

## Project Status

Core SSH CA functionality: **Production-ready**  
Trust Budgeting: **Experimental (opt-in, subject to change)**

The experimental features are clearly isolated and disabled by default.

## Why Ephemera?

Traditional SSH relies on long-lived private keys spread across laptops and servers. Once a key leaks, access persists until you discover it and rotate keys everywhere. Ephemera replaces static keys with short-lived certificates that expire automatically, shrinking the window of misuse from months to minutes.

## Positioning

### Best For
**Sovereign Deployments**: Teams requiring full ownership of their CA without external cloud dependencies.
**Air-Gapped Environments**: Designed to operate without outbound internet access once deployed.
**Minimal Overhead**: Organizations that need strong SSH security without the complexity of managing a full secrets platform.

### Not For
**Enterprise IAM**: If you require deep integration with complex AD/LDAP hierarchies, Teleport or HashiCorp Vault are better suited.
**Managed Services**: Ephemera is strictly self-hosted and does not offer a SaaS variant.

## Key Capabilities

**Just-in-Time Access**: Certificates expire in minutes (default 5m), reducing the window of opportunity for stolen credentials.
**WebAuthn Enforcement**: Certificate issuance requires physical MFA (FIDO2) interaction via YubiKey or TouchID.
**Sovereign Recovery**: Encrypted backups are protected via Shamir's Secret Sharing, requiring a quorum to restore.
**Verifiable Audit**: All CA actions are logged to a Merkle-chained ledger for tamper-evident history.
**Granular RBAC**: A YAML-based policy engine defines access based on roles, resources, and conditions.

![Sudo Hang](assets/screenshots/sudo_hang.png)

## Experimental: Trust Budgeting (Opt-in)

Ephemera includes an experimental, opt-in governance primitive called Trust Budgeting.

Trust Budgeting limits cumulative privileged authority at certificate issuance time by treating access as a finite, visible resource. Each certificate issuance consumes an explicit budget. When the budget is exhausted, normal issuance stops until the budget resets or a separate emergency (break-glass) path is used.

This mechanism:
**Issuance Logic**: Operates only at certificate issuance time.
**Zero Agents**: Introduces no runtime monitoring or agents.
**Opt-in Model**: Disabled by default.
**Technical Limit**: Not a security guarantee.

Trust Budgeting is experimental and may change or be removed.

**Documentation**: [docs/trust_budgeting.md](docs/trust_budgeting.md)

## Quick Start

**Goal:** Issue your first SSH certificate in under 5 minutes.

### 1. Start Ephemera

```bash
# Clone and start
git clone https://github.com/Qarait/ephemera.git
cd ephemera
docker compose up -d
```

> **Note:** CA master password is auto-generated and persisted on first run.  
> For production, set `CA_MASTER_PASSWORD` in a `.env` file before starting.

### 2. Access the Dashboard

Open [http://localhost:3000](http://localhost:3000) in your browser.

**Default credentials:**
- **Username:** `admin`
- **Password:** Check Docker logs:
  ```bash
  docker compose logs ephemera | grep "Password:"
  ```

### 3. Issue Your First Certificate

1. Complete WebAuthn MFA setup (requires hardware key or TouchID)
2. Click "Request Certificate"
3. Your certificate is valid for 5 minutes

---

**Alternative Compose Files:**
**Development Context**: docker-compose.dev.yml includes local builds and syslog.
**End-to-End Testing**: docker-compose.test.yml includes a dedicated SSH target server.

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
**Architecture**: See ARCHITECTURE.md for design details.
**Security**: See SECURITY_MODEL.md for threat assumptions and trust boundaries.
**Guides**: See docs/ for additional integration guides.

## Security
Please see [SECURITY.md](SECURITY.md) for responsible disclosure information.

Looking to contribute? Check out our [Small Tasks for New Contributors](CONTRIBUTING.md#small-tasks-for-new-contributors).

> [!TIP]
> **Threat model and security assumptions are documented [here](SECURITY_MODEL.md). Feedback and critique are welcome.**
