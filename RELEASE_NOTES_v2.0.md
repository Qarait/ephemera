# Ephemera v2.0.0 – Hardware-Backed Zero-Trust SSH CA

**Release Date:** 2025-12-05

Ephemera v2 introduces "Sovereign Security" features, hardening the CA against compromise and ensuring tamper-evident audit trails. This release transforms Ephemera from a demo-grade CA into a production-ready, hardware-backed security appliance.

## 🚀 New Features

### 1. WebAuthn Certificate Renewal
- **Self-Service Renewal**: Users can now renew their SSH certificates via a web interface (`/renew`).
- **MFA-Protected**: Renewal requires WebAuthn re-authentication, preventing session hijacking.
- **Seamless UX**: CLI command `ephemera renew` automatically opens the browser and saves the new certificate.

### 2. Strict SoftHSM Backend (Hardware Mode)
- **Non-Exportable Keys**: The CA private key is generated inside the SoftHSM token and marked as non-exportable.
- **PKCS#11 Integration**: Signing operations are performed via `ssh-keygen -D`, ensuring the key never touches system memory or disk in plain text.
- **Fail-Fast Validation**: The server strictly validates HSM configuration on boot and refuses to start if the secure hardware is inaccessible.

### 3. Remote Audit Log ("Black Box")
- **Tamper-Proof Logging**: All application logs are forwarded via UDP to a remote, write-only syslog server (e.g., a Raspberry Pi).
- **Data Diode**: The architecture enforces a one-way flow, preventing an attacker on the CA server from deleting or modifying past logs.

### 4. Automated Encrypted Backups
- **Nightly Archives**: A sidecar service automatically archives the database and CA store every 24 hours.
- **GPG Encryption**: Backups are encrypted with a public GPG key before leaving the container.
- **Off-Site Transfer**: Encrypted archives are securely transferred to a remote destination via SCP.

### 5. Enhanced CLI & Configuration
- **Auto-Config**: `ephemera init` now intelligently detects the OS and configures `~/.ssh/config` safely.
- **Status Command**: `ephemera status` provides a comprehensive health check of the local environment, including agent status and certificate validity.

## 📦 Upgrade Guide

### Docker
1.  Pull the latest changes.
2.  Update `docker-compose.yml` with the new `logging` and `backup` configurations.
3.  Rebuild and restart:
    ```bash
    docker compose up --build -d
    ```

### CLI
Update the client CLI:
```bash
pip install --upgrade ephemera-cli
```
