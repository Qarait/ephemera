# Production Readiness Guide: Ephemera

This guide outlines the critical operational steps required to transition an Ephemera deployment from "Development/POC" to "Production."

## 1. Hardening & Deployment

### TLS & Reverse Proxy
Ephemera's WebAuthn support requires a secure context (HTTPS). 
- **Requirement**: Run behind a reverse proxy (Nginx, Caddy, or HAProxy) with valid TLS certificates.
- **Security Header**: Ensure `Strict-Transport-Security` is enabled.

### Network Isolation
- **VPN/Allowlist**: Expose the Ephemera API (`port 3000`) only via VPN or strict IP allowlists.
- **Admin Endpoints**: Lockdown `/api/admin/*` and `/api/ca/rotate` to internal CIDR blocks if possible.

### Rate Limiting (Default Parameters)
Ephemera includes in-memory rate limiting with the following defaults (configurable in `server/core.py`):
- **Login**: 5 attempts per 15 minutes (30-minute lockout).
- **Cert Request**: 20 requests per 60 minutes.

## 2. SSH Server-Side Rollout

To enroll a target server into the Ephemera trust domain:

### Canonical `sshd_config` Snippet
```conf
# 1. Trust the Ephemera CA
TrustedUserCAKeys /etc/ssh/ephemera/ca_key.pub

# 2. Enable Revocation Checks
RevokedKeys /etc/ssh/ephemera/revoked.krl

# 3. Disable Static Passwords
PasswordAuthentication no
ChallengeResponseAuthentication no

# 4. Enable Pubkey (for Certificates)
PubkeyAuthentication yes
```

### Principals Mapping
Ensure your OIDC/Policy identities match the principals allowed on the target server (e.g., `root`, `ubuntu`, or a shared service account). Use `ephemera server-setup` to automate this.

## 3. CA Key Rotation Runbook

To maintain security hygiene, rotate the CA key periodically (e.g., every 90 days).

1. **Generate Next Key**: 
   `POST /api/ca/next` (Admin only)
   This prepares the next key for propagation without making it active.
2. **Propagate**: 
   Update `TrustedUserCAKeys` on all target servers to include *both* the active and the next public key.
3. **Execute Rotation**: 
   `POST /api/ca/rotate` (Admin only)
   Wait for at least the `max_cert_duration` of your longest-lived policy before removing the old key from target servers.

## 4. Disaster Recovery (Backup Custody)

Ephemera uses Shamir's Secret Sharing for CA key backups.

- **Storage**: Store the encrypted backup (`ephemera_backup.enc`) in your standard infrastructure backup location.
- **Custody**: Split the decryption password into `n` shards (e.g., 5) with a threshold `k` (e.g., 3).
- **Distribution**: Give shards to separate individuals (Custodians) across different teams/regions. **Never store shards on the same infrastructure being backed up.**

## 5. Audit & Integrity

### Remote Sink
Forward logs to a "Black Box" UDP sink to prevent log wiping during a server compromise. See [Remote Audit Log Guide](Remote-Audit-Log.md).

### Daily Integrity Check
Run the standalone verification script (documented in §4 of the Audit Log Guide) as a daily cron job.
```bash
python scripts/verify_audit.py /path/to/audit.json
```

---
> [!IMPORTANT]
> **Production checklist complete?** Review the [Security Model](SECURITY_MODEL.md) once more to ensure your threat assumptions align with this deployment profile.
