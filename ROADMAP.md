# Ephemera Roadmap

This document outlines completed features, research areas, and explicit non-goals.

## ✅ Completed (v3.0.0)

### Core Infrastructure
- Zero-Trust SSH Certificate Authority
- WebAuthn-enforced certificate issuance
- TOTP MFA fallback for CLI authentication
- Tamper-evident Merkle-chained audit logs

### Access Control
- RBAC Policy Engine (YAML-based)
  - OIDC group matching
  - Email/username wildcards
  - Source IP (CIDR) restrictions
  - Time-based access windows
  - WebAuthn ID binding
- Just-In-Time Sudo via `pam_exec` integration
- Admin API security (`@require_admin` decorator)

### Operations
- Shamir encrypted backups (k-of-n recovery)
- Zero-downtime CA key rotation (active/previous/next lifecycle)
- Automated server onboarding (`ephemera server-setup`)
- Remote audit log forwarding (UDP syslog to black box)

### CLI
- `ephemera init` — SSH config setup
- `ephemera status` — Certificate and SUDO state
- `ephemera sudo-history` — Access event history
- `ephemera renew` — WebAuthn certificate renewal

---

## 🔬 Research / Optional

These items are being evaluated but are **not committed**:

- Native OpenSSH session recording (via `ForceCommand` or `script`, no MITM)
- Host audit heartbeat verification
- HSM key rotation (currently file-based only)

---

## ❌ Explicit Non-Goals

The following are **intentionally excluded** from Ephemera's scope:

| Feature | Reason |
|---------|--------|
| SSH MITM Proxy | Violates end-to-end encryption; adds attack surface |
| Custom SSH Protocol | Unnecessary complexity; native OpenSSH is sufficient |
| Cloud Dependency | Ephemera is designed for sovereign, air-gapped deployments |
| Session Replay UI | Recording research is decentralized; no central player planned |
| QR-Based Shard Recovery | JSON file shards are simpler and more portable |
| C PAM Module | `pam_exec` with Python is portable and auditable |

---

*Last updated: 2025-12-16*
