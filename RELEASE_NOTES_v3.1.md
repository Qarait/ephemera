# Ephemera v3.1.0 – Zero-Trust SSH with JIT Sudo

**Release Date:** 2025-12-16

This release marks Ephemera's transition into a production-grade, sovereign Zero-Trust SSH authority with just-in-time privilege escalation and disaster recovery guarantees.

---

## Highlights

### ⚡ Just-in-Time Sudo (WebAuthn Protected)
- Replaces sudo passwords with explicit MFA approval
- PAM-based (`pam_exec`) integration, no SSH MITM
- Central audit trail for all privilege escalation

### 🎯 Policy Engine (RBAC)
- Declarative `policy.yaml`
- Matches on OIDC groups, email, username, CIDR, time-of-day, WebAuthn ID
- Determines SSH principals, TTL, and sudo permissions

### 🛡️ Sovereign Disaster Recovery
- AES-256-GCM encrypted backups
- Shamir Secret Sharing for password recovery
- Works with FileCA and SoftHSM-backed CA

### 🔄 Zero-Downtime CA Key Rotation
- Multi-CA trust model
- Seamless signer rotation
- Old keys retained for verification

### 📜 Tamper-Evident Audit Logging
- Hash-chained (Merkle-style) logs
- One-way remote syslog ("Black Box") support

---

## Design Principles

- No cloud dependencies
- No SSH MITM
- Native OpenSSH certificates
- Air-gap compatible by design

---

See `ARCHITECTURE.md` and `ROADMAP.md` for full details.
