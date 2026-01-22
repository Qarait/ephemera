# Changelog

All notable changes to this project will be documented in this file.

## [3.3.0] - 2026-01-21

### Added
- **GateBridge Differential Fuzzer**: A proactive hardening tool that generates random policies and requests to verify semantic parity between evaluation engines.
- **Shadow Evaluation Plane**: Real-time parallel evaluation of production traffic using the Gate0 engine (observational only).
- **1,000,000 Iteration Soak Test**: Verified Zero Mismatches across 1 million fuzzing iterations, providing a "Gold Standard" reliability signal.
- **Mismatch Forensic Tools**: Automated capture of divergence artifacts for rapid triage.

### Security
- Hardened policy engine via differential fuzzing.
- Verified absence of logic inversions or edge-case panics in the shadow plane.

---

## [3.2.0] – 2026-01-01

### Added
- **Experimental: Trust Budgeting (Opt-in)**: Added an opt-in governance primitive for limiting cumulative privileged authority at certificate issuance time. See [docs/trust_budgeting.md](docs/trust_budgeting.md).

### Notes
- Trust Budgeting is experimental and may change or be removed.
- Disabled by default; must be explicitly enabled in policy.yaml.

---

## [3.1.0] – 2025-12-16

### Added
- Just-in-Time Sudo with WebAuthn approval (PAM-based)
- Policy Engine (RBAC via policy.yaml)
- Shamir Secret Sharing disaster recovery
- Zero-downtime CA key rotation
- Admin-protected API endpoints
- Sudo visibility in `ephemera status`

### Security
- WebAuthn enforced for all privileged actions
- Tamper-evident audit logs
- Sovereign backup model (no cloud KMS)

### Notes
- This is the first fully production-grade Ephemera release.

---

## [3.0.0] - 2025-12-16

### Added
- **Just-In-Time Sudo**: Privilege escalation requires WebAuthn MFA approval via `pam_exec` integration.
- **Policy Engine (RBAC)**: YAML-based access control with matching by OIDC groups, emails, usernames, source IP (CIDR), time windows, and WebAuthn IDs.
- **Shamir Encrypted Backups**: CA keys and database encrypted with AES-256-GCM, password split into Shamir shards.
- **Zero-Downtime Key Rotation**: Multi-key lifecycle (active/previous/next) for seamless CA key rotation.
- **Admin API Security**: `@require_admin` decorator with API key (`X-Admin-Token`) and session-based auth.
- **CLI SUDO Visibility**: `ephemera sudo-history` and `ephemera status` show SUDO access state.
- **Server Onboarding**: `ephemera server-setup` generates bootstrap scripts for SSH targets.

### Security
- Policy engine enforces max certificate duration per role.
- All admin actions (rotate, revoke, policy reload) are audit logged.
- Default dev secrets documented with production override requirements.

---

## [2.0.0] - 2025-12-05

### Added
- **WebAuthn Certificate Renewal**: New `/renew` endpoint and CLI `ephemera renew` command for self-service certificate renewal protected by MFA.
- **SoftHSM Integration**: CA private keys are now stored in a simulated HSM (SoftHSMv2) via PKCS#11, ensuring keys are non-exportable and operations are performed in hardware (simulated).
- **Remote Audit Log**: Syslog data is now forwarded via UDP to a remote "black box" sink (e.g., Raspberry Pi) for tamper-evident logging.
- **Automated Backups**: New `backup` service in Docker Compose that encrypts and transfers data nightly.
- **CLI Enhancements**:
    - `ephemera init`: Auto-detects OS and configures `~/.ssh/config`.
    - `ephemera status`: Checks local agent, certificate validity, and server connectivity.
- **Documentation**: Added comprehensive guides for Remote Audit Log, SoftHSM setup, and Release Assets.

### Changed
- **Architecture**: Shifted to a Zero-Trust model with hardware-backed keys and strict logging.
- **Docker Compose**: Updated to include `syslog` and `backup` services.

### Security
- Enforced non-exportable keys for CA.
- Implemented one-way data diode logic for audit logs.
