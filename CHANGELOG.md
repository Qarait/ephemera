# Changelog

All notable changes to this project will be documented in this file.

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
