# Ephemera v1.1 Release Notes

**"The Zero-Trust Renewal Update"**

This release transforms Ephemera from a prototype into a security-hardened SSH CA. It introduces critical workflow tools (`init`, `status`) and enforces strict WebAuthn presence checks for certificate renewal.

## 🚀 New Features

### 1. WebAuthn-Enforced Renewal
- **Zero-Trust Presence Check**: Certificate renewal now *requires* a fresh WebAuthn assertion (touching your YubiKey).
- **Short-Lived Certificates**: Renewed certificates have a 15-minute TTL, enforcing frequent presence verification.
- **Browser Ceremony**: The `ephemera renew` command automatically opens your browser to complete the secure handshake.

### 2. Automated Configuration (`ephemera init`)
- **One-Command Setup**: Automatically configures `~/.ssh/config` with a safe `Include` directive.
- **Idempotent**: Can be run multiple times without corrupting your config.
- **Rollback**: Includes `--rollback` to cleanly remove all Ephemera configuration.

### 3. System Status (`ephemera status`)
- **Health Check**: Instantly diagnose your SSH environment.
- **Checks**:
    - WebAuthn identity binding.
    - Local certificate validity (expiration, principals).
    - SSH Agent status (is the key loaded?).
    - Configuration integrity.

## 🛡️ Security Improvements

- **Expired Challenge Rejection**: Server now strictly enforces a 3-minute window for WebAuthn challenges.
- **Replay Attack Protection**: Challenges are single-use and immediately deleted after verification.
- **Credential Binding**: Assertions are validated against the specific credential ID, preventing cross-key attacks.
- **Issuance Autonomy**: Certificate issuance logic is now strictly isolated from the login flow.

## 🐛 Bug Fixes

- Fixed `login.html` form submission to use POST (was incorrectly defaulting to GET).
- Fixed CSS linking issues in `login.html` and `renew.html`.
- Standardized CLI file paths to `~/.ssh/ephemera` for consistency.

## 📦 Upgrade Instructions

1.  Pull the latest code.
2.  Rebuild the server: `docker compose up --build -d`
3.  Update your CLI: `pip install .` (from the root directory)
4.  Run `ephemera init` to update your SSH configuration path.
