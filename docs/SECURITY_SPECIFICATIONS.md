# Security Technical Specifications: Ephemera

This document provide deep technical details on Ephemera's security implementation for auditors and security engineers.

## 1. Authentication & Wire Protocols

### API Authentication
- **Mechanism**: Flask session cookies (`session`).
- **Token Storage**: CLI stores session cookies in `~/.ephemera/session.json`.
- **CSRF Protection**: Currently relies on SameSite cookie attributes; explicit CSRF tokens are not used for API endpoints.
- **Protocol**: HTTPS (mandatory for WebAuthn).

### Login Flow
1. `POST /api/login` (Username, Password, TOTP).
2. Server validates credentials + TOTP.
3. Server returns session cookie.

## 2. WebAuthn Implementation

### CLI Integration
Ephemera avoids the "Native CLI WebAuthn" complexity by using a **Browser Sidecar** pattern:
- **Authentication**: `ephemera login` uses a standard username/password/TOTP flow.
- **Sensitive Operations (Renew/Sudo)**: The CLI opens the system browser to a server-hosted page (e.g., `/renew` or `/sudo_approve.html`).
- **RP ID / Origin**: The browser handles standard WebAuthn origin binding against the server's hostname.

### model Hardening
- **Downgrade Prevention**: Once a WebAuthn credential is registered to an account, the server can be configured (via Policy) to reject any renewal that does not use WebAuthn.
- **Recovery**: Admin-assisted re-enrollment. Shards/Quorum for CA recovery (see `PRODUCTION_READY.md`).

## 3. SSH Certificate Profile

When signing a user certificate, Ephemera uses the following `ssh-keygen` profile:

| Field | Value | Rationale |
|:------|:------|:----------|
| **Serial (`-z`)** | `1` | Simplified serial management (Serial is used for revocation) |
| **Identifier (`-I`)** | `ephemera-<uuid>` | Links certificate to audit log entry |
| **Principals (`-n`)** | List (e.g. `user,root`) | Restricted by policy based on user role |
| **Validity (`-V`)** | `+<N>s` | Short-lived (default 300s) |
| **Extensions** | Default | `permit-pty`, `permit-port-forwarding` (OOB) |
| **Critical Options** | None | Source-address restrictions are currently handled via Network-level allowlists |

## 4. CA Key Protection

### SoftHSM / PKCS#11
- **Command**: `ssh-keygen -D <module> -s <ca_pub> ...`
- **PIN Handling**: Passed via a temporary `SSH_ASKPASS` script which is deleted immediately after use.
- **Isolation**: The private key never touches the disk or the application memory (it remains inside SoftHSM).

### File-based CA
- **Encryption**: AES-256-CBC via `cryptography` library.
- **Key Master Password**: Derived from `CA_MASTER_PASSWORD` environment variable.
- **Key Rotation**: Shamir-backed backups of the master secret for recovery.

## 5. Audit Ledger Specification

### Format
The audit log is a JSON-L file where each record is chained to the previous:
```json
{
  "timestamp": "ISO-8601",
  "event": "cert_issued",
  "request_id": "<uuid>",
  "prev_hash": "<sha256-of-prev>",
  "hash": "<sha256-of-this-body>"
}
```

### Verification Spec
- **Genesis**: First entry `prev_hash` is 64 zeros.
- **Integrity**: `hash` is computed over the JSON body *without* the `hash` field, with keys sorted alphabetically.
- **Continuity**: `prev_hash` of entry `N+1` must match `hash` of entry `N`.

---
> [!NOTE]
> For implementation details on Audit verification, see the Python verification script in [Remote-Audit-Log.md](Remote-Audit-Log.md).
