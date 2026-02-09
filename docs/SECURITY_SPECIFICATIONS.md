# Security Technical Specifications: Ephemera

This document provides deep technical details on Ephemera's security implementation for auditors and security engineers.

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

> [!NOTE]
> **Applies to**: Both **FileCA** and **SoftHSM CA** backends.

- **RP ID / Origin**: The browser handles standard WebAuthn origin binding against the server's hostname.

### Sidecar Binding Protocol
To prevent session fixation or CSRF-driven certificate issuance, the Browser Sidecar follows this protocol:
- **Binding**: The CLI relies on the existing Cookie-based session.
- **Single-use / TTL**: Requests (like SUDO) generate a unique `request_id` (UUIDv4) valid for 300 seconds.
- **Polling / Resume**: The CLI (or sudo plugin) polls `GET /api/sudo/status/<id>`. Once the browser completes the WebAuthn challenge, the server marks that specific `request_id` as "Approved."
- **Replay Prevention**: The WebAuthn `challenge` is single-use and tied to the user's session.

> [!NOTE]
> **Applies to**: Both **FileCA** and **SoftHSM CA** backends.

### Model Hardening
- **Downgrade Prevention**: Once a WebAuthn credential is registered to an account, the server can be configured (via Policy) to reject any renewal that does not use WebAuthn.
- **Recovery**: Admin-assisted re-enrollment. Shards/Quorum for CA recovery (see `PRODUCTION_READY.md`).

## 3. SSH Certificate Profile

When signing a user certificate, Ephemera uses the following `ssh-keygen` profile:

| Field | Value | Rationale |
|:------|:------|:----------|
| **Serial (`-z`)** | `uint64` (Random) | Unique serial per cert; required for KRL-based revocation |
| **Identifier (`-I`)** | `ephemera-<uuid>` | Links certificate to audit log entry |
| **Principals (`-n`)** | List (e.g. `user,root`) | Restricted by policy based on user role |
| **Validity (`-V`)** | `+<N>s` | Short-lived (default 300s) |
| **Extensions** | Default | `permit-pty`, `permit-port-forwarding` (OOB) |
| **Critical Options** | None | Source-address restrictions are currently handled via Network-level allowlists |

> [!NOTE]
> **Applies to**: Both **FileCA** and **SoftHSM CA** backends.

## 4. CA Key Protection

### SoftHSM / PKCS#11
> **Applies to**: **SoftHSM CA** backend.
- **Command**: `ssh-keygen -D <module> -s <ca_pub> ...`
- **PIN Handling**: Passed via a temporary `SSH_ASKPASS` script which is deleted immediately after use.
- **Isolation**: The private key never touches the disk or the application memory (it remains inside SoftHSM).

### File-based CA
> **Applies to**: **FileCA** backend.

**Encryption Standard**: Fernet (Authenticated Encryption)
- **Algorithm**: AES-128 in CBC mode.
- **Integrity**: HMAC with SHA256 (using an EtM - Encrypt-then-MAC approach).
- **KDF**: PBKDF2 with SHA256 PRF.
- **Iterations**: 100,000.
- **Strength**: The `CA_MASTER_PASSWORD` is salted with 16 random bytes (`os.urandom(16)`) before key derivation.

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

> [!NOTE]
> **Applies to**: Both **FileCA** and **SoftHSM CA** backends.

---
> [!NOTE]
> For implementation details on Audit verification, see the Python verification script in [Remote-Audit-Log.md](Remote-Audit-Log.md).
