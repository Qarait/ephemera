# Security Model & Threat Assumptions — Ephemera

Ephemera is a high-assurance, sovereign SSH Certificate Authority. Consistent with its design for air-gapped and high-security environments, this document formally outlines the security model, trust boundaries, and inherent trade-offs of the system.

> [!NOTE]
> **Community Review**: We welcome feedback and adversarial critique from security researchers and infrastructure engineers. If you identify a flaw in our logic or implementation, please see our [SECURITY.md](SECURITY.md) for disclosure guidelines.

## 1. Threat Assumptions

Ephemera operates under the following adversarial assumptions:

- **Network-Level Adversary**: We assume an adversary may have full control over the network between the client and server (MITM capability). 
- **Compromised User Endpoint**: We assume that a user's workstation may be compromised at any time.
- **Custodial Collusion**: We assume that in a disaster recovery scenario, a quorum of custodians (`k` out of `n`) is required to restore the system.

## 2. Trust Boundaries

### The Ephemera Server (Trusted)
The server container is the root of trust. It holds the Master CA Key (encrypted at rest) and the Merkle-chained audit ledger. 
- **Boundary**: The server must be deployed on hardened infrastructure with minimal attack surface.
- **Enforcement**: Access to the server's control plane is protected by WebAuthn MFA.

### The Client Endpoint (Semi-Trusted / Ephemeral)
The client machine is used to request certificates. 
- **Boundary**: Certificates issued by the CA are bound to the user's identity and have a default TTL of 300 seconds (5 minutes).
- **Protection**: If the endpoint is compromised, the window of vulnerability is limited to the remaining lifetime of the active certificate.

## 3. Inherent Security Trade-offs

The following are properties of the chosen cryptographic and availability models:

### Post-Authorization Persistence
As an inherent property of time-bound credentials, a valid certificate remains authorized until its cryptographic expiry. Ephemera does not currently implement a real-time Certificate Revocation List (CRL) for issued user certificates, as the 5-minute TTL provides a sufficient decay-by-default security posture for most environments.

### Decoupled Availability
In a sovereign deployment, the CA is the single point of issuance. If the CA is unreachable, new certificates cannot be issued. However, existing sessions continue until their certificates naturally expire. This preserves availability for active workflows at the cost of immediate global revocation.

### Quorum Recovery Boundaries
Shamir's Secret Sharing (k-of-n) technically permits recovery if `k` custodians collude. This is an intended property of the model to ensure disaster recovery without a single point of failure (SPOF).

## 4. MFA Fallback Policy

Ephemera supports two MFA methods with distinct security properties:

### WebAuthn (Primary)
Hardware-backed authentication via FIDO2 keys (YubiKey, Titan, Nitrokey) or platform authenticators (TouchID, Windows Hello). WebAuthn provides:
- Phishing resistance via origin binding
- Physical presence verification
- Non-exportable private keys

### TOTP (Fallback)
Time-based One-Time Passwords are provided as a fallback for initial onboarding or environments where hardware keys are not yet deployed.

> [!IMPORTANT]
> **TOTP is not permitted for privileged operations.** The following actions require WebAuthn exclusively:
> - SUDO approval (`sudo.require_webauthn: true` in policy.yaml)
> - Certificate renewal via `/renew` endpoint
> - Admin key rotation

Organizations requiring WebAuthn-only authentication for all operations should ensure all users complete hardware key enrollment before disabling TOTP setup flows.

## 5. Lost Authenticator Recovery

If a user loses access to their registered hardware key:

1. **Admin-Assisted Re-enrollment**: An administrator with API access can clear the user's `webauthn_credentials` field from the users database, allowing them to re-enroll a new device.

2. **Quorum Recovery (Break-Glass)**: If the admin also loses access, the Shamir-protected backup can be restored by a quorum of custodians to recover the system state.

> [!TIP]
> **Best Practice**: Users should register multiple hardware keys (e.g., primary YubiKey + backup YubiKey stored securely) to avoid single points of failure.

## 6. Explicit Non-Goals

- **SSH MITM Inspection**: Ephemera does not inspect SSH traffic. It facilitates the *establishment* of a trusted connection but does not act as a proxy.
- **Password-Only Authentication**: Ephemera explicitly moves away from passwords. TOTP is provided as a fallback only; WebAuthn (FIDO2) is the primary intended authentication factor.
- **Continuous Revocation**: Real-time revocation of short-lived (5m) certificates is excluded to prevent the CA from becoming a runtime failure dependency for every single SSH packet.

## 7. Complementary Controls (What You Still Need)

Ephemera governs **who may receive access** and **for how long**. It does not monitor, inspect, or control what happens during an SSH session. A complete security posture requires additional controls:

| Control | Purpose | Examples |
|:--------|:--------|:---------|
| **Endpoint Hardening** | Reduce attack surface on client machines | EDR, disk encryption, OS patching |
| **Session Recording** | Audit what happened during a session | asciinema, Teleport session recording, or OS-level auditd |
| **Command Control** | Restrict which commands can be executed | sudo policies, rbash, SELinux/AppArmor |
| **Detection & Alerting** | Identify anomalous access patterns | SIEM integration, failed auth alerting |
| **Log Retention** | Meet compliance and forensic needs | Centralized log shipping, immutable storage |

> [!CAUTION]
> Deploying Ephemera alone does not constitute a complete SSH security program. It replaces static key management — it does not replace runtime controls or detection.

---
*Threat model and security assumptions are documented here. Feedback and critique are welcome.*
