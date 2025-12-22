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

## 4. Explicit Non-Goals

- **SSH MITM Inspection**: Ephemera does not inspect SSH traffic. It facilitates the *establishment* of a trusted connection but does not act as a proxy.
- **Password-Only Authentication**: Ephemera explicitly moves away from passwords. TOTP is provided as a fallback only; WebAuthn (FIDO2) is the primary intended authentication factor.
- **Continuous Revocation**: Real-time revocation of short-lived (5m) certificates is excluded to prevent the CA from becoming a runtime failure dependency for every single SSH packet.

---
*Threat model and security assumptions are documented here. Feedback and critique are welcome.*
