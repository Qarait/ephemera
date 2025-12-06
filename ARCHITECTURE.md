# Architecture

Ephemera uses a Zero-Trust model where no long-lived SSH keys exist on user devices.

## Components

1.  **Flask Server**: Handles auth, MFA, and certificate signing.
2.  **OpenSSH CA**: Signs user public keys with a generated CA key.
3.  **WebAuthn**: Provides phishing-resistant MFA.
4.  **Audit Ledger**: Hash-chained log of all issuance events.

## Security

-   **CA Key**: Encrypted at rest, never leaves the container.
-   **Audit**: Tamper-evident ledger.
-   **Ephemeral**: Certificates expire in minutes.
