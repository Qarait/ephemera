# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Ephemera, please do **NOT** open a public issue.

Instead, please report it responsibly:

1.  Email us at **security@ephemera.dev** (or open a draft security advisory on GitHub if enabled).
2.  Provide a detailed description of the vulnerability and steps to reproduce it.
3.  We will acknowledge your report within 48 hours and work with you to resolve the issue.

## Production Security Requirements

> **⚠️ IMPORTANT**: Ephemera uses fail-safe defaults that are NOT suitable for production.

Before deploying to production, you **MUST** set these environment variables:

| Variable | Default (Dev Only) | Production Requirement |
|----------|-------------------|------------------------|
| `FLASK_SECRET_KEY` | `dev_secret_key` | Random 32+ character string |
| `CA_MASTER_PASSWORD` | `ephemera-dev-secret` | Strong passphrase (16+ characters) |
| `ADMIN_API_KEY` | (none) | Random token for admin API access |

**Fail-Fast Behavior**: If default secrets are detected in production, the application will log warnings at startup. We strongly recommend adding startup checks in your deployment pipeline to reject default credentials.

## Security Features

Ephemera is designed with security in mind:
-   **Zero-Trust**: No long-lived keys.
-   **MFA Enforcement**: WebAuthn/TOTP required.
-   **Audit Logging**: Tamper-evident hash chain.
-   **Encryption**: CA keys encrypted at rest.
-   **JIT Sudo**: Privilege escalation requires fresh MFA approval.
-   **RBAC Policy Engine**: Fine-grained access control.

Thank you for helping keep Ephemera secure!

