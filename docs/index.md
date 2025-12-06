# Ephemera

**Zero-Trust SSH Certificate Authority**

Ephemera is a modern, secure, and air-gap-friendly SSH Certificate Authority designed to replace static keys with short-lived, identity-bound certificates.

---

## 🚀 Key Features

### 🔐 Zero-Trust Architecture
No long-lived private keys on user devices. Certificates are issued just-in-time and expire automatically.

### 🛡️ WebAuthn MFA
Phishing-resistant authentication using hardware keys (YubiKey) or biometrics (TouchID/FaceID).

### 📜 Tamper-Evident Audit
Every action is recorded in a local, hash-chained ledger. History cannot be rewritten without detection.

### 🐳 Dockerized & Portable
Fully self-contained. Runs on any machine with Docker. No external cloud dependencies.

---

## 📦 Get Started

Check out the [GitHub Repository](https://github.com/SSH-Pearl/ephemera) to get started.

### Quick Run
```bash
git clone https://github.com/SSH-Pearl/ephemera.git
cd ephemera
docker compose up --build
```

---

## 📚 Documentation
- [Architecture Overview](../ARCHITECTURE.md)
- [GitHub Setup](GITHUB_SETUP.md)

