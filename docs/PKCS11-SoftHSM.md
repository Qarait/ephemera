# Ephemera – Using SoftHSM as a PKCS#11 CA Backend

## 1. Overview

Ephemera supports two Certificate Authority backends:

*   **FileCA (Default)**
    *   CA key stored on disk
    *   Easiest to use
    *   Good for testing / local dev

*   **SoftHsmCA (Advanced)**
    *   CA key stored inside a virtual Hardware Security Module
    *   Key never leaves the HSM
    *   Supports PKCS#11
    *   Ideal for air-gapped or high-security deployments

SoftHSM gives you “HSM-level behavior” without cloud dependencies and without hardware cost.

## 2. Installation

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install softhsm2
```

### macOS (Homebrew)
```bash
brew install softhsm
```

### Windows

SoftHSM is not officially packaged for Windows.
Use WSL2 + Ubuntu:

```bash
wsl --install
```

Then inside WSL:

```bash
sudo apt update
sudo apt install softhsm2
```

Ephemera can still run on Windows while using SoftHSM inside WSL for signing.

## 3. Initialize SoftHSM

### Choose token location

Create a data directory:

```bash
mkdir -p ~/softhsm
export SOFTHSM2_CONF=~/softhsm/softhsm2.conf
echo "directories.tokendir = $HOME/softhsm/tokens" > $SOFTHSM2_CONF
```

### Create a token (HSM slot)
```bash
softhsm2-util --init-token \
    --slot 0 \
    --label "EphemeraCA" \
    --pin 1234 \
    --so-pin 0000
```

**Result:**
*   Slot: 0
*   Token Label: EphemeraCA
*   User PIN: 1234

## 4. Generate CA Key inside SoftHSM (Recommended)

This avoids writing private keys to disk.

Generate EC keypair:

```bash
pkcs11-tool \
    --module /usr/lib/softhsm/libsofthsm2.so \
    --keypairgen \
    --key-type EC:prime256v1 \
    --slot 0 \
    --label "EphemeraCAKey" \
    --pin 1234
```

You now have:
*   Token Label: EphemeraCA
*   Key Label: EphemeraCAKey
*   Key Type: EC P-256

**Key is stored only in HSM.**
No private key file exists anywhere on disk.

## 5. Using the Key with ssh-keygen

OpenSSH supports PKCS#11 via:

```bash
ssh-keygen -D <module>
```

To list keys:

```bash
ssh-keygen -D /usr/lib/softhsm/libsofthsm2.so
```

To sign a certificate:

```bash
ssh-keygen \
    -D /usr/lib/softhsm/libsofthsm2.so \
    -s "pkcs11:token=EphemeraCA;object=EphemeraCAKey" \
    -I user-cert \
    -n user \
    -V +5m \
    user_ed25519.pub
```

The `-s` argument now references the PKCS#11 URI, not a file.

Ephemera’s `SoftHsmCA` backend automates this invocation.

## 6. Ephemera Configuration

Set environment variables before running the server:

```bash
export EPHEMERA_CA_BACKEND=softhsm
export EPHEMERA_PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
export EPHEMERA_PKCS11_TOKEN_LABEL=EphemeraCA
export EPHEMERA_PKCS11_KEY_LABEL=EphemeraCAKey
export EPHEMERA_PKCS11_PIN=1234
```

Start server:

```bash
python server/server.py
```

**Expected behavior:**
*   If all env vars exist, Ephemera initializes `SoftHsmCA`.
*   If any are missing → server aborts with a clear startup error (“SoftHSM is not configured correctly”).

## 7. Directory Overview

**SoftHSM files:**
```text
~/softhsm/
    softhsm2.conf
    tokens/
        <HSM slot files>
```

**Ephemera client files remain:**
```text
~/.ssh/ephemera/
    id_ed25519
    id_ed25519-cert.pub
    config
```

No CA key ever appears in this folder when SoftHSM is enabled.

## 8. Troubleshooting

### "No suitable keys found in PKCS#11 module"
Likely causes:
*   Incorrect token label
*   Incorrect key label
*   Wrong PIN
*   Wrong PKCS#11 module path

### "The provider returned an error"
Run diagnostics:
```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -L
```
You should see your token and key listed.

### "ssh-keygen: invalid PKCS#11 URI"
URI must match exactly:
`pkcs11:token=<LABEL>;object=<LABEL>`

## 9. Security Notes

*   ✔ Private key never touches disk
*   ✔ Key operations require PIN
*   ✔ Works offline / air-gapped
*   ✔ No dependency on AWS, GCP, Azure
*   ✔ Upgrade path to real hardware HSMs / YubiKeys with zero code changes

This is the cleanest, safest, most philosophically consistent CA backend for Ephemera.
