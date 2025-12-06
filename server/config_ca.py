import os

# CA Backend Selection: "file" (default) or "softhsm"
CA_BACKEND = os.getenv("EPHEMERA_CA_BACKEND", "file")

# PKCS#11 Configuration (for SoftHSM)
PKCS11_MODULE = os.getenv("EPHEMERA_PKCS11_MODULE", "")
PKCS11_SLOT = os.getenv("EPHEMERA_PKCS11_SLOT", "")
PKCS11_KEY_LABEL = os.getenv("EPHEMERA_PKCS11_KEY_LABEL", "ephemera_ca")
PKCS11_PIN = os.getenv("EPHEMERA_PKCS11_PIN", "")
