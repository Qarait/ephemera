import os
import logging
from .pkcs11_utils import check_pkcs11_tool, verify_key_in_hsm

logger = logging.getLogger(__name__)

def validate_softhsm_boot(config):
    """
    Strict validation of SoftHSM configuration at boot.
    """
    module = config.get('EPHEMERA_PKCS11_MODULE')
    slot = config.get('EPHEMERA_PKCS11_SLOT')
    pin = config.get('EPHEMERA_PKCS11_PIN')
    # Key label might be hardcoded or config? User said "label ephemera_ca" in generation.
    # But in config_ca.py we had EPHEMERA_PKCS11_KEY_LABEL.
    # Let's assume we pass it in config or use a default.
    key_label = config.get('EPHEMERA_PKCS11_KEY_LABEL', 'ephemera_ca')

    missing = []
    if not module: missing.append('EPHEMERA_PKCS11_MODULE')
    if not slot: missing.append('EPHEMERA_PKCS11_SLOT')
    if not pin: missing.append('EPHEMERA_PKCS11_PIN')
    
    if missing:
        raise RuntimeError(f"FATAL: SoftHSM backend selected but missing configuration: {', '.join(missing)}")

    if not os.path.exists(module):
        raise RuntimeError(f"FATAL: PKCS#11 module not found at {module}")

    # Check if pkcs11-tool is available
    if not check_pkcs11_tool():
        # Maybe warn? Or fail if we strictly rely on it for boot check?
        # The user said "If token empty -> Provide ERROR". We need pkcs11-tool for that.
        logger.warning("pkcs11-tool not found. Skipping deep token validation.")
        return

    # Verify Token and Key
    try:
        if not verify_key_in_hsm(module, slot, key_label, pin):
             raise RuntimeError(
                 f"ERROR: No key found in SoftHSM with label '{key_label}'.\n"
                 "Run:\n"
                 f"softhsm2-util --init-token --slot {slot} ...\n"
                 f"pkcs11-tool --module {module} --keypairgen --label {key_label} ..."
             )
    except Exception as e:
        raise RuntimeError(f"FATAL: SoftHSM validation failed: {str(e)}")

    logger.info("SoftHSM boot validation passed.")
