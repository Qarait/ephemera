#!/bin/bash
set -e

# Configuration
BACKUP_ROOT="/app"
DATA_DIR="data"
CA_DIR="ca_store"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="ephemera_backup_${TIMESTAMP}.tar.gz"
ENCRYPTED_FILE="${BACKUP_FILE}.gpg"

# Check required env vars
if [ -z "$BACKUP_GPG_RECIPIENT" ]; then
    echo "Error: BACKUP_GPG_RECIPIENT not set."
    exit 1
fi

if [ -z "$BACKUP_DESTINATION" ]; then
    echo "Error: BACKUP_DESTINATION not set (format: user@host:/path/)."
    exit 1
fi

echo ">>> Starting Backup: ${TIMESTAMP}"

# 1. Create Tarball
echo "    Archiving ${DATA_DIR} and ${CA_DIR}..."
cd ${BACKUP_ROOT}
tar -czf /tmp/${BACKUP_FILE} ${DATA_DIR} ${CA_DIR}

# 2. Encrypt
echo "    Encrypting for ${BACKUP_GPG_RECIPIENT}..."
gpg --batch --yes --trust-model always \
    --encrypt --recipient "${BACKUP_GPG_RECIPIENT}" \
    --output /tmp/${ENCRYPTED_FILE} \
    /tmp/${BACKUP_FILE}

# 3. Transfer
echo "    Transferring to ${BACKUP_DESTINATION}..."
# Assumes SSH keys are mounted/configured in ~/.ssh or via agent
scp -o StrictHostKeyChecking=no -o BatchMode=yes \
    /tmp/${ENCRYPTED_FILE} "${BACKUP_DESTINATION}"

# 4. Cleanup
rm /tmp/${BACKUP_FILE} /tmp/${ENCRYPTED_FILE}

echo "✅ Backup Complete."
