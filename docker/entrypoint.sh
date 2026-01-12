#!/bin/bash
set -e

# Auto-generate CA_MASTER_PASSWORD if not set and persist it
PASSWORD_FILE="/app/data/.ca_password"

if [ -z "$CA_MASTER_PASSWORD" ]; then
    if [ -f "$PASSWORD_FILE" ]; then
        # Use existing persisted password
        export CA_MASTER_PASSWORD=$(cat "$PASSWORD_FILE")
        echo "[Ephemera] Using persisted CA master password"
    else
        # Generate new password and persist it
        export CA_MASTER_PASSWORD=$(openssl rand -base64 32)
        echo "$CA_MASTER_PASSWORD" > "$PASSWORD_FILE"
        chmod 600 "$PASSWORD_FILE"
        echo "[Ephemera] Generated new CA master password (persisted to $PASSWORD_FILE)"
        echo "[Ephemera] IMPORTANT: Back up this password for disaster recovery"
    fi
else
    echo "[Ephemera] Using CA master password from environment"
fi

# Execute the main application
exec python -u -m server.server
