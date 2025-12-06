#!/bin/bash
# Setup script for Ephemera Black Box (Raspberry Pi)
# Run this on the Raspberry Pi as root (sudo).
# Usage: sudo ./setup_blackbox.sh <EPHEMERA_IP>

EPHEMERA_IP=$1

if [ -z "$EPHEMERA_IP" ]; then
    echo "Error: You must specify the IP address of the Ephemera server."
    echo "Usage: sudo ./setup_blackbox.sh <EPHEMERA_IP>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo ">>> [1/4] Installing dependencies..."
apt-get update
apt-get install -y rsyslog ufw

echo ">>> [2/4] Configuring rsyslog (UDP 514)..."
# Create config for UDP reception
cat <<EOF > /etc/rsyslog.d/99-ephemera-blackbox.conf
\$ModLoad imudp
\$UDPServerRun 514
\$template BlackBoxFormat,"%timestamp% %hostname% %syslogtag% %msg%\n"
local1.*    -/var/log/ephemera/blackbox.log
EOF

# Create log directory
mkdir -p /var/log/ephemera
chown syslog:adm /var/log/ephemera

systemctl restart rsyslog
echo "    rSyslog configured to write to /var/log/ephemera/blackbox.log"

echo ">>> [3/4] Configuring Firewall (UFW)..."
# Reset to defaults
ufw --force reset

# Default Policies
ufw default deny incoming
ufw default deny outgoing

# Allow Syslog UDP
ufw allow 514/udp

# Block SSH from Ephemera Server (The "Black Box" requirement)
ufw deny from $EPHEMERA_IP to any port 22

# Allow SSH from ANYWHERE ELSE (so you don't lock yourself out right now)
# In a real high-security setup, restrict this to your admin workstation IP!
ufw allow ssh

echo ">>> [4/4] Enabling Firewall..."
ufw --force enable

echo "========================================================"
echo "✅ Black Box Setup Complete."
echo "--------------------------------------------------------"
echo "Logs:     /var/log/ephemera/blackbox.log"
echo "Security: SSH from $EPHEMERA_IP is BLOCKED."
echo "          Outbound traffic is BLOCKED."
echo "========================================================"
