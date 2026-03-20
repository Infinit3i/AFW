#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo ./uninstall.sh)"
    exit 1
fi

echo "Uninstalling AFW..."

# Stop and disable service
systemctl stop afw 2>/dev/null || true
systemctl disable afw 2>/dev/null || true

# Clean up nftables
nft delete table inet afw 2>/dev/null || true

# Remove files
rm -f /usr/bin/afw
rm -f /etc/systemd/system/afw.service
systemctl daemon-reload

echo ""
echo "AFW uninstalled."
echo "Config files preserved at /etc/afw/ (remove manually if desired)"
echo ""
