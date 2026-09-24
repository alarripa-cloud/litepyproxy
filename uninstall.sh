#!/bin/sh
set -eu

SERVICE_USER="liteproxy"
INSTALL_DIR="/opt/litepyproxy"
SERVICE_FILE="/etc/systemd/system/litepyproxy.service"
CONFIG_FILE="/etc/litepyproxy.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this uninstaller with sudo."
    exit 1
fi

echo "=== Uninstalling LitePyProxy ==="

systemctl disable --now litepyproxy 2>/dev/null || true
rm -f "$SERVICE_FILE"
rm -f "$CONFIG_FILE"
systemctl daemon-reload

rm -rf "$INSTALL_DIR"

if id "$SERVICE_USER" >/dev/null 2>&1; then
    userdel "$SERVICE_USER"
fi

echo "LitePyProxy removed."
