#!/bin/sh
set -eu

APP="litepyproxy"
SERVICE_USER="liteproxy"
INSTALL_DIR="/opt/litepyproxy"
SERVICE_FILE="/etc/systemd/system/litepyproxy.service"
CONFIG_FILE="/etc/litepyproxy.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer with sudo."
    exit 1
fi

echo "=== Installing LitePyProxy ==="

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "Creating system user: $SERVICE_USER"
    useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
else
    echo "User $SERVICE_USER already exists."
fi

echo "Installing application into $INSTALL_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" "$INSTALL_DIR"
install -m 0644 litepyproxy.py "$INSTALL_DIR/litepyproxy.py"
install -m 0644 requirements.txt "$INSTALL_DIR/requirements.txt"

echo "Creating Python virtual environment"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

echo "Installing systemd service"
install -m 0644 systemd/litepyproxy.service "$SERVICE_FILE"

if [ ! -f "$CONFIG_FILE" ]; then
    printf "Public URL path [/proxy]: "
    read -r PUBLIC_PATH
    PUBLIC_PATH=${PUBLIC_PATH:-/proxy}
    PUBLIC_PATH="/$(printf '%s' "$PUBLIC_PATH" | sed 's#^/*##; s#/*$##')"
    printf 'LITEPYPROXY_BASE_PATH=%s\n' "$PUBLIC_PATH" > "$CONFIG_FILE"
    chmod 0644 "$CONFIG_FILE"
    echo "Configured public path: $PUBLIC_PATH/"
else
    echo "Keeping existing configuration: $CONFIG_FILE"
fi

systemctl daemon-reload
systemctl enable litepyproxy
systemctl restart litepyproxy

echo
echo "=== LitePyProxy installed ==="
systemctl --no-pager status litepyproxy
