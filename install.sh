#!/bin/bash
set -e

echo ""
echo " █████╗ ███████╗██╗    ██╗"
echo "██╔══██╗██╔════╝██║    ██║"
echo "███████║█████╗  ██║ █╗ ██║"
echo "██╔══██║██╔══╝  ██║███╗██║"
echo "██║  ██║██║     ╚███╔███╔╝"
echo "╚═╝  ╚═╝╚═╝      ╚══╝╚══╝"
echo "  Application Firewall Installer"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo ./install.sh)"
    exit 1
fi

# Ensure rustup/cargo bin is in PATH (sudo often strips it)
REAL_HOME=$(eval echo "~${SUDO_USER:-$USER}")
if [ -d "$REAL_HOME/.cargo/bin" ]; then
    export PATH="$REAL_HOME/.cargo/bin:$PATH"
fi

# Check dependencies
for cmd in nft cargo rustup; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd is required but not found"
        exit 1
    fi
done

echo "[1/4] Building eBPF programs..."
sudo -u "${SUDO_USER:-$USER}" cargo xtask build-ebpf --release

echo "[2/4] Building userspace binary..."
sudo -u "${SUDO_USER:-$USER}" cargo build --release -p afw

echo "[3/4] Installing..."
install -Dm755 target/release/afw /usr/bin/afw
install -Dm644 config/afw.toml /etc/afw/afw.toml
install -dm755 /etc/afw/conf.d
for f in config/conf.d/*.toml; do
    install -Dm644 "$f" "/etc/afw/conf.d/$(basename "$f")"
done
install -Dm644 systemd/afw.service /etc/systemd/system/afw.service
install -dm755 /var/log/afw

echo "[4/4] Reloading systemd..."
systemctl daemon-reload

echo ""
echo "AFW installed successfully!"
echo ""
echo "  Start:   systemctl start afw"
echo "  Enable:  systemctl enable afw"
echo "  Status:  afw status"
echo ""
