#!/usr/bin/env bash
set -e

echo "==================================================="
echo "   Pyhardin - Automated Setup Script             "
echo "==================================================="
echo ""

# Ensure we're running in root/sudo for installing system deps if needed
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script with sudo (e.g., sudo ./install.sh)"
  exit 1
fi

echo "[*] Checking system dependencies..."
apt-get update -qq

# Ensure python 3 and python venv are available
if ! command -v python3 &> /dev/null; then
    echo "[*] Installing Python3..."
    apt-get install -y python3
fi

echo "[*] Ensuring python3-venv is installed..."
apt-get install -y python3-venv python3-pip

echo "[*] Setting up Python virtual environment..."
# Drop privileges to the user running sudo for venv creation if possible
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})
VENV_DIR="$USER_HOME/.pyhardin_venv"

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "[+] Created virtual environment at $VENV_DIR"
else
    echo "[+] Virtual environment already exists at $VENV_DIR"
fi

echo "[*] Installing Pyhardin dependencies..."
# We install the tool globally into the new venv
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -e .

echo "[*] Creating global symlink for 'pyhardin' command..."
# Link the executable into /usr/local/bin to make it available system-wide
ln -sf "$VENV_DIR/bin/pyhardin" /usr/local/bin/pyhardin

echo ""
echo "==================================================="
echo " [SUCCESS] Pyhardin is now installed!              "
echo "==================================================="
echo ""
echo " You can now run the tool from anywhere by typing:"
echo "   sudo pyhardin"
echo ""
echo " Note: We recommend running it with sudo so it can "
echo " read protected configuration files (like /etc/shadow)"
echo "==================================================="
