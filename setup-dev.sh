#!/usr/bin/env bash
# Run inside the Ubuntu VM after install: bash setup-dev.sh
set -euo pipefail
ARCH=$(dpkg --print-architecture)

sudo apt update
sudo apt install -y nodejs npm python3 python3-pip python3-venv curl git

# Cloud images need a desktop; the VirtualBox ISO already includes it.
if [ "${SNP_DESKTOP:-0}" = 1 ]; then
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ubuntu-desktop-minimal
  sudo systemctl set-default graphical.target
fi

# Chrome
curl -fLo /tmp/chrome.deb "https://dl.google.com/linux/direct/google-chrome-stable_current_${ARCH}.deb"
sudo apt install -y /tmp/chrome.deb

# Insomnia
if [ "$ARCH" = arm64 ]; then
  echo "Insomnia: skipped (no official Linux ARM64 desktop package)."
else
  sudo snap install insomnia
fi

# VS Code
if [ "$ARCH" = arm64 ]; then
  curl -fLo /tmp/code.deb https://update.code.visualstudio.com/latest/linux-deb-arm64/stable
  echo 'code code/add-microsoft-repo boolean true' | sudo debconf-set-selections
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/code.deb
else
  sudo snap install code --classic
fi

# Docker (log out and in for the group to apply)
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker "$USER"

# Claude Code CLI (native installer, lands in ~/.local/bin)
curl -fsSL https://claude.ai/install.sh | bash
grep -q '.local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

node -v; python3 --version; google-chrome --version
if [ "$ARCH" = arm64 ]; then code --version; else snap list insomnia; fi
"$HOME/.local/bin/claude" --version
