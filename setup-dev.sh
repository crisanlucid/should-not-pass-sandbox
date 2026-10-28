#!/usr/bin/env bash
# Run inside the Ubuntu VM after install: bash setup-dev.sh
set -euo pipefail

sudo apt update
sudo apt install -y nodejs npm python3 python3-pip python3-venv curl git

# Chrome
curl -fLo /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install -y /tmp/chrome.deb

# Insomnia
sudo snap install insomnia

# VS Code
sudo snap install code --classic

# Docker (log out and in for the group to apply)
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker "$USER"

# Claude Code CLI (native installer, lands in ~/.local/bin)
curl -fsSL https://claude.ai/install.sh | bash
grep -q '.local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Version list: `vm-versions` any time, and printed when an interactive shell starts (terminal or ssh)
sudo install -m 755 "$(dirname "$0")/report-installed.sh" /usr/local/bin/vm-versions
grep -q vm-versions /etc/bash.bashrc || echo '[ -n "$PS1" ] && [ -z "$VM_VERSIONS_SHOWN" ] && export VM_VERSIONS_SHOWN=1 && vm-versions' | sudo tee -a /etc/bash.bashrc >/dev/null
