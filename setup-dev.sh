#!/usr/bin/env bash
# Run inside the Ubuntu VM after install: bash setup-dev.sh
set -euo pipefail

sudo apt update
sudo apt install -y nodejs npm python3 python3-pip python3-venv curl git

# Chrome uses NSS for locally trusted roots, including HTTPS inspection CAs.
if [ -d /opt/snp/host-ca ]; then
  sudo apt install -y libnss3-tools
  nssdb="$HOME/.pki/nssdb"
  [ -d "$nssdb" ] || nssdb="$HOME/.local/share/pki/nssdb"
  mkdir -p "$nssdb"
  [ -f "$nssdb/cert9.db" ] || certutil -N -d "sql:$nssdb" --empty-password
  for cert in /opt/snp/host-ca/*.crt; do
    [ -f "$cert" ] || continue
    nickname="snp-host-${cert##*/}"
    if ! certutil -L -d "sql:$nssdb" -n "$nickname" >/dev/null 2>&1; then
      certutil -A -d "sql:$nssdb" -t 'C,,' -n "$nickname" -i "$cert"
    fi
  done
fi

# Chrome
curl -fLo /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install -y /tmp/chrome.deb

# snapd seeds itself on first boot; installing before that finishes fails with "too early for operation"
sudo snap wait system seed.loaded

# The snap store sits behind round-robin addresses and a single timeout fails the whole run, so retry
snap_install() {
  for attempt in 1 2 3 4 5; do
    sudo snap install "$@" && return 0
    echo "snap install $* failed (attempt $attempt), retrying" >&2
    sleep 10
  done
  return 1
}

# Insomnia
snap_install insomnia

# VS Code
snap_install code --classic

# Docker (log out and in for the group to apply)
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker "$USER"

# Claude Code CLI (native installer, lands in ~/.local/bin)
curl -fsSL https://claude.ai/install.sh | bash
grep -q '.local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Version list: `vm-versions` any time, and printed when an interactive shell starts (terminal or ssh)
sudo install -m 755 "$(dirname "$0")/report-installed.sh" /usr/local/bin/vm-versions
grep -q vm-versions /etc/bash.bashrc || echo '[ -n "$PS1" ] && [ -z "$VM_VERSIONS_SHOWN" ] && export VM_VERSIONS_SHOWN=1 && vm-versions' | sudo tee -a /etc/bash.bashrc >/dev/null
