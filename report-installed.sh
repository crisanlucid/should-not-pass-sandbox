#!/usr/bin/env bash
# Lists the tools setup-dev.sh installs, with versions. Runs inside the VM: bash report-installed.sh
export PATH="$HOME/.local/bin:$PATH"
row() { printf '%-16s %s\n' "$1" "${2:-NOT INSTALLED}"; }
v() { "$@" 2>/dev/null | head -1; }   # first line of a version command, empty if it fails
snapv() { snap list "$1" 2>/dev/null | awk 'NR==2 {print $2" ("$4")"}'; }

echo "Installed in this VM:"
row "Ubuntu" "$(. /etc/os-release && echo "$PRETTY_NAME")"
row "Node.js" "$(v node -v)"
row "npm" "$(v npm -v)"
row "Python" "$(v python3 --version | awk '{print $2}')"
row "pip" "$(v pip3 --version | awk '{print $2}')"
row "Git" "$(v git --version | awk '{print $3}')"
row "curl" "$(v curl --version | awk '{print $2}')"
row "Google Chrome" "$(v google-chrome --version | sed 's/Google Chrome //; s/ *$//')"
if [ "$(dpkg --print-architecture)" = arm64 ]; then
  row "VS Code" "$(v code --version)"
  row "Insomnia" "SKIPPED (no official Linux ARM64 desktop package)"
else
  row "VS Code" "$(snapv code)"
  row "Insomnia" "$(snapv insomnia)"
fi
row "Docker" "$(v docker --version | sed 's/Docker version //; s/,.*//')"
row "Docker Compose" "$(v docker compose version | sed 's/Docker Compose version //')"
row "Claude Code" "$(v claude --version)"
