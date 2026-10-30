#!/usr/bin/env bash
# Point the guest at the host egress proxy. Run inside the VM as user dev; asks for the sudo password.
#   bash setup-guest-proxy.sh [proxy-ca.pem [host-ca.crt ...]]
# Over SSH use a terminal: ssh -t dev@192.168.56.101 'bash setup-guest-proxy.sh'
set -euo pipefail
P=http://192.168.56.1:3128
NP=localhost,127.0.0.1,::1
S() { sudo "$@"; }
T=$(mktemp -d)

# system-wide env (login sessions, services reading /etc/environment)
grep -viE '^(http|https|no)_proxy=' /etc/environment > $T/env || true
cat >> $T/env <<E
http_proxy=$P
https_proxy=$P
HTTP_PROXY=$P
HTTPS_PROXY=$P
no_proxy=$NP
NO_PROXY=$NP
E
S install -m644 $T/env /etc/environment

# apt
printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' $P $P > $T/apt
S install -m644 $T/apt /etc/apt/apt.conf.d/95proxy

# snap (VS Code, Insomnia)
S snap set system proxy.http=$P proxy.https=$P

# Docker daemon
printf '[Service]\nEnvironment="HTTP_PROXY=%s" "HTTPS_PROXY=%s" "NO_PROXY=%s"\n' $P $P $NP > $T/docker
S mkdir -p /etc/systemd/system/docker.service.d
S install -m644 $T/docker /etc/systemd/system/docker.service.d/http-proxy.conf
S systemctl daemon-reload
# docker is installed later by setup-dev.sh on a fresh VM; it reads the drop-in when it starts
systemctl cat docker.service >/dev/null 2>&1 && S systemctl restart docker

# Chrome policy
echo '{"ProxyMode":"fixed_servers","ProxyServer":"192.168.56.1:3128","ProxyBypassList":"localhost;127.0.0.1"}' > $T/chrome
S mkdir -p /etc/opt/chrome/policies/managed
S install -m644 $T/chrome /etc/opt/chrome/policies/managed/proxy.json

# user level: git, npm, pip. Plain files, because git and npm are not installed yet on a fresh VM (setup-dev.sh installs them)
grep -qs "proxy = $P" ~/.gitconfig || printf '[http]\n\tproxy = %s\n[https]\n\tproxy = %s\n' $P $P >> ~/.gitconfig
grep -qs "^proxy=$P" ~/.npmrc || printf 'proxy=%s\nhttps-proxy=%s\n' $P $P >> ~/.npmrc
mkdir -p ~/.config/pip
printf '[global]\nproxy = %s\n' $P > ~/.config/pip/pip.conf

# Claude Code: placeholder token (the proxy swaps in the real one) and the proxy CA, only if a CA file is given
if [ -n "${1:-}" ]; then
  S mkdir -p /opt/snp
  cat "$1" > "$T/node-ca.pem"
  shift
  if [ "$#" -gt 0 ]; then
    S mkdir -p /opt/snp/host-ca
    for cert in "$@"; do
      S install -m644 "$cert" "/opt/snp/host-ca/${cert##*/}"
      S install -m644 "$cert" "/usr/local/share/ca-certificates/snp-host-${cert##*/}"
      cat "$cert" >> "$T/node-ca.pem"
    done
    S update-ca-certificates
    # Existing Go daemons cache their root pool; reload after adding public roots.
    for service in snapd docker; do
      if systemctl cat "$service.service" >/dev/null 2>&1; then
        S systemctl try-restart "$service.service"
      fi
    done
  fi
  S install -m644 "$T/node-ca.pem" /opt/snp/ca.pem
  grep -vE '^(CLAUDE_CODE_OAUTH_TOKEN|NODE_EXTRA_CA_CERTS)=' /etc/environment > $T/env2 || true
  printf 'CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-placeholder\nNODE_EXTRA_CA_CERTS=/opt/snp/ca.pem\n' >> $T/env2
  S install -m644 $T/env2 /etc/environment
fi

rm -rf $T
echo "proxy set to $P"
