# ubuntu-dev VM setup

## Quick start (any OS)
```
python3 snp.py setup        # once: builds the VM, installs the tools (long; see Not verified)
python3 snp.py up           # each run: firewall, proxy, VM
python3 snp.py snapshot     # once the VM works as you want: save it as `clean`
python3 snp.py reset        # after each repo: back to `clean`
```
`snp.py down` stops the VM and the proxy, `snp.py status` shows the state. `--dry-run` prints the commands. All state (venv, SSH key, VM password, proxy CA, VM disk) is in `.snp/`, per developer and git-ignored. For Claude Code put `SANDBOX_OAUTH_TOKEN=...` (from `claude setup-token`) in `.env`. Tests: `python3 test_snp.py`.

## Host
- Hypervisor: VirtualBox 7.1.18, VM name `ubuntu-dev`
- Storage: 60 GB virtual disk on the host's local disk
- Resources: 4 CPUs, 8 GB RAM, 128 MB video memory (VMSVGA)
- Network: host-only `vboxnet0` (`192.168.56.1/24`), no NAT. Guest address `192.168.56.101` (DHCP), no default route. The only way out is the egress proxy on `192.168.56.1:3128`
- Shared clipboard and drag and drop: disabled. No USB, no shared folders
- SSH: `dev@192.168.56.101`. The old NAT forward `127.0.0.1:2222` is gone
- OS image: Ubuntu 26.04.1 Desktop LTS (`ubuntu-26.04.1-desktop-amd64.iso`, SHA256 verified), kernel 7.0.0-38-generic

## Installed in the VM (checked 2026-10-18)

| Tool | Version | Source |
|------|---------|--------|
| Node.js | 22.22.1 | apt |
| npm | 9.2.0 | apt |
| Python 3 (+ pip, venv) | 3.14.4 (pip 25.1.1) | apt |
| curl, git | 8.18.0, 2.53.0 | apt |
| Google Chrome | 155.0.8059.84 | Google `.deb` |
| Insomnia | 13.3.1 | snap |
| Visual Studio Code | snap `code` (classic), revision 6d62b1d5 | snap |
| Docker Engine | 29.1.3 | apt (`docker.io`) |
| Docker Compose | 2.40.3 (plugin) | apt (`docker-compose-v2`) |
| Claude Code CLI | 2.1.302 | native installer (`https://claude.ai/install.sh`), `~/.local/bin/claude` |
| OpenSSH server | 10.2p1 | apt |

Also present from the Ubuntu desktop image: Firefox 154.0 (snap), Snap Store, snapd 2.77.1 and the usual GNOME snaps. 44 packages are marked manually installed; list them with `apt-mark showmanual`.

## Host firewall (needs admin)
Services on the host that listen on all interfaces are reachable from the VM at `192.168.56.1`. `firewall.py` (run by `snp.py up`) closes that: from the host-only interface it allows only DHCP (udp 67), the proxy (tcp 3128) and replies, and drops the rest. It picks the tool of the OS.

| OS | Tool used | Status |
|----|-----------|--------|
| Linux | `nft` (table `sandbox`), else `iptables`/`ip6tables` (chain `SNP`) | nft loaded and verified with the attack suite; iptables untested |
| macOS | `pf` (anchor `com.apple/snp`) | untested |
| Windows | Windows Firewall block rules (PowerShell) | untested |

```
python3 firewall.py up --dry-run   # print what it would run, changes nothing
python3 firewall.py up             # load (re-runs itself with sudo; on Windows use an elevated terminal)
python3 firewall.py status
python3 firewall.py down
```

- Needs `psutil`, like `netinfo.py` (`snp.py` uses its own venv).
- Not persistent: `snp.py up` loads it again after every host reboot, before it starts the VM.
- It finds the adapter by its address `192.168.56.1`, so create the host-only network first.
- Verify with the attack suite: `python3 snp.py probe --gateway <router IP>` (see `attack-suite/ATTACK-SUITE.md`). The host-port probes must be blocked and 3128 open.

## Proxy log and allow list (optional)
- By default there is no allow list: any public host is reachable, and every destination is written to `proxy.log` (one JSON line per connection). Private ranges are always blocked.
- To see what a project tried to reach, after a run: `cut -d'"' -f8,12 proxy.log | sort | uniq -c | sort -rn | head -20`
- For more control, create `allow.txt` next to `proxy_addon.py`, one domain per line (subdomains match, `#` starts a comment). Anything else gets a 403 and a `deny` line in `proxy.log`. The proxy reads the file on every request, so edits apply without a restart.
- `SANDBOX_MODE=log` with an `allow.txt` only logs the misses as `would-deny` and allows them: use it to learn which domains a project needs, then switch it off.

Every terminal and ssh login prints this list with the installed versions (`setup-dev.sh` installs it as `vm-versions`). Run `vm-versions` to see it again.

## Account
- User `dev`, member of the `docker` group (log out and in for it to apply)
- Console password: `snp.py setup` uses `dev` unless you pass `--password PW`. Change it with `passwd` after setup, or pass your own. It is stored in `.snp/<vm>/password`. SSH is key-only, and sudo needs no password.

## Configured for the sandbox (not in `setup-dev.sh`)
- Proxy `http://192.168.56.1:3128` (`NO_PROXY=localhost,127.0.0.1,::1`) in: `/etc/environment` (with `NODE_USE_ENV_PROXY=1`, so Node's `fetch` uses it too; without it `fetch` goes direct and fails), `/etc/apt/apt.conf.d/95proxy`, snap (`snap set system proxy.*`), the Docker daemon drop-in `/etc/systemd/system/docker.service.d/http-proxy.conf`, the Chrome policy `/etc/opt/chrome/policies/managed/proxy.json`, and the user's git, npm (`~/.npmrc`) and pip (`~/.config/pip/pip.conf`) configs
- Claude Code token placeholder: `CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-placeholder` in `/etc/environment`. The proxy swaps in the real token for `api.anthropic.com`; the real token is never in the VM
- mitmproxy CA (public cert only) at `/opt/snp/ca.pem`, used through `NODE_EXTRA_CA_CERTS`. It is not in the system trust store
- The attack suite is not in the image: `python3 snp.py probe --gateway <router IP>` copies it in and runs it (see `attack-suite/ATTACK-SUITE.md`). `snp.py reset` removes it
- The VM exits through the host's public IP. To hide it, run a VPN on the host (the proxy's outbound traffic follows it).

## Reproduce

Automated, one command (long run):
```
python3 snp.py setup        # builds the VM and installs the tools
python3 snp.py up           # each session: firewall, proxy, VM
python3 snp.py snapshot     # once the VM is right: save it as `clean`
```

`setup` runs these steps in order:
1. Creates the host-only network with DHCP.
2. Creates the VM with 8 GB RAM (`--ram` overrides). CPUs are 4, or the host's count if lower (`--cpus` overrides). If the host count is unknown, it uses 2.
3. Installs Ubuntu unattended over NAT, because the installer needs the mirrors.
4. Switches the VM to host-only, then starts the firewall and proxy.
5. Runs `setup-guest-proxy.sh` and `setup-dev.sh` over SSH.

`setup` does not take the snapshot. Check the VM, then run `snp.py snapshot`.

Manual, for a VM you built yourself. The VM has no route out, so start the proxy first:
```
python3 snp.py up
scp setup-guest-proxy.sh setup-dev.sh report-installed.sh .snp/mitmproxy/mitmproxy-ca-cert.pem dev@192.168.56.101:
ssh -t dev@192.168.56.101 'bash setup-guest-proxy.sh mitmproxy-ca-cert.pem && bash setup-dev.sh'
```
To keep a CA an existing VM already trusts, run `cp -r ~/.mitmproxy .snp/mitmproxy` before the first `up`.

## Not verified
- `snp.py setup` as a whole: only run with `--dry-run`. Unknown: the VirtualBox post-install hook and the guest additions check on Ubuntu 26.04, the DHCP server and host-only commands on VirtualBox 7.1+ for macOS and Windows.
- macOS, Windows and Apple Silicon (needs an arm64 Ubuntu image). On Windows run `snp.py` from an elevated terminal.
- `firewall.py` with iptables, pf and Windows Firewall.

Verified on Linux, 2026-10-21: token swap (`claude -p hi` works, the VM only holds the placeholder), `docker run hello-world`, clipboard, drag and drop and host files not reachable, `snp.py snapshot` and `reset`.
