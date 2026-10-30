# ShouldNotPass (`snp`): run untrusted repos in a VM that cannot reach your host
![You shall not pass](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExenA4OHpteWVieGZrZnI0ZTZ5ZHdzZWpiYXJqMW5uNzZhOXZxdHk1MCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/S6sZaHdqsGYFO/giphy.gif)

Run untrusted repos in a VM that reaches the internet but not your host, LAN or private networks. One script, `snp.py`, does everything. Runtime state defaults to `.snp/` (git-ignored); `--state-dir` can select another folder.

**Status: works on Linux.** `setup` (building a VM from nothing), `up`, `snapshot`, `reset`, the token swap and the nftables firewall are verified on Linux. The attack suite passes 26 of 26 (`leak-report.md`); a plain NAT VM passes 19 of 26 (`leak-report-baseline.md`). `snapshot` and `reset` were verified on a hand-built VM, not yet on one built by `setup`.

**Windows 11 x64:** VM startup, guest network isolation, Chrome, Docker and snapshot/reset were tested on a real host. The same Python CLI is used on every OS; firewall backends are selected automatically. The offline CI matrix includes Linux, Windows and macOS. macOS has not had a live VM test.

## TODO: test on other platforms
The code for these exists but has never been run. Testers wanted.
- [ ] **macOS (Intel):** VirtualBox host-only network setup, adapter names, the `pf` firewall in `firewall.py`, `netinfo.py`.
- [ ] **Linux with iptables** instead of nftables: the iptables path in `firewall.py`.
- [ ] **Apple Silicon:** needs an arm64 Ubuntu image. `setup` stops with a message for now.
- [ ] **Attack suite gaps:** IPv6, DNS and UDP around the proxy, a proxy-down test, and a check that `reset` removes planted files.

## 0. Before you start
- VirtualBox 7.1 or newer ([downloads](https://www.virtualbox.org/wiki/Downloads)), Python 3.12 or newer with the `venv` module (on Ubuntu: `sudo apt install python3-venv`), the OpenSSH client (`ssh`, `scp`, `ssh-keygen`).
- Nothing else to install. The proxy (mitmproxy and psutil) is installed by `snp.py` into `.snp/venv` the first time you run `setup` or `up`. It needs internet access once, for `pip`.
- About 20 GB free disk (the 60 GB disk file grows as it fills), and 8 GB of RAM to give the VM (4 GB works for a small frontend: `--ram 4096`).
- Admin rights once per start: the firewall step asks for your sudo password (Linux, macOS). On Windows, open an elevated (administrator) terminal first.
- ARM hosts, including Apple Silicon and Windows on ARM, are not supported yet (needs an arm64 Ubuntu image).
- Clone the repo and work from its folder. No absolute paths are needed anywhere.

### Host configuration

Defaults stay the same on Linux, macOS and Windows. No OS setting or separate fork is needed.

| Option | Default | Purpose |
|---|---|---|
| `--state-dir PATH` / `SNP_STATE_DIR` | `.snp/` in the checkout | Dedicated folder for VM disks, installer, keys and private Python runtime. Use the same value for every command. |
| `SNP_VBOXMANAGE` | Discover VirtualBox automatically | Optional path to a nonstandard `VBoxManage` installation. |
| `--ca-cert FILE` (repeatable) | Normal certificate trust | Explicit public inspection CA, used only by `setup`/`provision`; never a private key. |

Global options go before the command. For example: `python3 snp.py --state-dir /path/to/state up`. The source checkout, `.env` and `allow.txt` stay where they are. Use a dedicated state directory; its permissions protect SSH keys and the proxy CA.

On Windows, install VirtualBox, Python 3.12+ and the Windows OpenSSH Client. Use `py -3` in place of `python3` from an administrator terminal, or use the optional PowerShell launcher:

```powershell
.\snp.ps1 -Elevate --state-dir D:\snp setup --ram 4096
.\snp.ps1 -Elevate --state-dir D:\snp up
```

Choose an existing drive with at least 30 GB free for the installer and VM. The launcher finds Python and handles UAC; output is saved to `.snp\elevated.log`. If script execution is disabled, invoke `py -3 snp.py ...` directly from an administrator terminal. Guest scripts use LF line endings; Windows does not need Bash.

Windows rules apply only to the sandbox adapter and persist until `firewall.py down`; `up` verifies them before starting the VM. Keep Windows Firewall enabled. The setup refuses incompatible forwarding, bridging, sharing and firewall policy.

If HTTPS inspection requires an additional root, stop the proxy, then run `python3 snp.py --ca-cert /path/to/public-root.crt provision` with the same state options. Supply one public PEM/DER CA per file. Normal trust is extended for the proxy and guest OS/Node/Chrome; TLS verification stays enabled. Machine-specific certificates are stored outside Git.

## 1. Build the VM (once)
```
python3 snp.py setup
```
- Options: `--ram MB` (default 8192; 4096 is enough for a small frontend), `--cpus N` (default 4, or fewer if the host has fewer), `--password X` (default `dev`, console login only), `--iso FILE` (otherwise it uses the first `.iso` in this folder, or downloads Ubuntu 26.04.1 and checks its checksum).
- It creates the host-only network (`192.168.56.0/24`, DHCP, no NAT), the VM with clipboard, drag and drop and USB off, and installs Ubuntu without asking questions. This takes 30 to 60 minutes. Don't click inside the VM window.
- The install itself uses NAT, because the installer must reach the Ubuntu mirrors. No repo code runs yet. After the install the VM moves to the host-only network and loses NAT for good.
- Ubuntu guest services come from `virtualbox-guest-utils`/`virtualbox-guest-x11`; installation waits for a completion marker before switching networks.
- It then loads the firewall (asks for your sudo password), starts the proxy, and installs the tools over SSH: Node, npm, Python, Chrome, VS Code, Insomnia, Docker, Git and Claude Code. SSH is key-only, with a key made for you in `.snp/<vm name>/`.
- It ends with the VM powered off.
- If the tool install fails: fix the cause, then run `python3 snp.py provision`. It repeats only the SSH step, not the Ubuntu install.
- A second VM next to the first: add `--name NAME` to any command.

## 2. Give Claude Code its token (once, optional)
1. On the host: `claude setup-token`. Copy the `sk-ant-oat01-...` it prints. Don't paste it into a chat.
2. Add this line to `.env` in this folder (git-ignored):
   ```
   SANDBOX_OAUTH_TOKEN=sk-ant-oat01-...
   ```
3. The proxy reads `.env` when it starts, so run `python3 snp.py down` and `up` again if it is already running.

The real token stays on the host. The VM holds only the placeholder `sk-ant-oat01-placeholder`. The proxy swaps in the real token for `api.anthropic.com` only. Check it: in the VM `claude -p hi` answers, `env | grep -i token` shows only the placeholder, and `proxy.log` on the host has a `credential-swap` line.

## 3. Start a session (every time)
```
python3 snp.py up
```
It loads the host firewall, starts the egress proxy on `192.168.56.1:3128`, and starts the VM. The firewall is not saved across host reboots, which is why `up` loads it each time. The VM's only way out is that proxy, and the proxy refuses private addresses.

## 4. Check the VM, then save it (once)
In the VM:
- Chrome opens a site, `node -v` and `python3 --version` work, `docker run hello-world` works (log out and in once if Docker says permission denied), `claude -p hi` answers if you did step 2.
- Clipboard and drag and drop do not cross in either direction, and no host files are visible.

When it is the state you want to return to:
```
python3 snp.py snapshot
```
This powers the VM off and saves it as `clean`. Run it again after you change the VM; it replaces the old one.

## 5. Run a repo, then reset (every repo)
1. `python3 snp.py up`.
2. Clone and run the untrusted repo inside the VM only.
3. `python3 snp.py reset`. It powers the VM off, restores `clean`, and starts it again. Anything the repo wrote, installed or planted is gone.

Run `reset` after every repo. That is what makes the sandbox hold; a VM you keep using is a VM that can stay infected.

## 6. Other commands
| Command | What it does |
|---|---|
| `python3 snp.py status` | VM state, proxy, snapshots |
| `python3 snp.py down` | Power off the VM and stop the proxy |
| `python3 snp.py provision` | Repeat the tool install over SSH; ends with the install report |
| `python3 snp.py report` | List what is installed in the running VM, with versions |
| `python3 firewall.py status` | Show the host firewall rule |
| `python3 firewall.py down` | Remove the host firewall rule |
| `--dry-run` on any command | Print the commands, change nothing |

## 7. Check that the sandbox holds
1. In the VM, copy `attack-suite/` over (or clone this repo there), then run `SNP_VM=1 python3 probe.py` inside it. It runs 26 probes (host ports, private networks, metadata, redirects, secrets) and writes `probe-report.json`. It sends nothing sensitive.
2. On the host: `python3 -I leak_report.py probe-report.json > leak-report.md`. Today's result on Linux: 26 probes, 0 leaks. Open mode lets the VM reach any public site, which the report lists as accepted.
3. Run the `test_*.py` scripts listed in `.github/workflows/tests.yml` with the private venv's Python (`.snp/venv/bin/python` on Linux/macOS, `.snp\venv\Scripts\python.exe` on Windows). These tests mock VM, SSH and firewall operations.

## 8. Tighten it (optional)
- The proxy is in open mode: any public site is reachable, so a hostile repo can send data to one. An allow list (`allow.txt`) blocks the rest. Start with `SANDBOX_MODE=log` to learn what your work needs, then enforce.
- Keep VirtualBox patched. A VM escape is the one risk the sandbox adds.
- Services on your host that listen on all interfaces are reachable from the VM at `192.168.56.1` unless the firewall step is loaded. `up` loads it.
- Don't sign in to personal accounts inside the VM. Use throwaway credentials.

## 9. Undo
- `python3 snp.py down`, then `python3 firewall.py down`.
- Delete the VM: `VBoxManage unregistervm ubuntu-dev --delete` (or your `--name`).
- Delete the folder `.snp/` to remove the venv, keys and proxy CA.

## Troubleshooting
| Symptom | Likely cause and fix |
|---|---|
| `VirtualBox not found` | Install VirtualBox 7.1+ and put `VBoxManage` on PATH |
| `already locked by a session` on start | Wait a few seconds. `up` retries by itself for a minute |
| `no snapshot yet` on `reset` | Run `python3 snp.py snapshot` first |
| `timed out waiting for ...` | The step it names took over its limit. Check the VM window and the host load, then run `provision` |
| The VM cannot reach anything | Is the proxy up? `python3 snp.py status`. Did a host reboot drop the firewall? Run `up` |
| `claude` in the VM cannot sign in | `.env` has no `SANDBOX_OAUTH_TOKEN`, or the proxy started before you added it. Run `down` then `up` |
| Windows: firewall step fails | Run the terminal as administrator |
