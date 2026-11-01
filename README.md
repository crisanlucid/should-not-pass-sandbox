# ShouldNotPass

Run untrusted repos (fake-recruiter take-homes, unknown GitHub projects) in a disposable VM that cannot reach your host or your LAN. Three parts:

| Part | Files | What it is |
|---|---|---|
| 1. Sandbox | `snp.py`, `firewall.py`, `proxy_addon.py`, `egress_rules.py`, `netinfo.py`, `setup-*.sh`, `report-installed.sh` | The VirtualBox VM, the host firewall and the egress proxy. This is the protection. |
| 2. Malware | `probe.py`, `mock_recruiter.py`, `package.json`, `ATTACK-SUITE.md` | A mock hostile repo. It tries to escape and reports what got out. Test fixture only. |
| 3. Scan and reports | `scan.py`, `leak_report.py`, `leak-report.md`, `leak-report.html` | `scan.py` checks a project before you run it. `leak_report.py` turns the attack-suite results into a report. |

```
snp.py                 single entry point: setup, up, snapshot, reset, down, status, report, probe
firewall.py            host firewall per OS (nft/iptables, pf, Windows Firewall)
proxy_addon.py         mitmproxy addon: egress allow list, private-address refusal, credential swap
egress_rules.py        allow and deny rules used by proxy_addon.py
netinfo.py             host network details for snp.py
setup-dev.sh           guest: installs the dev tools, vm-versions command and login banner
setup-guest-proxy.sh   guest: proxy env vars and the Claude Code placeholder token
report-installed.sh    guest: lists installed tools with versions (vm-versions)
probe.py               attack suite: 36 probes, run inside the VM
mock_recruiter.py      builds a harmless fake take-home zip
scan.py                static scan of a project (folder or zip)
leak_report.py         probe output to leak report (md, --html)
test_*.py              tests
```

TODO: move to the folder layout used in the Antrust repo (`sandbox/`, `scan/`, `attack-suite/`) once the flat layout settles. Paths in the docs below assume flat.

## 1. Sandbox
The VM has no route out except an HTTP proxy on the host. The host firewall drops everything else from the VM, and the proxy refuses private addresses. Open internet, nothing local. No shared folders, clipboard or USB. `snp.py reset` returns the VM to a clean snapshot after each repo.

```
python3 snp.py setup      # once
python3 snp.py up         # each run
python3 snp.py reset      # after each repo
```
Inside the VM, every terminal and ssh login prints the installed tools with their versions (Node.js, Python, Chrome, VS Code, Docker, Claude Code and so on). To see the list again, run:

```
vm-versions
```
From the host: `python3 snp.py report`.

Details, firewall per OS, proxy log and the optional `allow.txt`: `VM-SETUP.md`.

What the sandbox must do, and what is verified so far: [`constraints.md`](constraints.md).

## 2. Malware (attack suite)
Run it from the host, with your router's IP:

```
python3 snp.py probe --gateway 192.168.1.1
```

`snp.py probe` copies the probe files into the VM and runs them there. It refuses to run anywhere else.

**Find your router IP** (the default gateway of the host, not the VM, which has no default route):

- Linux: `ip route | grep default`, the address after `via`
- macOS: `netstat -rn | grep default`, the first address
- Windows: `ipconfig`, the "Default Gateway" line

You type the address yourself; nothing scans your network. Without `--gateway` the router probes are skipped and the output says so. Each probe has an expected result; a `FAIL` means the sandbox leaked. `mock_recruiter.py` builds a harmless copy of the real fake-recruiter case (git `post-checkout` hook, base64 `fetch` plus `new Function`).

## 3. Scan and reports
Two different questions:

- **Is this project dangerous?** `python3 scan.py PATH` (folder or zip) lists hooks, install scripts, encoded URLs and other red flags before anything runs. Optional. Exit code 1 on a high finding.
- **Does the sandbox hold?** `python3 leak_report.py probe-report.json [--html]` turns the attack-suite output into a report. Current result: `leak-report.md` and `leak-report.html`.

## How they connect
The mock malware is the shared fixture. The scan flags it (4 high findings). Run inside the sandbox, it fails to get out (36 of 36 probes as expected).

## Tests
```
python3 test_snp.py
python3 test_scan.py
.snp/venv/bin/python test_egress_rules.py
.snp/venv/bin/python test_credential_swap.py
```
