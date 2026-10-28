"""Mock malicious postinstall: tries what a hostile repo would try, reports pass/FAIL. Harmless: reads names only, sends nothing sensitive.

Run ONLY inside the sandbox VM:  SNP_VM=1 npm install     (or: SNP_VM=1 python3 probe.py)
Each probe has an expected outcome. FAIL = the sandbox leaked.
"""
import json
import os
import socket
import sys
import urllib.request
import urllib.parse
from pathlib import Path

if os.environ.get("SNP_VM") != "1":
    sys.exit("refusing to run: this probes the network it is on. Run it inside the VM with SNP_VM=1")

PROXY = os.environ.get("http_proxy", "http://192.168.56.1:3128")
PROXY_HOST = urllib.parse.urlsplit(PROXY).hostname
# QEMU's proxy endpoint is separate from its host/gateway address.
HOST = "10.0.2.2" if PROXY_HOST == "10.0.2.100" else PROXY_HOST
results = []


CRITICAL = ("router", "metadata", "NAT gateway", "localhost", "host-only IP", "encoded", "hostname", "redirect",
            "real secrets", "direct ")  # reaching these = host/LAN/secrets exposed


def severity(name):
    return "info" if "(info)" in name else "critical" if any(k in name for k in CRITICAL) else "high"


def record(name, expect, got, note=""):
    ok = got == expect
    results.append({"probe": name, "severity": severity(name), "expect": expect, "got": got, "pass": ok, "note": note})
    print(f"{'pass' if ok else 'FAIL'}  {name:<34} expect {expect:<8} got {got} {note}")


def tcp(host, port, t=3):
    try:
        socket.create_connection((host, port), timeout=t).close()
        return "open"
    except OSError:
        return "blocked"


def http(url, proxy=PROXY, t=8):
    """'blocked' if the request fails or the proxy refuses (4xx/5xx), 'reached' on 2xx/3xx."""
    h = urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})
    try:
        r = urllib.request.build_opener(h).open(url, timeout=t)
        return "reached" if r.status < 400 else "blocked"
    except Exception:
        return "blocked"


# 1. Host services reachable from the VM (only the proxy port may answer)
for port in (22, 3000, 7070, 8443, 32400):
    record(f"host port {port}", "blocked", tcp(HOST, port))
record("host proxy port 3128", "open", tcp(PROXY_HOST, 3128), "(must stay open)")

# 2. Direct network access, no proxy
record("raw tcp to 1.1.1.1:443", "blocked", tcp("1.1.1.1", 443))
record("http without proxy", "blocked", http("https://example.com", proxy=None))
for ip in ("10.0.2.2", "169.254.169.254", "192.168.178.1", "192.168.56.254"):
    record(f"direct {ip}:80", "blocked", tcp(ip, 80))

# 3. Through the proxy: private targets
for name, url in (("router via proxy", "http://192.168.178.1/"),
                  ("cloud metadata via proxy", "http://169.254.169.254/latest/meta-data/"),
                  ("NAT gateway via proxy", "http://10.0.2.2/"),
                  ("host localhost via proxy", f"http://127.0.0.1:7070/"),
                  ("host-only IP via proxy", f"http://{HOST}:7070/"),
                  ("decimal-encoded 127.0.0.1", "http://2130706433/"),
                  ("hex-encoded 127.0.0.1", "http://0x7f000001/"),
                  ("octal-encoded 127.0.0.1", "http://0177.0.0.1/"),
                  ("hostname -> 127.0.0.1", "http://localhost:7070/"),
                  ("redirect to metadata", "https://httpbin.org/redirect-to?url=http://169.254.169.254/&status=302")):
    record(name, "blocked", http(url))

# 4. Secrets in reach (names only, nothing is read or sent)
home = Path.home()
found = [p for p in (".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".config/gh/hosts.yml", ".netrc")
         if (home / p).exists()]
record("credential files in VM home", "none", "none" if not found else ",".join(found))
real = [k for k, v in os.environ.items()
        if any(s in k for s in ("TOKEN", "KEY", "SECRET")) and v and "placeholder" not in v.lower()]
record("real secrets in environment", "none", "none" if not real else ",".join(real), "(names only)")

# 5. Escape surfaces
record("docker socket usable (info)", "open", "open" if os.access("/var/run/docker.sock", os.W_OK) else "blocked",
       "(dev is in the docker group by design: root inside the VM, not on the host)")
record("shared folders mounted", "none", "none" if not [m for m in Path("/proc/mounts").read_text().splitlines()
                                                         if any(fs in m.split()[2:3] for fs in ("vboxsf", "9p", "virtiofs"))] else "mounted")

# 6. Exfiltration: allowed by design while the proxy is in open mode (not a pass/fail of the network)
record("exfil to public site (info)", "reached", http("https://example.com"),
       "(open mode allows it; an allow list should make this blocked)")

Path("probe-report.json").write_text(json.dumps(results, indent=2))
bad = [r for r in results if not r["pass"]]
print(f"\n{len(results) - len(bad)}/{len(results)} as expected; {len(bad)} FAIL -> probe-report.json")
sys.exit(0)  # never fail the install: a failing postinstall would hide the report
