"""Mock malicious postinstall: tries what a hostile repo would try, reports pass/FAIL. Harmless: reads names only, sends nothing sensitive.

Run ONLY inside the sandbox VM. From the host: python3 snp.py probe --gateway <router IP>. Inside the VM: SNP_GATEWAY=<router IP> SNP_VM=1 python3 probe.py
Each probe has an expected outcome. FAIL = the sandbox leaked.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

if os.environ.get("SNP_VM") != "1":
    sys.exit("refusing to run: this probes the network it is on. Run it inside the VM with SNP_VM=1")

HOST = "192.168.56.1"      # host-only address of the host
PROXY = f"http://{HOST}:3128"
GATEWAY = os.environ.get("SNP_GATEWAY", "")  # your home router, set by you (see README)
if not GATEWAY:
    print("skipped: router probes (set SNP_GATEWAY=<your router IP>)")
results = []


CRITICAL = ("router", "metadata", "NAT gateway", "localhost", "host-only IP", "encoded", "hostname", "redirect",
            "real secrets", "direct ", "IPv6", "rebind", "0.0.0.0", "private ", "CGNAT", "ECS", "Alibaba", "userinfo",
            "ping", "https to host")  # reaching these = host/LAN/secrets exposed


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
record("host proxy port 3128", "open", tcp(HOST, 3128), "(must stay open)")

# 2. Direct network access, no proxy
record("raw tcp to 1.1.1.1:443", "blocked", tcp("1.1.1.1", 443))
record("http without proxy", "blocked", http("https://example.com", proxy=None))
for ip in ["10.0.2.2", "169.254.169.254", "192.168.56.254"] + ([GATEWAY] if GATEWAY else []):
    record(f"direct {ip}:80", "blocked", tcp(ip, 80))

# 3. Through the proxy: private targets
for name, url in ([("router via proxy", f"http://{GATEWAY}/")] if GATEWAY else []) + [
                  ("cloud metadata via proxy", "http://169.254.169.254/latest/meta-data/"),
                  ("NAT gateway via proxy", "http://10.0.2.2/"),
                  ("host localhost via proxy", f"http://127.0.0.1:7070/"),
                  ("host-only IP via proxy", f"http://{HOST}:7070/"),
                  ("decimal-encoded 127.0.0.1", "http://2130706433/"),
                  ("hex-encoded 127.0.0.1", "http://0x7f000001/"),
                  ("hostname -> 127.0.0.1", "http://localhost:7070/"),
                  ("redirect to metadata", "https://httpbin.org/redirect-to?url=http://169.254.169.254/&status=302"),
                  ("short-form 127.1", "http://127.1:7070/"),
                  ("0.0.0.0", "http://0.0.0.0:7070/"),
                  ("IPv6 loopback [::1]", "http://[::1]:7070/"),
                  ("IPv4-mapped IPv6 loopback", "http://[::ffff:127.0.0.1]:7070/"),
                  ("userinfo trick @127.0.0.1", "http://example.com@127.0.0.1:7070/"),
                  ("rebind hostname localtest.me", "http://localtest.me:7070/"),
                  ("rebind hostname nip.io", f"http://{HOST}.nip.io:7070/"),
                  ("GCP metadata hostname", "http://metadata.google.internal/computeMetadata/v1/"),
                  ("CGNAT 100.64.0.1", "http://100.64.0.1/"),
                  ("https to host port", f"https://{HOST}:8443/")]:
    record(name, "blocked", http(url))

# 3b. Other protocols and address families, no proxy
record("direct IPv6 public tcp", "blocked", tcp("2606:4700:4700::1111", 443))
record("direct IPv6 loopback ::1:7070", "blocked", tcp("::1", 7070))


def udp_dns(server, name="example.com", t=3):
    """'open' if a DNS server answers a raw UDP query, else 'blocked'."""
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(t)
            s.sendto(q, (server, 53))
            return "open" if s.recvfrom(512)[0][:2] == b"\x12\x34" else "blocked"
    except OSError:
        return "blocked"


def ping(host, t=2):
    r = subprocess.run(["ping", "-c1", "-W", str(t), host], capture_output=True)
    return "open" if r.returncode == 0 else "blocked"


record("direct DNS to 1.1.1.1 (exfil channel)", "blocked", udp_dns("1.1.1.1"))
record("ping 1.1.1.1 (ICMP tunnel)", "blocked", ping("1.1.1.1"))

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
                                                         if "vboxsf" in m] else "mounted")

# 6. Exfiltration: allowed by design while the proxy is in open mode (not a pass/fail of the network)
record("exfil to public site (info)", "reached", http("https://example.com"),
       "(open mode allows it; an allow list should make this blocked)")

# 6b. Node's fetch must use the proxy like curl/npm/git/pip (needs NODE_USE_ENV_PROXY=1; without it fetch goes direct and fails)
try:
    r = subprocess.run(["node", "-e", "fetch('https://example.com').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"],
                       capture_output=True, timeout=15)
    got = "reached" if r.returncode == 0 else "blocked"
except (OSError, subprocess.TimeoutExpired):
    got = "blocked"
record("node fetch uses the proxy (info)", "reached", got, "(open mode; set NODE_USE_ENV_PROXY=1 if blocked)")

# 7. Real-case vector (fake recruiter take-home): a git post-checkout hook runs on checkout. The hook below only touches a marker file.
with tempfile.TemporaryDirectory() as d:
    hook = Path(d, ".git/hooks/post-checkout")
    git = ["git", "-C", d, "-c", "user.name=x", "-c", "user.email=x@x"]
    if shutil.which("git"):  # a plain VM may have no git
        subprocess.run(git + ["init", "-q"], capture_output=True)
        hook.write_text(f"#!/bin/sh\ntouch {d}/hook-ran\n")
        hook.chmod(0o755)
        subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "x"], capture_output=True)
        subprocess.run(git + ["checkout", "-q", "-b", "video"], capture_output=True)
    record("git post-checkout hook runs (info)", "ran", "ran" if Path(d, "hook-ran").exists() else "none",
           "(unzipped .git/hooks run on checkout; the network is the containment)")

Path("probe-report.json").write_text(json.dumps(results, indent=2))
bad = [r for r in results if not r["pass"]]
print(f"\n{len(results) - len(bad)}/{len(results)} as expected; {len(bad)} FAIL -> probe-report.json")
sys.exit(0)  # never fail the install: a failing postinstall would hide the report
