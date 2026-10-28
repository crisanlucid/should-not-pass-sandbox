#!/usr/bin/env python3
"""ShouldNotPass (snp): run untrusted repos in a VM that cannot reach your host. VirtualBox on x86_64; native QEMU/HVF on Apple Silicon. Everything lives in this directory.

  python3 snp.py setup [--iso FILE] [--ram MB] [--cpus N] [--password PW]   once: build the VM and install the tools
  python3 snp.py up                                         every run: firewall, proxy, start the VM
  python3 snp.py snapshot                                   once the VM works as you want: save it as `clean`
  python3 snp.py reset                                      after each repo: restore `clean`, start again
  python3 snp.py report                                     list what is installed in the running VM, with versions
  python3 snp.py down | status                              stop VM and proxy | show state
  add --dry-run to print the commands without running them, --name NAME to work on another VM (default ubuntu-dev)

Needs: VirtualBox 7.1+ (x86_64) or Homebrew QEMU (Apple Silicon), Python 3.12+, ssh/scp/ssh-keygen (OpenSSH client), admin rights for the firewall step.
Secrets (SSH key, proxy CA; the VM password is `dev` unless --password) are kept per developer in .snp/ (git-ignored).
Put SANDBOX_OAUTH_TOKEN (from `claude setup-token`) in .env next to this file; only the host proxy ever sees it.
Untested: macOS Intel and Windows; the extracted VirtualBox adapter needs live x86_64 testing.
"""
import argparse
import hashlib
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from vm_backends import Qemu, VirtualBox

HERE = Path(__file__).resolve().parent
STATE = HERE / ".snp"
VM, HOST_IP, PORT, USER = "ubuntu-dev", "192.168.56.1", 3128, "dev"
UBUNTU = "https://releases.ubuntu.com/26.04.1/"
ISO_NAME = "ubuntu-26.04.1-desktop-amd64.iso"
WIN = platform.system() == "Windows"
DRY = False
HEADLESS = False
PROFILE = {"disk_mb": 61440, "desktop": False}


def exe(name):
    return str(STATE / "venv" / ("Scripts" if WIN else "bin") / (name + (".exe" if WIN else "")))


def run(cmd, ro=False, check=True, show=False):
    """ro=True: runs even in --dry-run (queries only). show=True: print the output live instead of capturing it."""
    cmd = [str(c) for c in cmd]
    if DRY and not ro:
        print("+", " ".join(cmd))
        return ""
    r = subprocess.run(cmd, capture_output=not show, text=True)
    if check and r.returncode:
        sys.exit(f"failed: {' '.join(cmd)}" + ("" if show else f"\n{(r.stderr or r.stdout).strip()}"))
    return r.stdout


def vbm(*args, **kw):
    path = shutil.which("VBoxManage") or next((p for p in (r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
                                                           "/Applications/VirtualBox.app/Contents/MacOS/VBoxManage")
                                                if os.path.exists(p)), None)
    return run([path or sys.exit("VirtualBox not found: install VirtualBox 7.1+ first"), *args], **kw)


def wait(what, ok, minutes):
    if DRY:
        return print(f"(would wait for {what})")
    print(f"waiting for {what} ...", flush=True)
    end = time.time() + minutes * 60
    while not ok():
        time.sleep(5)
        if time.time() > end:
            sys.exit(f"timed out waiting for {what}")


def vm_state():
    for line in vbm("showvminfo", VM, "--machinereadable", ro=True, check=False).splitlines():
        if line.startswith("VMState="):
            return line.split("=")[1].strip('"')


def vm_prop(name):
    out = vbm("guestproperty", "get", VM, name, ro=True, check=False)
    return out.split("Value:")[1].strip() if "Value:" in out else ""


def load_env():
    env = dict(os.environ)
    f = HERE / ".env"
    for line in f.read_text().splitlines() if f.exists() else []:
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip("'\"")
    return env


def proxy_up():
    try:
        socket.create_connection((HOST_IP, PORT), timeout=1).close()
        return True
    except OSError:
        return False


# ---- host network ----------------------------------------------------------------------------------------------

def network():
    """Host-only network on 192.168.56.0/24 with DHCP, no NAT. Returns the adapter name (differs per OS)."""
    def find():
        for block in vbm("list", "hostonlyifs", ro=True).split("\n\n"):
            f = {k.strip(): v.strip() for k, _, v in (l.partition(":") for l in block.splitlines())}
            if f.get("IPAddress") == HOST_IP:
                return f["Name"]
    name = find()
    if not name:
        out = vbm("hostonlyif", "create")
        name = out.split("'")[1] if "'" in out else "vboxnet0"
        vbm("hostonlyif", "ipconfig", name, "--ip", HOST_IP, "--netmask", "255.255.255.0")
    if name not in vbm("list", "dhcpservers", ro=True) and f"HostInterfaceNetworking-{name}" not in vbm("list", "dhcpservers", ro=True):
        vbm("dhcpserver", "add", "--interface", name, "--server-ip", "192.168.56.2", "--netmask", "255.255.255.0",
            "--lower-ip", "192.168.56.100", "--upper-ip", "192.168.56.200", "--enable", check=False)
    return name


# ---- setup -----------------------------------------------------------------------------------------------------

def find_iso(given):
    if given:
        return Path(given)
    local = next(HERE.glob("*.iso"), None) if not BACKEND.cloud_image else None
    if local:
        return local
    dest = STATE / ISO_NAME
    if not DRY and not dest.exists():
        print("downloading", UBUNTU + ISO_NAME, flush=True)
        urllib.request.urlretrieve(UBUNTU + ISO_NAME, dest)
        sums = urllib.request.urlopen(UBUNTU + "SHA256SUMS").read().decode()
        want = next(l.split()[0] for l in sums.splitlines() if ISO_NAME in l)
        h = hashlib.sha256()
        with dest.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != want:
            dest.unlink()
            sys.exit("ISO checksum mismatch, deleted")
    return dest


def venv():
    """Python environment with mitmproxy and psutil, inside .snp/ (created on first use)."""
    if not Path(exe("python")).exists():
        run([sys.executable, "-m", "venv", STATE / "venv"])
        run([exe("python"), "-m", "pip", "install", "-q", "mitmproxy", "psutil"])


def guest_ssh():
    """Common ssh/scp options and the isolated VM address."""
    key = STATE / VM / "id_ed25519"
    ip, port = BACKEND.ssh_address() or ("<vm ip>", 22)
    ssh = ["-F", os.devnull, "-i", key, "-o", f"Port={port}", "-o", "ForwardAgent=no",
           "-o", "ClearAllForwardings=yes", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new",
           "-o", f'UserKnownHostsFile="{STATE / VM / "known_hosts"}"']
    return ssh, f"{USER}@{ip}"


def report(_=None):
    """Print what is installed in the running VM, with versions."""
    ssh, host = guest_ssh()
    run(["scp", *ssh, HERE / "report-installed.sh", f"{host}:"])
    run(["ssh", *ssh, host, "bash report-installed.sh"], show=True)


def provision(_=None):
    """Install the shared tools over SSH; rerun this after a failed tool install."""
    pw_file = STATE / VM / "password"
    pw = pw_file.read_text() if pw_file.exists() else "<password>"
    up()
    ca = STATE / "mitmproxy" / "mitmproxy-ca-cert.pem"
    wait("the proxy CA", ca.exists, 1)
    def ready():
        if not BACKEND.ssh_address():
            return False
        ssh, host = guest_ssh()
        return run(["ssh", *ssh, host, "printf snp-ready"], check=False) == "snp-ready"
    wait("SSH in the isolated VM", ready, 15)
    ssh, host = guest_ssh()
    if BACKEND.cloud_image:
        run(["ssh", *ssh, host, "sudo cloud-init status --wait"], show=True)
    run(["scp", *ssh, HERE / "setup-guest-proxy.sh", HERE / "setup-dev.sh", HERE / "report-installed.sh", ca, f"{host}:"])
    run(["ssh", *ssh, host, f"bash setup-guest-proxy.sh {ca.name} {BACKEND.proxy_url} && set -a && . /etc/environment && set +a && SNP_DESKTOP={int(PROFILE['desktop'])} bash setup-dev.sh && bash report-installed.sh"], show=True)
    BACKEND.stop()
    print(f"\ndone. VM console password (sudo needs none): {pw}\n"
          "Next: `up`, check the VM works (browser, npm, Claude Code), then `python3 snp.py snapshot` to save that state.")


def bootstrap(pub):
    return (f"install -d -m700 -o {USER} -g {USER} /home/{USER}/.ssh && "
            f"printf '%s\\n' {shlex.quote(pub)} > /home/{USER}/.ssh/authorized_keys && "
            f"chown {USER}:{USER} /home/{USER}/.ssh/authorized_keys && chmod 600 /home/{USER}/.ssh/authorized_keys && "
            "if ! command -v sshd >/dev/null; then apt-get install -y openssh-server; fi && ssh-keygen -A && "
            "printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\nPermitRootLogin no\\n' > /etc/ssh/sshd_config.d/10-snp.conf && "
            f"printf '{USER} ALL=(ALL) NOPASSWD:ALL\\n' > /etc/sudoers.d/{USER} && chmod 440 /etc/sudoers.d/{USER} && "
            "systemctl enable --now ssh && systemctl restart ssh")


def setup(a):
    if BACKEND.cloud_image and a.baseline:
        sys.exit("--baseline is only available with VirtualBox")
    BACKEND.check_new()
    if not DRY:
        (STATE / VM).mkdir(parents=True, mode=0o700, exist_ok=True)
    venv()
    image = find_iso(a.image or a.iso)
    key = STATE / VM / "id_ed25519"
    if not key.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    pw_file = STATE / VM / "password"
    if not pw_file.exists() and not DRY:
        pw_file.write_text(a.password)
        pw_file.chmod(0o600)
    pw = pw_file.read_text() if pw_file.exists() else "<password>" if DRY else a.password
    pub = key.with_suffix(".pub").read_text().strip() if not DRY else "<public key>"
    BACKEND.create(a, image, pub, pw, bootstrap(pub))
    if not a.baseline:
        provision()


# ---- run -------------------------------------------------------------------------------------------------------

def stop_vm():
    if DRY:
        return print("+ VBoxManage controlvm", VM, "acpipowerbutton   (repeated, then poweroff if the guest ignores it)")
    if vm_state() != "running":
        return
    print("waiting for the VM to power off ...", flush=True)
    for _ in range(6):  # the ACPI button is ignored while the guest is still booting, so press it again every 30 s
        vbm("controlvm", VM, "acpipowerbutton", check=False)
        for _ in range(6):
            time.sleep(5)
            if vm_state() != "running":
                return
    vbm("controlvm", VM, "poweroff", check=False)  # guest did not react in 3 min: pull the plug
    wait("the VM to power off", lambda: vm_state() != "running", 1)


def up(start_vm=True):
    if not DRY:
        STATE.mkdir(exist_ok=True)
    venv()
    # Only the VirtualBox host-only network needs a host firewall.
    if BACKEND.host_firewall:
        if DRY:
            print("+", exe("python"), HERE / "firewall.py", "up")
        else:
            subprocess.run([exe("python"), str(HERE / "firewall.py"), "up"], check=True)
    env = load_env()
    if not (env.get("SANDBOX_OAUTH_TOKEN") or env.get("SANDBOX_ANTHROPIC_KEY")):
        print("note: no SANDBOX_OAUTH_TOKEN in .env, Claude Code in the VM will not authenticate")
    if not proxy_up():
        cmd = [exe("mitmdump"), "--listen-host", HOST_IP, "--listen-port", PORT, "--set", f"confdir={STATE / 'mitmproxy'}",
               "-s", HERE / "proxy_addon.py"]
        if DRY:
            print("+", " ".join(map(str, cmd)))
        else:
            kw = {"creationflags": 0x00000008 | 0x00000200} if WIN else {"start_new_session": True}
            p = subprocess.Popen(list(map(str, cmd)), env=env, cwd=HERE, stdout=(STATE / "proxy.out").open("a"),
                                 stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kw)
            (STATE / "proxy.pid").write_text(str(p.pid))
        wait("the proxy to listen", proxy_up, 1)
    if start_vm:
        BACKEND.start()


def down(_=None):
    BACKEND.stop()
    pid = STATE / "proxy.pid"
    if pid.exists() and not DRY:
        try:
            os.kill(int(pid.read_text()), 15)
            wait("the proxy to stop", lambda: not proxy_up(), 1)
        except OSError:
            pass
        pid.unlink()


def has_snapshot():
    return "clean" in BACKEND.snapshots()


def snapshot(_=None):
    """Save the current VM as `clean`, including mutable firmware state."""
    BACKEND.stop()
    BACKEND.snapshot()
    print("saved snapshot `clean`; `python3 snp.py reset` returns to it")


def reset(_=None):
    if not DRY and not has_snapshot():
        sys.exit("no snapshot yet: get the VM working, then run `python3 snp.py snapshot`")
    BACKEND.stop(force=True)
    BACKEND.snapshot(restore=True)
    up()


def status(_=None):
    print(f"VM {VM}: {BACKEND.state() or 'not found'}\nproxy {HOST_IP}:{PORT}: {'listening' if proxy_up() else 'down'}")
    print(", ".join(BACKEND.snapshots()) or "no snapshots")


def main():
    global DRY, VM, HEADLESS, BACKEND, PROFILE, HOST_IP, UBUNTU, ISO_NAME
    if sys.version_info < (3, 12):  # mitmproxy needs 3.12+; fail here, not in pip
        sys.exit(f"Python 3.12 or newer is required (this is {sys.version.split()[0]}): https://www.python.org/downloads/")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--headless", action="store_true", help="start without a VM window")
    p.add_argument("--profile", choices=("macos-arm64", "virtualbox-amd64"), help="defaults to the host architecture")
    p.add_argument("--name", default=VM, help="VM name, default %(default)s; lets a second VM exist next to the first")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--baseline", action="store_true", help="test control: stop after the install, leave the VM on NAT with no sandbox")
    s.add_argument("--iso")
    s.add_argument("--image", help="local ARM64 qcow2 image for the macos-arm64 profile")
    s.add_argument("--password", default="dev", help="console login only (SSH is key-only, sudo needs none); default %(default)s")
    s.add_argument("--ram", type=int, default=8192, help="MB, default %(default)s (4096 is enough for a small frontend)")
    s.add_argument("--cpus", type=int, default=min(4, os.cpu_count() or 2))
    for c in ("up", "provision", "report", "snapshot", "down", "reset", "status"):
        sub.add_parser(c)
    a = p.parse_args()
    if not a.name or a.name in (".", "..") or "/" in a.name or "\\" in a.name:
        p.error("--name must be a VM name, not a path")
    DRY, VM, HEADLESS = a.dry_run, a.name, a.headless
    apple_silicon = platform.system() == "Darwin" and platform.machine().lower() in ("arm64", "aarch64")
    name = a.profile or ("macos-arm64" if apple_silicon else "virtualbox-amd64")
    if name == "macos-arm64" and not apple_silicon and not DRY:
        p.error("macos-arm64 requires native Apple Silicon macOS")
    if name == "virtualbox-amd64" and platform.machine().lower() in ("arm64", "aarch64") and not DRY:
        p.error("virtualbox-amd64 requires an x86_64 host")
    import tomllib
    PROFILE = tomllib.loads((HERE / "profiles" / f"{name}.toml").read_text())
    BACKEND = (Qemu if PROFILE["backend"] == "qemu" else VirtualBox)(sys.modules[__name__])
    HOST_IP, UBUNTU, ISO_NAME = BACKEND.listen_host, PROFILE["url"], PROFILE["image"]
    {"setup": setup, "up": lambda a: up(), "provision": provision, "report": report, "snapshot": snapshot, "down": down, "reset": reset, "status": status}[a.cmd](a)


BACKEND = VirtualBox(sys.modules[__name__])


if __name__ == "__main__":
    main()
