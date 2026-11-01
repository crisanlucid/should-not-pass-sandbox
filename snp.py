#!/usr/bin/env python3
"""ShouldNotPass (snp): run untrusted repos in a VM that cannot reach your host. Written for Linux, macOS and Windows; only Linux is tested. Everything lives in this directory.

  python3 snp.py setup [--iso FILE] [--ram MB] [--cpus N] [--password PW]   once: build the VM and install the tools
  python3 snp.py up                                         every run: firewall, proxy, start the VM
  python3 snp.py snapshot                                   once the VM works as you want: save it as `clean`
  python3 snp.py reset                                      after each repo: restore `clean`, start again
  python3 snp.py report                                     list what is installed in the running VM, with versions
  python3 snp.py down | status                              stop VM and proxy | show state
  add --dry-run to print the commands without running them, --name NAME to work on another VM (default ubuntu-dev)

Needs: VirtualBox 7.1+, Python 3.12+, ssh/scp/ssh-keygen (OpenSSH client), admin rights for the firewall step.
Secrets (SSH key, proxy CA; the VM password is `dev` unless --password) are kept per developer in .snp/ (git-ignored).
Put SANDBOX_OAUTH_TOKEN (from `claude setup-token`) in .env next to this file; only the host proxy ever sees it.
Untested: `setup` as a whole (written, dry-run only), macOS, Windows, Apple Silicon (needs an arm64 guest image).
"""
import argparse
import hashlib
import ipaddress
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE = HERE / ".snp"
VM, HOST_IP, PORT, USER = "ubuntu-dev", "192.168.56.1", 3128, "dev"
UBUNTU = "https://releases.ubuntu.com/26.04.1/"
ISO_NAME = "ubuntu-26.04.1-desktop-amd64.iso"
WIN = platform.system() == "Windows"
DRY = False


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
    local = next(HERE.glob("*.iso"), None)
    if local:
        return local
    dest = STATE / ISO_NAME
    if not DRY and not dest.exists():
        print("downloading", UBUNTU + ISO_NAME, "(about 6 GB)")
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
    """Common ssh options and the VM address (needs the VM running)."""
    key = STATE / VM / "id_ed25519"
    ip = vm_prop("/VirtualBox/GuestInfo/Net/0/V4/IP") or "<vm ip>"
    ssh = ["-i", key, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={STATE / VM / 'known_hosts'}"]
    return ssh, f"{USER}@{ip}"


def report(_=None):
    """Print what is installed in the running VM, with versions."""
    ssh, host = guest_ssh()
    run(["scp", *ssh, HERE / "report-installed.sh", f"{host}:"])
    run(["ssh", *ssh, host, "bash report-installed.sh"], show=True)


def probe(a):
    """Copy the attack suite into the running VM and run it. --gateway is your router IP (see README)."""
    ssh, host = guest_ssh()
    gw = f"SNP_GATEWAY={a.gateway} " if a.gateway else ""  # ipaddress-checked, so safe in the shell line
    run(["ssh", *ssh, host, "mkdir -p probe"])
    run(["scp", *ssh, HERE / "probe.py", HERE / "mock_recruiter.py", HERE / "package.json", f"{host}:probe/"])
    run(["ssh", *ssh, host, f"cd probe && {gw}SNP_VM=1 npm install"], show=True)


def provision(_=None):
    """Install the tools over SSH. setup runs it; run it alone to resume after a failed install step (it can be repeated)."""
    key = STATE / VM / "id_ed25519"
    pw_file = STATE / VM / "password"
    pw = pw_file.read_text() if pw_file.exists() else "<password>"
    up(start_vm=True)
    ca = STATE / "mitmproxy" / "mitmproxy-ca-cert.pem"
    wait("the proxy CA", ca.exists, 1)
    wait("the VM to get an address on the host-only network", lambda: vm_prop("/VirtualBox/GuestInfo/Net/0/V4/IP").startswith("192.168.56."), 15)
    ip = vm_prop("/VirtualBox/GuestInfo/Net/0/V4/IP") or "<vm ip>"
    ssh = ["-i", key, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={STATE / VM / 'known_hosts'}"]
    run(["scp", *ssh, HERE / "setup-guest-proxy.sh", HERE / "setup-dev.sh", HERE / "report-installed.sh", ca, f"{USER}@{ip}:"])
    run(["ssh", *ssh, f"{USER}@{ip}", f"bash setup-guest-proxy.sh {ca.name} && set -a && . /etc/environment && set +a && bash setup-dev.sh && bash report-installed.sh"], show=True)  # ssh is not a login shell: load the proxy variables for curl
    stop_vm()
    print(f"\ndone. VM console password (sudo needs none): {pw}\n"
          "Next: `up`, check the VM works (browser, npm, Claude Code), then `python3 snp.py snapshot` to save that state.")


def setup(a):
    if platform.machine().lower() in ("arm64", "aarch64"):
        sys.exit("Apple Silicon / ARM host: needs an arm64 Ubuntu image, not supported yet")
    if VM in vbm("list", "vms", ro=True):
        sys.exit(f"VM {VM} already exists: remove it first (VBoxManage unregistervm {VM} --delete)")
    if not DRY:
        (STATE / VM).mkdir(parents=True, exist_ok=True)  # per-VM secrets; the venv and proxy CA in STATE are shared
    venv()
    iso = find_iso(a.iso)
    key = STATE / VM / "id_ed25519"
    if not key.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    pw_file = STATE / VM / "password"
    if not pw_file.exists() and not DRY:
        pw_file.write_text(a.password)
        pw_file.chmod(0o600)
    pw, pub = (pw_file.read_text() if pw_file.exists() else "<password>"), (key.with_suffix(".pub").read_text().strip() if not DRY else "<public key>")
    net = network()

    # Install phase: NAT, because the installer must reach the Ubuntu mirrors. No repo code runs yet.
    vbm("createvm", "--name", VM, "--ostype", "Ubuntu_64", "--basefolder", STATE / "vms", "--register")
    vbm("modifyvm", VM, "--memory", a.ram, "--cpus", a.cpus, "--vram", 128, "--graphicscontroller", "vmsvga",
        "--nic1", "nat", "--nic2", "none", "--nic3", "none", "--nic4", "none",
        "--clipboard-mode", "disabled", "--drag-and-drop", "disabled")
    disk = STATE / "vms" / VM / f"{VM}.vdi"
    vbm("createmedium", "disk", "--filename", disk, "--size", 61440)
    vbm("storagectl", VM, "--name", "SATA", "--add", "sata")
    vbm("storageattach", VM, "--storagectl", "SATA", "--port", 0, "--device", 0, "--type", "hdd", "--medium", disk)
    late = (f"mkdir -p /home/{USER}/.ssh && echo '{pub}' > /home/{USER}/.ssh/authorized_keys && "
            f"chown -R 1000:1000 /home/{USER}/.ssh && chmod 700 /home/{USER}/.ssh && chmod 600 /home/{USER}/.ssh/authorized_keys && "
            "apt-get install -y openssh-server && ssh-keygen -A && echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/10-snp.conf && "
            f"echo '{USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{USER}")
    vbm("unattended", "install", VM, "--iso", iso, "--user", USER, "--password", pw, "--full-user-name", USER,
        "--install-additions", "--post-install-command", late, "--start-vm", "gui")
    wait("the installer to finish (guest additions report in)", lambda: vm_prop("/VirtualBox/GuestAdd/Version"), 90)
    if not DRY:
        time.sleep(60)
    stop_vm()
    if a.baseline:  # test control: a plain NAT VM with no sandbox, to prove the attack suite can detect leaks
        vbm("modifyvm", VM, "--natpf1", "ssh,tcp,127.0.0.1,2223,,22")
        return print(f"\nbaseline VM {VM} built on NAT, NO sandbox. `VBoxManage startvm {VM}`, then ssh -p 2223 -i {key} {USER}@127.0.0.1. Delete it when done.")
    vbm("modifyvm", VM, "--nic1", "hostonly", "--hostonlyadapter1", net)  # from here on: no NAT, proxy is the only way out

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
    # firewall.py prompts for sudo (Linux/macOS); on Windows run this script from an elevated terminal
    if DRY:
        print("+", exe("python"), HERE / "firewall.py", "up")
    else:
        subprocess.run([exe("python"), str(HERE / "firewall.py"), "up"], check=True)  # not captured: sudo needs the terminal
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
    if start_vm and vm_state() != "running":
        for _ in range(12):  # VirtualBox keeps the VM locked for a few seconds after power-off or restore
            try:
                vbm("startvm", VM, "--type", "gui")
                break
            except SystemExit as e:
                if "locked" not in str(e.code):
                    raise
                time.sleep(5)
        else:
            sys.exit("the VM stayed locked for 60 s")


def down(_=None):
    stop_vm()
    pid = STATE / "proxy.pid"
    if pid.exists() and not DRY:
        try:
            os.kill(int(pid.read_text()), 15)
        except OSError:
            pass
        pid.unlink()


def has_snapshot():
    return "clean" in vbm("snapshot", VM, "list", ro=True, check=False)


def snapshot(_=None):
    """Save the current, working VM as the state `reset` returns to. Replaces an older one."""
    stop_vm()
    if has_snapshot():
        vbm("snapshot", VM, "delete", "clean")
    vbm("snapshot", VM, "take", "clean")
    print("saved snapshot `clean`; `python3 snp.py reset` returns to it")


def reset(_=None):
    if not DRY and not has_snapshot():
        sys.exit("no snapshot yet: get the VM working, then run `python3 snp.py snapshot`")
    if DRY or vm_state() != "poweroff":
        vbm("controlvm", VM, "poweroff", check=False)
        wait("the VM to power off", lambda: vm_state() == "poweroff", 2)
    vbm("snapshot", VM, "restore", "clean")
    up()


def status(_=None):
    print(f"VM {VM}: {vm_state() or 'not found'}\nproxy {HOST_IP}:{PORT}: {'listening' if proxy_up() else 'down'}")
    print(vbm("snapshot", VM, "list", ro=True, check=False).strip() or "no snapshots")


def main():
    global DRY, VM
    if sys.version_info < (3, 12):  # mitmproxy needs 3.12+; fail here, not in pip
        sys.exit(f"Python 3.12 or newer is required (this is {sys.version.split()[0]}): https://www.python.org/downloads/")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--name", default=VM, help="VM name, default %(default)s; lets a second VM exist next to the first")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--baseline", action="store_true", help="test control: stop after the install, leave the VM on NAT with no sandbox")
    s.add_argument("--iso")
    s.add_argument("--password", default="dev", help="console login only (SSH is key-only, sudo needs none); default %(default)s")
    s.add_argument("--ram", type=int, default=8192, help="MB, default %(default)s (4096 is enough for a small frontend)")
    s.add_argument("--cpus", type=int, default=min(4, os.cpu_count() or 2))
    for c in ("up", "provision", "report", "snapshot", "down", "reset", "status"):
        sub.add_parser(c)
    pr = sub.add_parser("probe", help="run the attack suite in the VM")
    pr.add_argument("--gateway", type=ipaddress.IPv4Address, help="your router IP; without it the router probes are skipped")
    a = p.parse_args()
    DRY, VM = a.dry_run, a.name
    {"setup": setup, "up": lambda a: up(), "provision": provision, "report": report, "snapshot": snapshot, "down": down, "reset": reset, "status": status, "probe": probe}[a.cmd](a)


if __name__ == "__main__":
    main()
