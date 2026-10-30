#!/usr/bin/env python3
"""ShouldNotPass (snp): run untrusted repos in an isolated VirtualBox VM on Linux, macOS or Windows x64.

  python3 snp.py setup [--iso FILE] [--ram MB] [--cpus N] [--password PW]   once: build the VM and install the tools
  python3 snp.py up                                         every run: firewall, proxy, start the VM
  python3 snp.py snapshot                                   once the VM works as you want: save it as `clean`
  python3 snp.py reset                                      after each repo: restore `clean`, start again
  python3 snp.py report                                     list what is installed in the running VM, with versions
  python3 snp.py down | status                              stop VM and proxy | show state
  add --state-dir PATH before the command to store VM disks, ISO, keys and runtime on another drive
  add --dry-run to print the commands without running them, --name NAME to work on another VM (default ubuntu-dev)

Needs: VirtualBox 7.1+, Python 3.12+, ssh/scp/ssh-keygen (OpenSSH client), admin rights for the firewall step.
Secrets (SSH key, proxy CA; the VM password is `dev` unless --password) are kept per developer in .snp/ (git-ignored).
Put SANDBOX_OAUTH_TOKEN (from `claude setup-token`) in .env next to this file; only the host proxy ever sees it.
See README.md for the current validation status; Apple Silicon/ARM hosts need an arm64 image and are unsupported.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
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


def run(cmd, ro=False, check=True, show=False, label=None):
    """ro=True: runs even in --dry-run (queries only). show=True: print the output live instead of capturing it."""
    cmd = [str(c) for c in cmd]
    if DRY and not ro:
        print("+", label or " ".join(cmd))
        return ""
    try:
        r = subprocess.run(cmd, capture_output=not show, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        sys.exit(f"command not found: {cmd[0]}")
    if check and r.returncode:
        sys.exit(f"failed: {label or ' '.join(cmd)}" + ("" if show else f"\n{(r.stderr or r.stdout).strip()}"))
    return r.stdout


def vbm(*args, **kw):
    candidates = (Path(os.environ.get("VBOX_MSI_INSTALL_PATH", r"C:\Program Files\Oracle\VirtualBox")) / "VBoxManage.exe",
                  Path("/Applications/VirtualBox.app/Contents/MacOS/VBoxManage"))
    path = (os.environ.get("SNP_VBOXMANAGE") or shutil.which("VBoxManage")
            or next((str(p) for p in candidates if p.is_file()), None))
    return run([path or sys.exit("VirtualBox not found: install VirtualBox 7.1+ first"), *args], **kw)


def vbm_unlocked(*args, **kw):
    """Poweroff/restore can finish before VirtualBox releases its Windows session lock."""
    for attempt in range(12):
        try:
            return vbm(*args, **kw)
        except SystemExit as error:
            if "locked" not in str(error.code).lower():
                raise
            if attempt == 11:
                sys.exit("the VM stayed locked for 60 s")
            time.sleep(5)


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


def install_complete():
    if not vm_prop("/VirtualBox/GuestAdd/Version"):
        return False
    out = vbm("guestcontrol", VM, "run", "--username", USER,
              "--passwordfile", STATE / VM / "password", "--exe", "/usr/bin/cat",
              "--wait-stdout", "--wait-stderr", "--timeout", "10000", "--",
              "cat", "/var/lib/snp-install-complete", ro=True, check=False)
    return out.strip() == "complete"


def load_env():
    env = dict(os.environ)
    f = HERE / ".env"
    for line in f.read_text(encoding="utf-8-sig").splitlines() if f.exists() else []:
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip("'\"")
    return env


def port_open():
    try:
        socket.create_connection((HOST_IP, PORT), timeout=1).close()
        return True
    except OSError:
        return False


PROXY_ENTRY = "from snp import proxy_entry; proxy_entry()"


def proxy_entry():
    """The real interpreter publishes its PID; Windows venv launchers have another PID."""
    import psutil
    record = Path(os.environ["SNP_PROXY_PIDFILE"])
    process = psutil.Process(os.getpid())
    temporary = record.with_name(f"{record.name}.{process.pid}.tmp")
    try:
        temporary.write_text(json.dumps({"pid": process.pid, "created": process.create_time()}), encoding="utf-8")
        temporary.replace(record)
    finally:
        temporary.unlink(missing_ok=True)
    from mitmproxy.tools.main import mitmdump
    mitmdump()


def proxy_process():
    """A PID alone is unsafe on Windows: PIDs can be reused after a crash/reboot."""
    try:
        import psutil
        record = json.loads((STATE / "proxy.pid").read_text(encoding="utf-8"))
        legacy = type(record) is int  # existing Unix installations stored a plain PID
        p = psutil.Process(record if legacy else record["pid"])
        cmd = p.cmdline()
        identity = (exe("mitmdump") in cmd and p.create_time() <= (STATE / "proxy.pid").stat().st_mtime
                    if legacy else p.create_time() == record["created"] and PROXY_ENTRY in cmd)
        if (identity
                and str(HERE / "proxy_addon.py") in cmd
                and f"confdir={STATE / 'mitmproxy'}" in cmd):
            return p
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        return None
    except psutil.Error:
        return None


def proxy_up():
    """Only the managed proxy's own IPv4 listening socket establishes readiness."""
    try:
        import psutil
        process = proxy_process()
        if process is None:
            return False
        return any(connection.family == socket.AF_INET
                   and connection.type == socket.SOCK_STREAM
                   and connection.status == psutil.CONN_LISTEN
                   and connection.laddr
                   and connection.laddr.ip == HOST_IP
                   and connection.laddr.port == PORT
                   for connection in process.net_connections(kind="tcp"))
    except (ImportError, OSError):
        return False
    except psutil.Error:
        return False


def vm_info():
    out = vbm("showvminfo", VM, "--machinereadable", ro=True)
    return {key: value.strip('"') for line in out.splitlines()
            if "=" in line for key, value in [line.split("=", 1)]}


def check_vm_isolation():
    """Check restored/edited VMs too; a NAT NIC bypasses the entire proxy policy."""
    info = vm_info()
    adapters = hostonly_interfaces()
    own = [a for a in adapters if a.get("IPAddress") == HOST_IP]
    names = {a.get("Name") for a in own if a.get("NetworkMask") == "255.255.255.0"}
    bad = []
    if len(own) != 1 or info.get("nic1") != "hostonly" or info.get("hostonlyadapter1") not in names:
        bad.append("NIC 1 must use the host-only adapter at " + HOST_IP)
    if any(info.get(f"nic{i}") != "none" for i in range(2, 9)):
        bad.append("NICs 2 through 8 must be disabled")
    for key in ("clipboard", "draganddrop"):
        if info.get(key) != "disabled":
            bad.append(key + " must be disabled")
    for key in ("usb", "ehci", "xhci"):
        if info.get(key) != "off":
            bad.append(key + " must be off")
    if any(k.startswith("SharedFolderName") for k in info):
        bad.append("shared folders must be removed")
    if bad:
        sys.exit("unsafe VM configuration; refusing to start:\n  " + "\n  ".join(bad))


def ssh_options():
    # OpenSSH parses -o as its own config syntax, even when argv was quoted correctly.
    key = STATE / VM / "id_ed25519"
    known = (STATE / VM / "known_hosts").as_posix()
    return ["-F", "none", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", f'UserKnownHostsFile="{known}"', "-o", "ConnectTimeout=15", "-o", "BatchMode=yes"]


def copy_guest_scripts(ssh, host, scripts, extra=()):
    if DRY:
        return run(["scp", *ssh, *(HERE / s for s in scripts), *extra, f"{host}:"])
    # Also handle pre-existing clones checked out with core.autocrlf=true.
    with tempfile.TemporaryDirectory(prefix="snp-scripts-") as directory:
        paths = []
        for name in scripts:
            path = Path(directory) / name
            path.write_bytes((HERE / name).read_bytes().replace(b"\r\n", b"\n"))
            paths.append(path)
        run(["scp", *ssh, *paths, *extra, f"{host}:"])


# ---- host network ----------------------------------------------------------------------------------------------

def fields(out):
    return [{k.strip(): value.strip() for line in block.splitlines()
             if ":" in line for k, value in [line.split(":", 1)]}
            for block in re.split(r"\n\s*\n", out.strip()) if block.strip()]


def hostonly_interfaces():
    return fields(vbm("list", "hostonlyifs", ro=True))


def network():
    """Host-only network on 192.168.56.0/24 with DHCP, no NAT. Returns the adapter name (differs per OS)."""
    before = hostonly_interfaces()
    adapter = next((a for a in before if a.get("IPAddress") == HOST_IP), None)
    name = adapter.get("Name") if adapter else None
    if adapter and adapter.get("NetworkMask") != "255.255.255.0":
        sys.exit(f"host-only adapter {name} must use netmask 255.255.255.0")
    if not name:
        vbm("hostonlyif", "create")
        if DRY:
            name = "<new host-only adapter>"
        else:
            previous = {a.get("Name") for a in before}
            created = [a["Name"] for a in hostonly_interfaces() if a.get("Name") not in previous]
            if len(created) != 1:
                sys.exit("could not identify the newly created host-only adapter; run setup again")
            name = created[0]
        vbm("hostonlyif", "ipconfig", name, "--ip", HOST_IP, "--netmask", "255.255.255.0")
    server = next((s for s in fields(vbm("list", "dhcpservers", ro=True))
                   if s.get("NetworkName") == f"HostInterfaceNetworking-{name}"), None)
    vbm("dhcpserver", "modify" if server else "add", "--interface", name,
        "--server-ip", "192.168.56.2", "--netmask", "255.255.255.0",
        "--lower-ip", "192.168.56.100", "--upper-ip", "192.168.56.200", "--enable")
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
    if DRY or subprocess.run([exe("python"), "-c", "import mitmproxy, psutil"],
                             capture_output=True).returncode:
        run([exe("python"), "-m", "pip", "install", "-q", "mitmproxy", "psutil"])


def prepare_state():
    if DRY:
        return
    resolved = STATE.resolve()
    if (resolved == Path(resolved.anchor) or resolved == Path.home().resolve()
            or resolved == HERE or resolved in HERE.parents or (resolved / ".git").exists()):
        sys.exit("--state-dir must be a dedicated state folder, not a drive root, home or source checkout")
    STATE.mkdir(parents=True, exist_ok=True)
    if WIN:
        from windows_host import private_state_command
        output = run(private_state_command(STATE), label="protect private state permissions")
        if output.strip() != "SNP_STATE_PRIVATE":
            sys.exit("Windows PowerShell did not verify private state permissions")
    else:
        STATE.chmod(0o700)


def store_trusted_ca(paths):
    """Opt-in public CA certificates for HTTPS inspection on the host network."""
    for source in paths:
        source = Path(source).expanduser().resolve()
        if not source.is_file():
            sys.exit(f"CA certificate not found: {source}")
        if DRY:
            print(f"+ stage public CA certificate {source} for {VM}")
            continue
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        data = source.read_bytes()
        if b"PRIVATE KEY" in data or data.count(b"-----BEGIN CERTIFICATE-----") > 1:
            sys.exit("--ca-cert accepts one public CA certificate per file, never private keys")
        try:
            cert = (x509.load_pem_x509_certificate(data) if b"-----BEGIN CERTIFICATE-----" in data
                    else x509.load_der_x509_certificate(data))
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("certificate is not a CA")
        except (ValueError, x509.ExtensionNotFound) as error:
            sys.exit(f"invalid public CA certificate {source}: {error}")
        digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        target = STATE / VM / "trusted-ca" / (digest + ".crt")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        print(f"staged public CA: {cert.subject.rfc4514_string()} (SHA256 {digest})")


def proxy_ca_bundle():
    """Keep the proxy's normal upstream trust and extend it with supplied roots."""
    roots = sorted(STATE.glob("*/trusted-ca/*.crt"))
    if not roots:
        return None
    target = STATE / "upstream-ca.pem"
    if not DRY:
        import certifi
        bundle = Path(certifi.where()).read_bytes() + b"\n" + b"\n".join(root.read_bytes() for root in roots)
        if not target.exists() or target.read_bytes() != bundle:
            target.write_bytes(bundle)
    return target


def guest_ssh():
    """Common ssh options and the VM address (needs the VM running)."""
    ip = vm_prop("/VirtualBox/GuestInfo/Net/0/V4/IP") or "<vm ip>"
    return ssh_options(), f"{USER}@{ip}"


def report(_=None):
    """Print what is installed in the running VM, with versions."""
    ssh, host = guest_ssh()
    copy_guest_scripts(ssh, host, ["report-installed.sh"])
    run(["ssh", *ssh, host, "bash report-installed.sh"], show=True)


def provision(_=None):
    """Install the tools over SSH. setup runs it; run it alone to resume after a failed install step (it can be repeated)."""
    pw_file = STATE / VM / "password"
    pw = pw_file.read_text() if pw_file.exists() else "<password>"
    up(start_vm=True)
    ca = STATE / "mitmproxy" / "mitmproxy-ca-cert.pem"
    wait("the proxy CA", ca.exists, 1)
    wait("the VM to get an address on the host-only network", lambda: vm_prop("/VirtualBox/GuestInfo/Net/0/V4/IP").startswith("192.168.56."), 15)
    ip = vm_prop("/VirtualBox/GuestInfo/Net/0/V4/IP") or "<vm ip>"
    ssh = ssh_options()
    certs = [ca, *sorted((STATE / VM / "trusted-ca").glob("*.crt"))]
    copy_guest_scripts(ssh, f"{USER}@{ip}", ["setup-guest-proxy.sh", "setup-dev.sh", "report-installed.sh"], certs)
    ca_args = " ".join(shlex.quote(cert.name) for cert in certs)
    run(["ssh", *ssh, f"{USER}@{ip}", f"bash setup-guest-proxy.sh {ca_args} && set -a && . /etc/environment && set +a && bash setup-dev.sh && bash report-installed.sh"], show=True)  # ssh is not a login shell: load the proxy variables for curl
    stop_vm()
    print(f"\ndone. VM console password (sudo needs none): {pw}\n"
          "Next: `up`, check the VM works (browser, npm, Claude Code), then `python3 snp.py snapshot` to save that state.")


def setup(a):
    if platform.machine().lower() in ("arm64", "aarch64"):
        sys.exit("Apple Silicon / ARM host: needs an arm64 Ubuntu image, not supported yet")
    if any(line.startswith(f'"{VM}" ') for line in vbm("list", "vms", ro=True).splitlines()):
        sys.exit(f"VM {VM} already exists: remove it first (VBoxManage unregistervm {VM} --delete)")
    if not DRY:
        prepare_state()
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
    pub = key.with_suffix(".pub").read_text().strip() if not DRY else "<public key>"
    net = network()

    # Install phase: NAT, because the installer must reach the Ubuntu mirrors. No repo code runs yet.
    vbm("createvm", "--name", VM, "--ostype", "Ubuntu_64", "--basefolder", STATE / "vms", "--register")
    vbm("modifyvm", VM, "--memory", a.ram, "--cpus", a.cpus, "--vram", 128, "--graphicscontroller", "vmsvga",
        "--nic1", "nat", *(item for i in range(2, 9) for item in (f"--nic{i}", "none")),
        "--boot1", "disk", "--boot2", "dvd", "--boot3", "none", "--boot4", "none",
        "--clipboard-mode", "disabled", "--drag-and-drop", "disabled",
        "--usb-ohci", "off", "--usb-ehci", "off", "--usb-xhci", "off")
    disk = STATE / "vms" / VM / f"{VM}.vdi"
    vbm("createmedium", "disk", "--filename", disk, "--size", 61440)
    vbm("storagectl", VM, "--name", "SATA", "--add", "sata")
    vbm("storageattach", VM, "--storagectl", "SATA", "--port", 0, "--device", 0, "--type", "hdd", "--medium", disk)
    late = (f"mkdir -p /home/{USER}/.ssh && echo {shlex.quote(pub)} > /home/{USER}/.ssh/authorized_keys && "
            f"chown -R 1000:1000 /home/{USER}/.ssh && chmod 700 /home/{USER}/.ssh && chmod 600 /home/{USER}/.ssh/authorized_keys && "
            "apt-get install -y openssh-server virtualbox-guest-utils virtualbox-guest-x11 && ssh-keygen -A && echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/10-snp.conf && "
            f"echo '{USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{USER} && "
            "printf complete > /var/lib/snp-install-complete")
    vbm("unattended", "install", VM, "--iso", iso, "--user", USER, "--password-file", pw_file, "--full-user-name", USER,
        "--no-install-additions", "--post-install-command", late, "--start-vm", "gui")
    wait("the installed guest and completed post-install configuration", install_complete, 90)
    stop_vm()
    if a.baseline:  # test control: a plain NAT VM with no sandbox, to prove the attack suite can detect leaks
        vbm_unlocked("modifyvm", VM, "--natpf1", "ssh,tcp,127.0.0.1,2223,,22")
        return print(f"\nbaseline VM {VM} built on NAT, NO sandbox. `VBoxManage startvm {VM}`, then ssh -p 2223 -i {key} {USER}@127.0.0.1. Delete it when done.")
    vbm_unlocked("modifyvm", VM, "--nic1", "hostonly", "--hostonlyadapter1", net)  # from here on: no NAT, proxy is the only way out

    provision()


# ---- run -------------------------------------------------------------------------------------------------------

def stop_vm():
    if DRY:
        return print("+ VBoxManage controlvm", VM, "acpipowerbutton   (repeated, then poweroff if the guest ignores it)")
    state = vm_state()
    if state == "saved":
        vbm_unlocked("discardstate", VM)
        return wait("the saved VM to power off", lambda: vm_state() == "poweroff", 1)
    if state in ("paused", "stuck"):
        vbm("controlvm", VM, "poweroff")
        return wait("the paused VM to power off", lambda: vm_state() == "poweroff", 1)
    if state != "running":
        return
    print("waiting for the VM to power off ...", flush=True)
    for _ in range(6):  # the ACPI button is ignored while the guest is still booting, so press it again every 30 s
        vbm("controlvm", VM, "acpipowerbutton", check=False)
        for _ in range(6):
            time.sleep(5)
            if vm_state() == "poweroff":
                return
    vbm("controlvm", VM, "poweroff", check=False)  # guest did not react in 3 min: pull the plug
    wait("the VM to power off", lambda: vm_state() == "poweroff", 1)


def up(start_vm=True):
    if not DRY:
        prepare_state()
    venv()
    if not DRY:
        check_vm_isolation()
    # firewall.py prompts for sudo (Linux/macOS); on Windows run this script from an elevated terminal
    if DRY:
        print("+", exe("python"), HERE / "firewall.py", "up")
    else:
        subprocess.run([exe("python"), str(HERE / "firewall.py"), "up"], check=True)  # not captured: sudo needs the terminal
    env = load_env()
    if not (env.get("SANDBOX_OAUTH_TOKEN") or env.get("SANDBOX_ANTHROPIC_KEY")):
        print("note: no SANDBOX_OAUTH_TOKEN in .env, Claude Code in the VM will not authenticate")
    if not proxy_up():
        if not DRY and (proxy_process() is not None or port_open()):
            sys.exit("proxy port is occupied or a managed proxy is unhealthy; run down and check the listener before retrying")
        cmd = [exe("python"), "-c", PROXY_ENTRY, "--listen-host", HOST_IP, "--listen-port", PORT, "--set", f"confdir={STATE / 'mitmproxy'}",
               "-s", HERE / "proxy_addon.py"]
        trusted = proxy_ca_bundle()
        if trusted:
            cmd += ["--set", f"ssl_verify_upstream_trusted_ca={trusted}"]
        if DRY:
            print("+", " ".join(map(str, cmd)))
        else:
            env["SNP_PROXY_PIDFILE"] = str(STATE / "proxy.pid")
            kw = {"creationflags": subprocess.CREATE_NO_WINDOW} if WIN else {"start_new_session": True}
            with (STATE / "proxy.out").open("a", encoding="utf-8") as output:
                p = subprocess.Popen(list(map(str, cmd)), env=env, cwd=HERE, stdout=output,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kw)

        def ready():
            if p.poll() is not None:
                sys.exit(f"proxy exited ({p.returncode}); see {STATE / 'proxy.out'}")
            return proxy_up()
        wait("the proxy to listen", ready if not DRY else proxy_up, 1)
    if start_vm and vm_state() != "running":
        vbm_unlocked("startvm", VM, "--type", "gui")


def down(_=None):
    stop_vm()
    pid = STATE / "proxy.pid"
    if pid.exists() and not DRY:
        p = proxy_process()
        if p:
            import psutil
            try:
                p.terminate()
                p.wait(timeout=10)
            except psutil.NoSuchProcess:
                pass
            except psutil.TimeoutExpired:
                sys.exit("proxy did not stop; keeping its PID record for a later retry")
        pid.unlink()


def has_snapshot():
    return bool(re.search(r"Name: clean \(UUID:", vbm("snapshot", VM, "list", ro=True, check=False)))


def snapshot(_=None):
    """Save the current, working VM as the state `reset` returns to. Replaces an older one."""
    stop_vm()
    if has_snapshot():
        vbm_unlocked("snapshot", VM, "delete", "clean")
    vbm_unlocked("snapshot", VM, "take", "clean")
    print("saved snapshot `clean`; `python3 snp.py reset` returns to it")


def reset(_=None):
    if not DRY and not has_snapshot():
        sys.exit("no snapshot yet: get the VM working, then run `python3 snp.py snapshot`")
    state = vm_state() if not DRY else ""
    if DRY or state != "poweroff":
        if state == "saved":
            vbm_unlocked("discardstate", VM)
        else:
            vbm("controlvm", VM, "poweroff", check=False)
        wait("the VM to power off", lambda: vm_state() == "poweroff", 2)
    vbm_unlocked("snapshot", VM, "restore", "clean")
    up()


def status(_=None):
    print(f"VM {VM}: {vm_state() or 'not found'}\nproxy {HOST_IP}:{PORT}: {'listening' if proxy_up() else 'down'}")
    print(vbm("snapshot", VM, "list", ro=True, check=False).strip() or "no snapshots")


def main():
    global DRY, VM, STATE
    if sys.version_info < (3, 12):  # mitmproxy needs 3.12+; fail here, not in pip
        sys.exit(f"Python 3.12 or newer is required (this is {sys.version.split()[0]}): https://www.python.org/downloads/")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--name", default=VM, help="VM name, default %(default)s; lets a second VM exist next to the first")
    p.add_argument("--state-dir", type=Path, default=Path(os.environ.get("SNP_STATE_DIR", STATE)),
                   help="state folder (VM disks, ISO, keys, proxy and venv); use the same path for every command")
    p.add_argument("--ca-cert", type=Path, action="append", default=[],
                   help="public host/network CA for the VM and proxy during setup/provision (repeatable)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--baseline", action="store_true", help="test control: stop after the install, leave the VM on NAT with no sandbox")
    s.add_argument("--iso")
    s.add_argument("--password", default="dev", help="console login only (SSH is key-only, sudo needs none); default %(default)s")
    s.add_argument("--ram", type=int, default=8192, help="MB, default %(default)s (4096 is enough for a small frontend)")
    s.add_argument("--cpus", type=int, default=min(4, os.cpu_count() or 2))
    for c in ("up", "provision", "report", "snapshot", "down", "reset", "status"):
        sub.add_parser(c)
    a = p.parse_args()
    DRY, VM, STATE = a.dry_run, a.name, a.state_dir.expanduser().resolve()
    if not VM or VM in (".", "..") or Path(VM).name != VM:
        p.error("--name must be a folder name")
    if WIN and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", VM) or VM.endswith(".")
            or VM.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}):
        p.error("--name must be a safe folder name (letters, digits, dash, underscore or dot; no Windows device names)")
    if not DRY and a.cmd in ("setup", "up", "provision", "reset"):
        prepare_state()
        venv()
    # The user only needs stdlib Python; psutil and mitmproxy live in our private runtime.
    if (not DRY and Path(exe("python")).exists()
            and Path(sys.prefix).resolve() != (STATE / "venv").resolve()):
        os.execv(exe("python"), [exe("python"), str(HERE / "snp.py"), *sys.argv[1:]])
    if a.ca_cert:
        if a.cmd not in ("setup", "provision"):
            p.error("--ca-cert applies only to setup or provision")
        store_trusted_ca(a.ca_cert)
    {"setup": setup, "up": lambda a: up(), "provision": provision, "report": report, "snapshot": snapshot, "down": down, "reset": reset, "status": status}[a.cmd](a)


if __name__ == "__main__":
    main()
