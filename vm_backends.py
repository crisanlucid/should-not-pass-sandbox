"""VM operations used by snp.py. Both adapters share its provisioning and proxy."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import time


class VirtualBox:
    listen_host = "192.168.56.1"
    proxy_url = "http://192.168.56.1:3128"
    cloud_image = False
    host_firewall = True

    def __init__(self, host):
        self.host = host

    def check_new(self):
        h = self.host
        if f'"{h.VM}" ' in h.vbm("list", "vms", ro=True):
            raise SystemExit(f"VM {h.VM} already exists: use --name for another VM")

    def create(self, a, iso, pub, pw, bootstrap):
        h = self.host
        net = h.network()

        # Install phase: NAT, because the installer must reach the Ubuntu mirrors. No repo code runs yet.
        h.vbm("createvm", "--name", h.VM, "--ostype", "Ubuntu_64", "--basefolder", h.STATE / "vms", "--register")
        h.vbm("modifyvm", h.VM, "--memory", a.ram, "--cpus", a.cpus, "--vram", 128, "--graphicscontroller", "vmsvga",
            "--nic1", "nat", "--nic2", "none", "--nic3", "none", "--nic4", "none",
            "--clipboard-mode", "disabled", "--drag-and-drop", "disabled")
        disk = h.STATE / "vms" / h.VM / f"{h.VM}.vdi"
        h.vbm("createmedium", "disk", "--filename", disk, "--size", h.PROFILE["disk_mb"])
        h.vbm("storagectl", h.VM, "--name", "SATA", "--add", "sata")
        h.vbm("storageattach", h.VM, "--storagectl", "SATA", "--port", 0, "--device", 0, "--type", "hdd", "--medium", disk)
        h.vbm("unattended", "install", h.VM, "--iso", iso, "--user", h.USER, "--user-password", pw, "--full-user-name", h.USER,
            "--install-additions", "--post-install-command", bootstrap, "--start-vm", "headless" if h.HEADLESS else "gui")
        h.wait("the installer to finish (guest additions report in)", lambda: h.vm_prop("/VirtualBox/GuestAdd/Version"), 90)
        if not h.DRY:
            time.sleep(60)
        h.stop_vm()
        if a.baseline:
            h.vbm("modifyvm", h.VM, "--natpf1", "ssh,tcp,127.0.0.1,2223,,22")
            print("baseline VM built with NAT and NO sandbox")
        else:
            h.vbm("modifyvm", h.VM, "--nic1", "hostonly", "--hostonlyadapter1", net)

    def state(self):
        return self.host.vm_state()

    def ssh_address(self):
        ip = self.host.vm_prop("/VirtualBox/GuestInfo/Net/0/V4/IP")
        return (ip, 22) if ip.startswith("192.168.56.") else None

    def start(self):
        h = self.host
        if self.state() == "running":
            return
        for _ in range(12):
            try:
                h.vbm("startvm", h.VM, "--type", "headless" if h.HEADLESS else "gui")
                return
            except SystemExit as error:
                if "locked" not in str(error.code):
                    raise
                time.sleep(5)
        raise SystemExit("the VM stayed locked for 60 s")

    def stop(self, force=False):
        h = self.host
        if force:
            if h.DRY or self.state() != "poweroff":
                h.vbm("controlvm", h.VM, "poweroff", check=False)
                h.wait("the VM to power off", lambda: self.state() == "poweroff", 2)
        else:
            h.stop_vm()

    def snapshots(self):
        h = self.host
        return re.findall(r"Name: (.*?) \(UUID:", h.vbm("snapshot", h.VM, "list", ro=True, check=False))

    def snapshot(self, restore=False):
        h = self.host
        if restore:
            h.vbm("snapshot", h.VM, "restore", "clean")
        else:
            if "clean" in self.snapshots():
                h.vbm("snapshot", h.VM, "delete", "clean")
            h.vbm("snapshot", h.VM, "take", "clean")


class Qemu:
    def __init__(self, host):
        self.host = host
        self._created_config = None

    @property
    def root(self):
        return self.host.STATE / self.host.VM

    @property
    def config_path(self):
        return self.root / "qemu.json"

    listen_host = "127.0.0.1"
    proxy_url = "http://10.0.2.100:3128"
    cloud_image = True
    host_firewall = False

    @property
    def control_dir(self):
        digest = hashlib.sha256(str(self.root).encode()).hexdigest()[:16]
        return Path(f"/tmp/snp-{os.getuid()}-{digest}")

    @property
    def monitor(self):
        return self.control_dir / "qmp.sock"

    def tool(self, name):
        path = shutil.which(name)
        if not path and not self.host.DRY:
            raise SystemExit(f"{name} not found: brew install qemu")
        return path or name

    def config(self):
        if not self.config_path.exists():
            raise SystemExit(f"VM {self.host.VM} not found: run `python3 snp.py setup` first")
        return json.loads(self.config_path.read_text())

    def qmp(self, command):
        info = self.control_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SystemExit(f"unsafe QMP socket directory: {self.control_dir}; expected an owner-only directory")
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(5)
            sock.connect(str(self.monitor))
            with sock.makefile("rwb") as stream:
                greeting = stream.readline()
                if not greeting:
                    raise ConnectionError("QEMU closed its monitor")
                if "QMP" not in json.loads(greeting):
                    raise RuntimeError("invalid QMP greeting")
                for request in ("qmp_capabilities", command):
                    message = {"execute": request}
                    stream.write((json.dumps(message) + "\n").encode())
                    stream.flush()
                    while True:
                        line = stream.readline()
                        if not line:
                            raise ConnectionError("QEMU closed its monitor")
                        response = json.loads(line)
                        if "error" in response:
                            raise RuntimeError(response["error"])
                        if "return" in response:
                            break
                return response["return"]

    def active(self):
        try:
            self.qmp("query-status")
            return True
        except OSError:
            return False

    def state(self):
        if self.active():
            return "running"
        return "poweroff" if self.config_path.exists() else "not found"

    def firmware(self):
        share = Path(self.tool("qemu-system-aarch64")).absolute().parent.parent / "share" / "qemu"
        code, variables = share / "edk2-aarch64-code.fd", share / "edk2-arm-vars.fd"
        if not self.host.DRY and not (code.is_file() and variables.is_file()):
            raise SystemExit(f"QEMU ARM UEFI firmware not found in {share}; reinstall the Homebrew qemu package")
        return code, variables

    def command(self, config, headless=False):
        # Isolation is backend policy, not an overridable profile option. Each
        # guest proxy connection gets its own nc stream; there is no general NAT.
        net = ("user,id=egress,restrict=on,ipv6=off,"
               f"hostfwd=tcp:127.0.0.1:{config['ssh_port']}-:22,"
               "guestfwd=tcp:10.0.2.100:3128-cmd:/usr/bin/nc 127.0.0.1 3128")
        esc = lambda path: str(path).replace(",", ",,")
        return [self.tool("qemu-system-aarch64"), "-name", self.host.VM,
                "-machine", "virt,accel=hvf", "-cpu", "host",
                "-m", str(config["ram"]), "-smp", str(config["cpus"]), "-nodefaults", "-no-user-config",
                "-smbios", "type=1,serial=ds=nocloud",
                "-drive", f"if=pflash,format=raw,readonly=on,file={esc(config['firmware'])}",
                "-drive", f"if=pflash,format=raw,file={esc(self.root / 'vars.fd')}",
                "-drive", f"if=none,id=os,format=qcow2,file={esc(self.root / 'disk.qcow2')}",
                "-device", "virtio-blk-pci,drive=os", "-netdev", net,
                "-device", "virtio-net-pci,netdev=egress,mac=52:54:00:53:4e:50", "-device", "virtio-rng-pci",
                "-qmp", f"unix:{self.monitor},server=on,wait=off",
                "-chardev", f"socket,id=console,path={self.control_dir / 'console.sock'},server=on,wait=off,logfile={esc(self.root / 'serial.log')}",
                "-serial", "chardev:console", "-device", "virtio-gpu-pci", "-device", "qemu-xhci",
                "-device", "usb-kbd", "-device", "usb-tablet", "-display", "none" if headless else "cocoa",
                "-drive", f"if=none,id=seed,format=raw,readonly=on,file={esc(self.root / 'seed.iso')}",
                "-device", "virtio-blk-pci,drive=seed"]

    def check_new(self):
        # A failed preflight may have left only shared credentials. Reuse those,
        # while refusing any existing disk, seed, metadata or unknown VM state.
        credentials = {"id_ed25519", "id_ed25519.pub", "password", "known_hosts"}
        if self.root.exists() and any(path.name not in credentials for path in self.root.iterdir()):
            raise SystemExit(f"VM state already exists at {self.root}; use --name for another VM, or provision to resume")
        self.firmware()
        self.tool("qemu-img")

    def write_seed(self, pub, password, bootstrap):
        directory, target = self.root / "seed", self.root / "seed.iso"
        config = {"hostname": "snp", "manage_etc_hosts": True,
                  "users": [{"name": "dev", "shell": "/bin/bash", "groups": ["sudo"],
                             "lock_passwd": False, "plain_text_passwd": password, "ssh_authorized_keys": [pub]}],
                  "ssh_pwauth": False, "disable_root": True, "chpasswd": {"expire": False},
                  "runcmd": [["bash", "-c", bootstrap]]}
        network = {"version": 2, "ethernets": {"sandbox": {
            "match": {"macaddress": "52:54:00:53:4e:50"}, "dhcp4": False, "dhcp6": False,
            "accept-ra": False, "optional": True, "addresses": ["10.0.2.15/24"],
            "routes": [{"to": "default", "via": "10.0.2.2"}]}}}
        if not self.host.DRY:
            directory.mkdir(mode=0o700)
            for name, content in {"user-data": "#cloud-config\n" + json.dumps(config),
                                  "meta-data": json.dumps({"instance-id": self.host.VM, "local-hostname": "snp"}),
                                  "network-config": json.dumps(network)}.items():
                (directory / name).write_text(content)
        try:
            self.host.run(["hdiutil", "makehybrid", "-iso", "-joliet", "-default-volume-name", "cidata",
                           "-o", target, directory])
            if not self.host.DRY:
                target.chmod(0o600)
        finally:
            if not self.host.DRY:
                shutil.rmtree(directory)

    def create(self, a, image, pub, password, bootstrap):
        if self.config_path.exists() or (self.root / "disk.qcow2").exists():
            raise SystemExit(f"VM state already exists at {self.root}")
        _, variables = self.firmware()
        if not self.host.DRY:
            info = json.loads(self.host.run([self.tool("qemu-img"), "info", "--output=json", image]))
            if info["format"] != "qcow2" or info.get("backing-filename") or info.get("format-specific", {}).get("data", {}).get("data-file"):
                raise SystemExit("--image must be a standalone ARM64 Ubuntu cloud image in qcow2 format")
            shutil.copyfile(image, self.root / "disk.qcow2")
            shutil.copyfile(variables, self.root / "vars.fd")
        else:
            print("+ copy", image, "to", self.root / "disk.qcow2")
        self.host.run([self.tool("qemu-img"), "resize", self.root / "disk.qcow2", f"{self.host.PROFILE['disk_mb']}M"])
        self.write_seed(pub, password, bootstrap)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self._created_config = {"ram": a.ram, "cpus": a.cpus,
                                "ssh_port": port}
        if not self.host.DRY:
            self.config_path.write_text(json.dumps(self._created_config, indent=2) + "\n")

    def start(self):
        if self.active():
            return
        config = self.config() if self.config_path.exists() else self._created_config or {
            "ram": 8192, "cpus": 4, "ssh_port": "<allocated port>"}
        config["firmware"] = str(self.firmware()[0])
        command = self.command(config, self.host.HEADLESS)
        if self.host.DRY:
            self.host.run(command)
            return
        if not self.config_path.exists():
            raise SystemExit(f"VM {self.host.VM} not found")
        self.control_dir.mkdir(mode=0o700, exist_ok=True)
        info = self.control_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SystemExit(f"unsafe QMP socket directory: {self.control_dir}")
        for name in ("qmp.sock", "console.sock"):
            (self.control_dir / name).unlink(missing_ok=True)
        with (self.root / "qemu.log").open("a") as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        for _ in range(100):
            if process.poll() is not None:
                raise SystemExit(f"QEMU exited ({process.returncode}); check {self.root / 'qemu.log'}")
            if self.active():
                return
            time.sleep(0.1)
        raise SystemExit(f"QEMU monitor did not start; check {self.root / 'qemu.log'}")

    def stop(self, force=False):
        if self.host.DRY:
            print("+ QMP", "quit" if force else "system_powerdown (then quit if ignored)")
            return
        if not self.active():
            return
        if not force:
            print("waiting for the VM to power off ...", flush=True)
            self.qmp("system_powerdown")
            for _ in range(60):
                if not self.active():
                    return
                time.sleep(1)
        self.qmp("quit")
        self.host.wait("QEMU to exit", lambda: not self.active(), 1)

    def ssh_address(self):
        if not self.config_path.exists():
            return ("127.0.0.1", self._created_config["ssh_port"]) if self._created_config else None
        return ("127.0.0.1", self.config()["ssh_port"])

    def _disk_snapshots(self):
        disk = self.root / "disk.qcow2"
        if not disk.exists():
            return []
        info = json.loads(self.host.run([self.tool("qemu-img"), "info", "--force-share", "--output=json", disk], ro=True))
        return [item["name"] for item in info.get("snapshots", [])]

    def snapshots(self):
        return [name for name in self._disk_snapshots() if (self.root / f"vars.{name}.fd").exists()]

    def snapshot(self, restore=False):
        if restore:
            return self.restore_snapshot()
        name = "clean"
        # The workflow stops the VM first. Stage firmware before replacing the disk snapshot.
        pending = self.root / f"vars.{name}.fd.tmp"
        if not self.host.DRY:
            shutil.copyfile(self.root / "vars.fd", pending)
            # A failed replacement must not pair a new disk snapshot with old firmware.
            (self.root / f"vars.{name}.fd").unlink(missing_ok=True)
        if name in self._disk_snapshots():
            self.host.run([self.tool("qemu-img"), "snapshot", "-d", name, self.root / "disk.qcow2"])
        self.host.run([self.tool("qemu-img"), "snapshot", "-c", name, self.root / "disk.qcow2"])
        if not self.host.DRY:
            pending.replace(self.root / f"vars.{name}.fd")

    def restore_snapshot(self):
        name = "clean"
        if not self.host.DRY and name not in self.snapshots():
            raise SystemExit(f"no complete snapshot {name}: both disk and UEFI variables are required")
        self.host.run([self.tool("qemu-img"), "snapshot", "-a", name, self.root / "disk.qcow2"])
        if not self.host.DRY:
            shutil.copyfile(self.root / f"vars.{name}.fd", self.root / "vars.fd")
