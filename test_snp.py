"""python3 test_snp.py  (offline: VBoxManage, ssh and the firewall are faked)"""
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import snp  # noqa: E402


def exits(fn, *words):
    try:
        fn()
    except SystemExit as e:
        assert all(w in str(e.code) for w in words), e.code
        return
    raise AssertionError("expected SystemExit")


def test_snapshot_detection():
    # regression: `snapshot list --brief` is rejected by VirtualBox 7.1, so reset never saw the snapshot
    seen = []
    with mock.patch.object(snp, "run", side_effect=lambda cmd, **kw: seen.append(cmd) or "   Name: clean (UUID: 1) *\n"), \
            mock.patch("shutil.which", return_value="VBoxManage"):
        assert snp.has_snapshot()
    assert "--brief" not in seen[0] and seen[0][1:4] == ["snapshot", snp.VM, "list"], seen
    with mock.patch.object(snp, "vbm", return_value=""):
        assert not snp.has_snapshot()


def test_reset_needs_snapshot():
    with mock.patch.object(snp, "vbm", return_value=""):
        exits(snp.reset, "no snapshot yet", "snapshot")


def test_start_retries_while_locked():
    # regression: startvm right after poweroff/restore fails with "already locked by a session"
    calls = []

    def vbm(*a, **kw):
        calls.append(a[0])
        if a[0] == "startvm" and calls.count("startvm") < 3:
            sys.exit("VBoxManage: error: The machine 'ubuntu-dev' is already locked by a session")
        return ""
    with mock.patch.object(snp, "vbm", vbm), mock.patch.object(snp, "venv"), mock.patch.object(snp, "proxy_up", return_value=True), \
            mock.patch.object(snp, "load_env", return_value={"SANDBOX_OAUTH_TOKEN": "x"}), mock.patch.object(snp, "vm_state", return_value="poweroff"), \
            mock.patch("subprocess.run"), mock.patch("time.sleep"):
        snp.up()
    assert calls.count("startvm") == 3
    with mock.patch.object(snp, "vbm", side_effect=SystemExit("boom")), mock.patch.object(snp, "venv"), \
            mock.patch.object(snp, "proxy_up", return_value=True), mock.patch.object(snp, "load_env", return_value={"SANDBOX_OAUTH_TOKEN": "x"}), \
            mock.patch.object(snp, "vm_state", return_value="poweroff"), mock.patch("subprocess.run"):
        exits(snp.up, "boom")  # other errors are not retried


def test_dry_run_writes_nothing():
    with tempfile.TemporaryDirectory() as d, mock.patch.object(snp, "STATE", Path(d) / ".snp"), mock.patch.object(snp, "DRY", True), \
            mock.patch.object(snp, "vbm", return_value=""), mock.patch.object(snp, "network", return_value="vboxnet0"), \
            mock.patch.object(snp, "find_iso", return_value=Path("x.iso")), mock.patch("builtins.print"):
        snp.setup(mock.Mock(iso=None, ram=4096, cpus=2, password='dev', baseline=False))
        assert not (Path(d) / ".snp").exists()  # no password, key or venv in a dry run


def test_setup_refuses_existing_vm():
    with mock.patch.object(snp, "vbm", return_value=f'"{snp.VM}" {{uuid}}\n'):
        exits(lambda: snp.setup(mock.Mock(iso=None, ram=4096, cpus=2, password='dev', baseline=False)), "already exists")


def test_network_finds_adapter_by_address():
    listing = ("Name:            vboxnet1\nIPAddress:       10.0.0.1\n\n"
               "Name:            VirtualBox Host-Only Ethernet Adapter\nIPAddress:       192.168.56.1\n")
    with mock.patch.object(snp, "vbm", side_effect=lambda *a, **kw: listing if a[:2] == ("list", "hostonlyifs") else snp.HOST_IP + " HostInterfaceNetworking-x"):
        assert snp.network() == "VirtualBox Host-Only Ethernet Adapter"
    with mock.patch.object(snp, "vm_prop", return_value="10.0.2.15"):
        assert snp.VirtualBox(snp).ssh_address() is None


def test_name_selects_the_vm():
    # a second VM must not touch the first: every command acts on --name
    seen = []
    with mock.patch.object(snp, "vbm", side_effect=lambda *a, **kw: seen.append(a) or ""), mock.patch.object(snp, "VM", snp.VM), mock.patch.object(snp, "DRY", False), \
            mock.patch("sys.argv", ["snp.py", "--profile", "virtualbox-amd64", "--name", "snp-test", "--dry-run", "status"]), mock.patch("builtins.print"):
        snp.main()
        assert snp.VM == "snp-test"
    assert seen and all("snp-test" in a and "ubuntu-dev" not in a for a in seen), seen


def test_stop_vm_forces_poweroff():
    # regression: a guest still booting ignores the ACPI button; stop_vm must press again, then power off hard
    calls, states = [], iter(["running"] * 200 + ["poweroff"])
    with mock.patch.object(snp, "vbm", side_effect=lambda *a, **kw: calls.append(a[2]) or ""), mock.patch.object(snp, "vm_state", lambda: next(states)), \
            mock.patch("time.sleep"), mock.patch("builtins.print"):
        snp.stop_vm()
    assert calls.count("acpipowerbutton") == 6 and "poweroff" in calls, calls


def test_stop_vm_stops_when_guest_obeys():
    calls, states = [], iter(["running", "running", "poweroff"])
    with mock.patch.object(snp, "vbm", side_effect=lambda *a, **kw: calls.append(a[2]) or ""), mock.patch.object(snp, "vm_state", lambda: next(states)), \
            mock.patch("time.sleep"), mock.patch("builtins.print"):
        snp.stop_vm()
    assert calls == ["acpipowerbutton"], calls


def test_env_file():
    with tempfile.TemporaryDirectory() as d, mock.patch.object(snp, "HERE", Path(d)):
        (Path(d) / ".env").write_text("# c\nA=1\nSANDBOX_OAUTH_TOKEN='sk-x=y'\nB = \"two\"\n")
        env = snp.load_env()
    assert env["A"] == "1" and env["SANDBOX_OAUTH_TOKEN"] == "sk-x=y" and env["B"] == "two"


def test_old_python_is_refused():
    with mock.patch.object(snp.sys, "version_info", (3, 11, 0)), mock.patch.object(snp.sys, "argv", ["snp.py", "status"]):
        exits(snp.main, "3.12", "python.org")


def test_qemu_network_and_native_acceleration():
    vm = snp.Qemu(snp)
    config = dict(ram=2048, cpus=2, ssh_port=22222, firmware="/firmware.fd")
    with mock.patch.object(vm, "tool", side_effect=lambda name: name):
        command = vm.command(config, headless=True)
    network = command[command.index("-netdev") + 1]
    assert "restrict=on,ipv6=off" in network and command.count("-netdev") == 1
    assert "hostfwd=tcp:127.0.0.1:22222-:22" in network
    assert "guestfwd=tcp:10.0.2.100:3128-cmd:/usr/bin/nc 127.0.0.1 3128" in network
    assert "virt,accel=hvf" in command and "-nodefaults" in command
    assert not any(flag in command for flag in ("-virtfs", "-fsdev", "-spice", "-vnc"))
    assert any("seed.iso" in str(arg) and "readonly=on" in str(arg) for arg in command)


def test_qemu_seed_uses_shared_bootstrap():
    import json
    with tempfile.TemporaryDirectory() as d, mock.patch.object(snp, "STATE", Path(d)):
        vm = snp.Qemu(snp)
        vm.root.mkdir()
        captured = {}
        def run(cmd, **kw):
            captured.update({p.name: p.read_text() for p in (vm.root / "seed").iterdir()})
            (vm.root / "seed.iso").touch()
        script = snp.bootstrap("ssh-ed25519 PUBLIC")
        password = "quoted'\"\npassword"
        with mock.patch.object(snp, "run", side_effect=run):
            vm.write_seed("ssh-ed25519 PUBLIC", password, script)
        data = json.loads(captured["user-data"].split("\n", 1)[1])
        assert data["users"][0]["plain_text_passwd"] == password
        assert data["runcmd"] == [["bash", "-c", script]] and not data["ssh_pwauth"]
        network = json.loads(captured["network-config"])["ethernets"]["sandbox"]
        assert network["addresses"] == ["10.0.2.15/24"] and not network["dhcp6"]
        assert not network["accept-ra"] and "nameservers" not in network
        assert not (vm.root / "seed").exists()


def test_qemu_reset_requires_and_restores_firmware():
    import json
    with tempfile.TemporaryDirectory() as d, mock.patch.object(snp, "STATE", Path(d)):
        vm = snp.Qemu(snp)
        vm.root.mkdir()
        (vm.root / "disk.qcow2").touch()
        (vm.root / "vars.fd").write_bytes(b"planted")
        with mock.patch.object(vm, "tool", side_effect=lambda name: name), \
                mock.patch.object(snp, "run", return_value=json.dumps({"snapshots": [{"name": "clean"}]})) as run:
            exits(lambda: vm.snapshot(restore=True), "both disk and UEFI")
            assert not any("-a" in call.args[0] for call in run.call_args_list)
            (vm.root / "vars.clean.fd").write_bytes(b"clean")
            vm.snapshot(restore=True)
            assert (vm.root / "vars.fd").read_bytes() == b"clean"
            run.side_effect = [json.dumps({"snapshots": [{"name": "clean"}]}), "", SystemExit("disk snapshot failed")]
            exits(vm.snapshot, "disk snapshot failed")
            assert not (vm.root / "vars.clean.fd").exists()


def test_qemu_monitor_eof_and_private_directory():
    with tempfile.TemporaryDirectory() as d:
        directory = Path(d)
        vm = snp.Qemu(snp)
        with mock.patch.object(snp.Qemu, "control_dir", new_callable=mock.PropertyMock, return_value=directory), \
                mock.patch("vm_backends.socket.socket") as socket:
            stream = socket.return_value.__enter__.return_value.makefile.return_value.__enter__.return_value
            stream.readline.return_value = b""
            assert not vm.active()  # QEMU may close before its greeting during shutdown.
            directory.chmod(0o755)
            exits(vm.active, "unsafe QMP socket directory")


def test_macos_dry_setup_uses_no_virtualbox_and_writes_nothing():
    with tempfile.TemporaryDirectory() as d, mock.patch.object(snp, "STATE", Path(d) / ".snp"), \
            mock.patch.object(snp, "DRY", False), mock.patch.object(snp, "VM", "mac-test"), \
            mock.patch.object(snp, "BACKEND", snp.BACKEND), mock.patch.object(snp, "proxy_up", return_value=False), \
            mock.patch.object(snp, "vbm", side_effect=AssertionError("VirtualBox called")), \
            mock.patch("sys.argv", ["snp.py", "--dry-run", "--headless", "--profile", "macos-arm64", "setup"]), \
            mock.patch("builtins.print"):
        snp.main()
        assert not snp.STATE.exists()


for name, fn in list(globals().items()):
    if name.startswith("test_"):
        fn()
print("ok")
