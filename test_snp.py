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
    with mock.patch.object(snp, "vbm", vbm), mock.patch.object(snp, "venv"), mock.patch.object(snp, "prepare_state"), mock.patch.object(snp, "check_vm_isolation"), mock.patch.object(snp, "proxy_up", return_value=True), \
            mock.patch.object(snp, "load_env", return_value={"SANDBOX_OAUTH_TOKEN": "x"}), mock.patch.object(snp, "vm_state", return_value="poweroff"), \
            mock.patch("subprocess.run"), mock.patch("time.sleep"):
        snp.up()
    assert calls.count("startvm") == 3
    with mock.patch.object(snp, "vbm", side_effect=SystemExit("boom")), mock.patch.object(snp, "venv"), mock.patch.object(snp, "prepare_state"), mock.patch.object(snp, "check_vm_isolation"), \
            mock.patch.object(snp, "proxy_up", return_value=True), mock.patch.object(snp, "load_env", return_value={"SANDBOX_OAUTH_TOKEN": "x"}), \
            mock.patch.object(snp, "vm_state", return_value="poweroff"), mock.patch("subprocess.run"):
        exits(snp.up, "boom")  # other errors are not retried


def test_dry_run_writes_nothing():
    with tempfile.TemporaryDirectory() as d, mock.patch.object(snp, "STATE", Path(d) / ".snp"), mock.patch.object(snp, "DRY", True), \
            mock.patch.object(snp, "vbm", return_value=""), mock.patch.object(snp, "network", return_value="vboxnet0"), \
            mock.patch.object(snp, "find_iso", return_value=Path("x.iso")), \
            mock.patch.object(snp.platform, "machine", return_value="AMD64"), mock.patch("builtins.print"):
        snp.setup(mock.Mock(iso=None, ram=4096, cpus=2, password='dev', baseline=False))
        assert not (Path(d) / ".snp").exists()  # no password, key or venv in a dry run


def test_setup_refuses_existing_vm():
    with mock.patch.object(snp, "vbm", return_value=f'"{snp.VM}" {{uuid}}\n'), \
            mock.patch.object(snp.platform, "machine", return_value="AMD64"):
        exits(lambda: snp.setup(mock.Mock(iso=None, ram=4096, cpus=2, password='dev', baseline=False)), "already exists")


def test_network_finds_adapter_by_address():
    listing = ("Name:            vboxnet1\nIPAddress:       10.0.0.1\n\n"
               "Name:            VirtualBox Host-Only Ethernet Adapter\nIPAddress:       192.168.56.1\nNetworkMask:     255.255.255.0\n")
    dhcp = "NetworkName: HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter\nEnabled: Yes\n"
    with mock.patch.object(snp, "vbm", side_effect=lambda *a, **kw: listing if a[:2] == ("list", "hostonlyifs") else dhcp):
        assert snp.network() == "VirtualBox Host-Only Ethernet Adapter"


def test_name_selects_the_vm():
    # a second VM must not touch the first: every command acts on --name
    seen = []
    with mock.patch.object(snp, "vbm", side_effect=lambda *a, **kw: seen.append(a) or ""), mock.patch.object(snp, "VM", snp.VM), mock.patch.object(snp, "DRY", False), \
            mock.patch("sys.argv", ["snp.py", "--name", "snp-test", "--dry-run", "status"]), mock.patch("builtins.print"):
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


for name, fn in list(globals().items()):
    if name.startswith("test_"):
        fn()
print("ok")
