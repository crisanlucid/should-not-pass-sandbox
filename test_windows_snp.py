"""Offline Windows regressions: no VM, firewall, SSH connection, or download runs."""
import base64
import io
import json
import os
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import Mock, patch

import snp


class WindowsPathsTests(unittest.TestCase):
    def test_ssh_known_hosts_quotes_spaces_and_uses_forward_slashes(self):
        with patch.object(snp, "STATE", PureWindowsPath(r"C:\Users\Developer Name\Sandbox State")), \
                patch.object(snp, "VM", "ubuntu-dev"):
            options = snp.ssh_options()
        self.assertEqual(str(options[options.index("-i") + 1]),
                         r"C:\Users\Developer Name\Sandbox State\ubuntu-dev\id_ed25519")
        self.assertIn('UserKnownHostsFile="C:/Users/Developer Name/Sandbox State/ubuntu-dev/known_hosts"', options)
        self.assertEqual(options[options.index("-F") + 1], "none")
        self.assertIn("ForwardAgent=no", options)
        self.assertIn("ForwardX11=no", options)
        self.assertIn("ClearAllForwardings=yes", options)
        self.assertIn("IdentitiesOnly=yes", options)
        self.assertIn("BatchMode=yes", options)

    def test_guest_script_copy_normalizes_crlf_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            content = b"#!/bin/bash\r\nset -e\r\necho hello\r\n"
            (source / "setup-dev.sh").write_bytes(content)
            extra = source / "ca.pem"
            extra.write_bytes(b"certificate\r\n")
            copied = []

            def capture(command, **kwargs):
                self.assertEqual(command[0], "scp")
                self.assertEqual(command[-2:], [extra, "dev@192.168.56.100:"])
                copied.append(Path(command[-3]).read_bytes())

            with patch.object(snp, "HERE", source), patch.object(snp, "DRY", False), \
                    patch.object(snp, "run", side_effect=capture):
                snp.copy_guest_scripts(["-o", "BatchMode=yes"], "dev@192.168.56.100", ["setup-dev.sh"], [extra])
            self.assertEqual(copied, [content.replace(b"\r\n", b"\n")])
            self.assertEqual((source / "setup-dev.sh").read_bytes(), content)
            self.assertEqual(extra.read_bytes(), b"certificate\r\n")


class HostOnlyNetworkTests(unittest.TestCase):
    def test_new_adapter_is_discovered_from_list_instead_of_localized_stdout(self):
        old = {"Name": "VirtualBox Host-Only Ethernet Adapter", "IPAddress": "192.168.57.1"}
        new = {"Name": "VirtualBox Host-Only Ethernet Adapter #2", "IPAddress": "0.0.0.0"}
        with patch.object(snp, "DRY", False), \
                patch.object(snp, "hostonly_interfaces", side_effect=[[old], [old, new]]), \
                patch.object(snp, "vbm", return_value="L'interface a été créée.") as vbm:
            self.assertEqual(snp.network(), new["Name"])
        self.assertIn((("hostonlyif", "create"), {}), [(call.args, call.kwargs) for call in vbm.call_args_list])
        configure = next(call.args for call in vbm.call_args_list if call.args[:2] == ("hostonlyif", "ipconfig"))
        self.assertEqual(configure[2], new["Name"])
        self.assertIn(snp.HOST_IP, configure)

    def test_existing_disabled_dhcp_is_modified_and_enabled(self):
        name = "VirtualBox Host-Only Ethernet Adapter #2"
        adapter = {"Name": name, "IPAddress": snp.HOST_IP, "NetworkMask": "255.255.255.0"}
        dhcp = f"NetworkName: HostInterfaceNetworking-{name}\nEnabled: No\nIPAddress: 192.168.56.9\n"

        def response(*args, **kwargs):
            return dhcp if args == ("list", "dhcpservers") else ""

        with patch.object(snp, "hostonly_interfaces", return_value=[adapter]), \
                patch.object(snp, "vbm", side_effect=response) as vbm:
            self.assertEqual(snp.network(), name)
        changes = [call for call in vbm.call_args_list if call.args[0] == "dhcpserver"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].args[:2], ("dhcpserver", "modify"))
        self.assertIn("--enable", changes[0].args)
        self.assertIn("192.168.56.2", changes[0].args)
        self.assertIn("192.168.56.100", changes[0].args)
        self.assertIn("192.168.56.200", changes[0].args)
        self.assertNotEqual(changes[0].kwargs.get("check"), False)

    def test_dhcp_errors_propagate(self):
        adapter = {"Name": "adapter", "IPAddress": snp.HOST_IP, "NetworkMask": "255.255.255.0"}

        def response(*args, **kwargs):
            if args[0] == "dhcpserver":
                raise SystemExit("VirtualBox DHCP configuration failed")
            return ""

        with patch.object(snp, "hostonly_interfaces", return_value=[adapter]), \
                patch.object(snp, "vbm", side_effect=response), \
                self.assertRaisesRegex(SystemExit, "DHCP configuration failed"):
            snp.network()

    def test_wrong_existing_netmask_is_rejected_before_changes(self):
        adapter = {"Name": "adapter", "IPAddress": snp.HOST_IP, "NetworkMask": "255.255.0.0"}
        with patch.object(snp, "hostonly_interfaces", return_value=[adapter]), \
                patch.object(snp, "vbm") as vbm, self.assertRaisesRegex(SystemExit, "netmask"):
            snp.network()
        vbm.assert_not_called()

    def test_ambiguous_new_adapter_is_rejected(self):
        with patch.object(snp, "DRY", False), \
                patch.object(snp, "hostonly_interfaces", side_effect=[[], [{"Name": "one"}, {"Name": "two"}]]), \
                patch.object(snp, "vbm") as vbm, self.assertRaisesRegex(SystemExit, "identify"):
            snp.network()
        self.assertEqual([call.args for call in vbm.call_args_list], [("hostonlyif", "create")])


class VMIsolationTests(unittest.TestCase):
    def safe_config(self):
        return {"nic1": "hostonly", "hostonlyadapter1": "VirtualBox Host-Only Ethernet Adapter",
                **{f"nic{i}": "none" for i in range(2, 9)},
                "clipboard": "disabled", "draganddrop": "disabled", "usb": "off", "ehci": "off", "xhci": "off"}

    def check(self, changes):
        info = self.safe_config()
        info.update(changes)
        with patch.object(snp, "vm_info", return_value=info), \
                patch.object(snp, "hostonly_interfaces", return_value=[
                    {"Name": "VirtualBox Host-Only Ethernet Adapter", "IPAddress": snp.HOST_IP,
                     "NetworkMask": "255.255.255.0"}]):
            snp.check_vm_isolation()

    def test_safe_configuration_passes(self):
        self.check({})

    def test_bypasses_are_rejected(self):
        cases = [({"nic1": "nat"}, "NIC 1"),
                 ({"hostonlyadapter1": "some-other-network"}, "NIC 1"),
                 ({"nic2": "nat"}, "NICs 2 through 8"),
                 ({"nic8": "bridged"}, "NICs 2 through 8"),
                 ({"clipboard": "bidirectional"}, "clipboard"),
                 ({"draganddrop": "hosttoguest"}, "draganddrop"),
                 ({"usb": "on"}, "usb"), ({"ehci": "on"}, "ehci"), ({"xhci": "on"}, "xhci"),
                 ({"SharedFolderNameMachineMapping1": "host-files"}, "shared folders")]
        for changes, message in cases:
            with self.subTest(changes=changes), self.assertRaisesRegex(SystemExit, message):
                self.check(changes)

    def test_missing_isolation_fields_are_rejected(self):
        with patch.object(snp, "vm_info", return_value={}), \
                patch.object(snp, "hostonly_interfaces", return_value=[]), \
                self.assertRaisesRegex(SystemExit, "unsafe VM configuration"):
            snp.check_vm_isolation()

    def test_wrong_missing_or_ambiguous_hostonly_subnet_is_rejected(self):
        adapter = {"Name": "VirtualBox Host-Only Ethernet Adapter", "IPAddress": snp.HOST_IP,
                   "NetworkMask": "255.255.255.0"}
        cases = [[{key: value for key, value in adapter.items() if key != "NetworkMask"}],
                 [{**adapter, "NetworkMask": "255.255.0.0"}],
                 [adapter, {**adapter, "Name": "Duplicate host-only adapter"}]]
        for adapters in cases:
            with self.subTest(adapters=adapters), patch.object(snp, "vm_info", return_value=self.safe_config()), \
                    patch.object(snp, "hostonly_interfaces", return_value=adapters), \
                    self.assertRaisesRegex(SystemExit, "NIC 1"):
                snp.check_vm_isolation()


class ProxyOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        self.pid = self.state / "proxy.pid"
        mock = patch.object(snp, "STATE", self.state)
        mock.start()
        self.addCleanup(mock.stop)
        self.process = Mock()
        self.process.create_time.return_value = 12345.0
        self.process.cmdline.return_value = [str(self.state / "venv" / "Scripts" / "python.exe"), "-c", snp.PROXY_ENTRY,
                                                "--set", f"confdir={self.state / 'mitmproxy'}",
                                                "-s", str(snp.HERE / "proxy_addon.py")]

    def record(self, created=12345.0):
        self.pid.write_text(json.dumps({"pid": 111, "created": created}), encoding="utf-8")

    def test_managed_proxy_is_identified(self):
        self.record()
        with patch("psutil.Process", return_value=self.process) as process:
            self.assertIs(snp.proxy_process(), self.process)
        process.assert_called_once_with(111)

    def test_reused_pid_with_different_creation_time_is_rejected(self):
        self.record(created=12344.0)
        with patch("psutil.Process", return_value=self.process):
            self.assertIsNone(snp.proxy_process())

    def test_another_program_or_checkout_is_rejected(self):
        self.record()
        for command in (["unrelated.exe"],
                        ["python.exe", "-c", snp.PROXY_ENTRY, "-s", str(snp.HERE / "proxy_addon.py"),
                         "--set", "confdir=C:/other-checkout/mitmproxy"]):
            with self.subTest(command=command), patch("psutil.Process", return_value=self.process):
                self.process.cmdline.return_value = command
                self.assertIsNone(snp.proxy_process())

    def test_legacy_numeric_pid_cannot_terminate_unrelated_process(self):
        self.pid.write_text("111", encoding="utf-8")
        with patch.object(snp, "DRY", False), patch.object(snp, "stop_vm"), \
                patch("psutil.Process", return_value=self.process):
            snp.down()
        self.process.terminate.assert_not_called()
        self.assertFalse(self.pid.exists())

    def test_shutdown_terminates_identified_proxy(self):
        self.record()
        with patch.object(snp, "DRY", False), patch.object(snp, "stop_vm"), \
                patch("psutil.Process", return_value=self.process):
            snp.down()
        self.process.terminate.assert_called_once()
        self.process.wait.assert_called_once_with(timeout=10)
        self.assertFalse(self.pid.exists())

    def test_unrelated_listener_prevents_vm_start(self):
        with patch.object(snp, "DRY", False), patch.object(snp, "venv"), patch.object(snp, "prepare_state"), \
                patch.object(snp, "check_vm_isolation"), patch.object(snp, "load_env", return_value={}), \
                patch.object(snp, "proxy_up", return_value=False), patch.object(snp, "proxy_process", return_value=None), \
                patch.object(snp, "port_open", return_value=True), patch.object(snp.subprocess, "run"), \
                patch.object(snp.subprocess, "Popen") as start_proxy, patch.object(snp, "vbm") as vbm, \
                self.assertRaisesRegex(SystemExit, "proxy port is occupied"):
            snp.up()
        start_proxy.assert_not_called()
        vbm.assert_not_called()


class PrivateStateTests(unittest.TestCase):
    def test_drive_home_source_ancestor_and_git_checkout_are_rejected_before_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "projects" / "source"
            source.mkdir(parents=True)
            home = root / "home"
            home.mkdir()
            checkout = root / "other-checkout"
            checkout.mkdir()
            # Worktrees use a .git file; normal clones use a directory. Both exist().
            (checkout / ".git").write_text("gitdir: somewhere-else\n", encoding="utf-8")
            for state in (Path(root.anchor), home, source, source.parent, checkout):
                with self.subTest(state=state), patch.object(snp, "STATE", state), \
                        patch.object(snp, "HERE", source), patch.object(snp, "DRY", False), \
                        patch.object(Path, "home", return_value=home), patch.object(Path, "mkdir") as mkdir, \
                        patch.object(snp, "run") as run, self.assertRaisesRegex(SystemExit, "dedicated state folder"):
                    snp.prepare_state()
                mkdir.assert_not_called()
                run.assert_not_called()

    def test_windows_nested_state_gets_inheritable_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "nested" / "développeur's sandbox state"
            with patch.object(snp, "STATE", state), patch.object(snp, "WIN", True), \
                    patch.object(snp, "DRY", False), patch.object(snp, "run", return_value="SNP_STATE_PRIVATE\n") as run:
                snp.prepare_state()
            self.assertTrue(state.is_dir())
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertIn("-NoProfile", command)
        self.assertIn("-NonInteractive", command)
        self.assertIn("-EncodedCommand", command)
        script = base64.b64decode(command[-1]).decode("utf-16le")
        self.assertIn(str(state).replace("'", "''"), script)
        self.assertIn("$ErrorActionPreference = 'Stop'", script)
        self.assertIn("$env:PSModulePath = Join-Path $PSHOME 'Modules'", script)
        self.assertIn("Import-Module ($PSHOME + '\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1')", script)
        self.assertIn("$directory.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)", script)
        self.assertIn("SetAccessRuleProtection($true, $false)", script)
        self.assertIn("foreach ($entry in $existing)", script)
        self.assertIn("RemoveAccessRuleSpecific($entry)", script)
        self.assertIn("WindowsIdentity]::GetCurrent().User", script)
        self.assertIn("SecurityIdentifier]::new('S-1-5-18')", script)
        self.assertIn("SecurityIdentifier]::new('S-1-5-32-544')", script)
        self.assertIn("FileSystemRights]::FullControl", script)
        self.assertIn("'ContainerInherit, ObjectInherit'", script)
        self.assertIn("PropagationFlags]::None", script)
        self.assertIn("AccessControlType]::Allow", script)
        self.assertIn("$directory.SetAccessControl($acl)", script)
        self.assertLess(script.index("RemoveAccessRuleSpecific"), script.index("AddAccessRule"))
        self.assertIn("$acl.AreAccessRulesProtected", script)
        self.assertIn("$acl.GetAccessRules", script)

    def test_silent_powershell_exit_cannot_claim_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(snp, "STATE", Path(directory) / "state"), patch.object(snp, "WIN", True), \
                patch.object(snp, "DRY", False), patch.object(snp, "run", return_value=""), \
                self.assertRaisesRegex(SystemExit, "did not verify private state permissions"):
            snp.prepare_state()

    def test_windows_permission_failure_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(snp, "STATE", Path(directory) / "state"), patch.object(snp, "WIN", True), \
                patch.object(snp, "DRY", False), \
                patch.object(snp, "run", side_effect=SystemExit("ACL failed")), \
                self.assertRaisesRegex(SystemExit, "ACL failed"):
            snp.prepare_state()

    def test_dry_run_does_not_create_state_or_change_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "does-not-exist"
            with patch.object(snp, "STATE", state), patch.object(snp, "DRY", True), \
                    patch.object(snp, "run") as run:
                snp.prepare_state()
            self.assertFalse(state.exists())
        run.assert_not_called()


class RuntimeCommandTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name).resolve() / "sandbox state"
        for attribute, value in (("STATE", self.state), ("VM", "ubuntu-dev"), ("DRY", False), ("WIN", True)):
            mock = patch.object(snp, attribute, value)
            mock.start()
            self.addCleanup(mock.stop)
        self.environment = patch.dict(os.environ, {}, clear=False)
        self.environment.start()
        os.environ.pop("SNP_STATE_DIR", None)
        self.addCleanup(self.environment.stop)
        self.runtime = self.state / "venv" / "Scripts" / "python.exe"

    def create_runtime(self):
        self.runtime.parent.mkdir(parents=True, exist_ok=True)
        self.runtime.touch()

    def test_clean_host_bootstraps_then_reexecutes_same_command_in_private_runtime(self):
        arguments = ["snp.py", "--state-dir", str(self.state), "--name", "windows-test", "up"]
        events = []

        def install():
            events.append("venv")
            self.create_runtime()

        with patch.object(snp.sys, "argv", arguments), patch.object(snp.sys, "prefix", str(self.state.parent)), \
                patch.object(snp, "prepare_state", side_effect=lambda: events.append("permissions")), \
                patch.object(snp, "venv", side_effect=install), patch.object(snp, "up") as up, \
                patch.object(snp.os, "execv", side_effect=SystemExit(77)) as execute, \
                self.assertRaises(SystemExit) as error:
            snp.main()
        self.assertEqual(error.exception.code, 77)
        self.assertEqual(events, ["permissions", "venv"])
        self.assertEqual(execute.call_args.args,
                         (str(self.runtime), [str(self.runtime), str(snp.HERE / "snp.py"), *arguments[1:]]))
        up.assert_not_called()

    def test_private_runtime_does_not_reexecute_itself(self):
        self.create_runtime()
        with patch.object(snp.sys, "argv", ["snp.py", "--state-dir", str(self.state), "up"]), \
                patch.object(snp.sys, "prefix", str(self.state / "venv")), \
                patch.object(snp, "prepare_state"), patch.object(snp, "venv"), patch.object(snp, "up") as up, \
                patch.object(snp.os, "execv") as execute:
            snp.main()
        execute.assert_not_called()
        up.assert_called_once()

    def test_dry_run_uses_selected_state_without_bootstrapping_or_reexec(self):
        self.create_runtime()
        with patch.object(snp.sys, "argv", ["snp.py", "--state-dir", str(self.state), "--dry-run", "up"]), \
                patch.object(snp, "prepare_state") as prepare, patch.object(snp, "venv") as venv, \
                patch.object(snp.os, "execv") as execute, patch.object(snp, "up") as up:
            snp.main()
            self.assertEqual(snp.STATE, self.state.resolve())
            self.assertTrue(snp.DRY)
        up.assert_called_once()
        prepare.assert_not_called()
        venv.assert_not_called()
        execute.assert_not_called()

    def test_state_directory_can_come_from_environment(self):
        with patch.dict(os.environ, {"SNP_STATE_DIR": str(self.state)}), \
                patch.object(snp.sys, "argv", ["snp.py", "--dry-run", "status"]), patch.object(snp, "status"):
            snp.main()
            self.assertEqual(snp.STATE, self.state.resolve())

    def test_explicit_state_directory_overrides_environment(self):
        alternate = self.state.parent / "other state"
        with patch.dict(os.environ, {"SNP_STATE_DIR": str(alternate)}), \
                patch.object(snp.sys, "argv", ["snp.py", "--state-dir", str(self.state), "--dry-run", "status"]), \
                patch.object(snp, "status"):
            snp.main()
            self.assertEqual(snp.STATE, self.state.resolve())

    def test_unsafe_windows_names_fail_before_runtime_or_action(self):
        for name in ("../escape", "..\\escape", "CON", "con.txt", "NUL", "COM1", "LPT9", "name.", "name with spaces", ""):
            with self.subTest(name=name), patch.object(snp.sys, "argv", ["snp.py", "--name", name, "up"]), \
                    patch.object(snp, "WIN", True), \
                    patch.object(snp.sys, "stderr", io.StringIO()), patch.object(snp, "prepare_state") as prepare, \
                    patch.object(snp, "venv") as venv, patch.object(snp, "up") as up, \
                    self.assertRaises(SystemExit) as error:
                snp.main()
            self.assertEqual(error.exception.code, 2)
            prepare.assert_not_called()
            venv.assert_not_called()
            up.assert_not_called()


class GuestInstallationTests(unittest.TestCase):
    def test_down_powers_off_saved_and_paused_gui_states(self):
        for state, expected in (("saved", ("discardstate", snp.VM)),
                                ("paused", ("controlvm", snp.VM, "poweroff"))):
            with self.subTest(state=state), patch.object(snp, "DRY", False), \
                    patch.object(snp, "vm_state", side_effect=[state, "poweroff"]), \
                    patch.object(snp, "vbm") as vbm, patch.object(snp.time, "sleep"):
                snp.stop_vm()
            vbm.assert_called_once_with(*expected)

    def test_reset_discards_saved_gui_memory_before_restoring_clean(self):
        with patch.object(snp, "DRY", False), patch.object(snp, "has_snapshot", return_value=True), \
                patch.object(snp, "vm_state", side_effect=["saved", "poweroff"]), \
                patch.object(snp, "vbm") as vbm, patch.object(snp, "up") as up:
            snp.reset()
        self.assertEqual([call.args for call in vbm.call_args_list],
                         [("discardstate", snp.VM), ("snapshot", snp.VM, "restore", "clean")])
        up.assert_called_once_with()

    def test_vm_configuration_retries_transient_post_shutdown_lock(self):
        with patch.object(snp, "vbm", side_effect=[SystemExit("already locked for a session (or being unlocked)"), "done"]) as vbm, \
                patch.object(snp.time, "sleep") as sleep:
            self.assertEqual(snp.vbm_unlocked("modifyvm", snp.VM, "--nic1", "hostonly"), "done")
        self.assertEqual(vbm.call_count, 2)
        sleep.assert_called_once_with(5)
        with patch.object(snp, "vbm", side_effect=SystemExit("invalid adapter")), patch.object(snp.time, "sleep") as sleep:
            with self.assertRaisesRegex(SystemExit, "invalid adapter"):
                snp.vbm_unlocked("modifyvm", snp.VM)
        sleep.assert_not_called()

    def test_installer_requires_guest_additions_before_checking_target_marker(self):
        with patch.object(snp, "vm_prop", return_value="") as property, patch.object(snp, "vbm") as vbm:
            self.assertFalse(snp.install_complete())
        property.assert_called_once_with("/VirtualBox/GuestAdd/Version")
        vbm.assert_not_called()

    def test_installer_accepts_only_exact_target_marker(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(snp, "STATE", Path(directory)):
            for output, expected in (("complete", True), ("complete\r\n", True), ("", False),
                                     ("incomplete", False), ("complete-but-still-installing", False)):
                with self.subTest(output=output), patch.object(snp, "vm_prop", return_value="7.2.6"), \
                        patch.object(snp, "vbm", return_value=output) as vbm:
                    self.assertEqual(snp.install_complete(), expected)
                command = vbm.call_args.args
                self.assertEqual(command[:4], ("guestcontrol", snp.VM, "run", "--username"))
                self.assertEqual(command[command.index("--exe") + 1], "/usr/bin/cat")
                self.assertEqual(command[-2:], ("cat", "/var/lib/snp-install-complete"))
                self.assertEqual(command[command.index("--passwordfile") + 1], snp.STATE / snp.VM / "password")
                self.assertTrue(vbm.call_args.kwargs["ro"])

    def test_setup_uses_distribution_guest_tools_and_hardened_vm(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            with patch.object(snp, "STATE", state), patch.object(snp, "DRY", True), \
                    patch.object(snp.platform, "machine", return_value="AMD64"), patch.object(snp, "venv"), \
                    patch.object(snp, "vbm", return_value="") as vbm, patch.object(snp, "run"), \
                    patch.object(snp, "network", return_value="VirtualBox Host-Only Ethernet Adapter"), \
                    patch.object(snp, "find_iso", return_value=Path("ubuntu.iso")), patch.object(snp, "wait") as wait, \
                    patch.object(snp, "stop_vm"), patch.object(snp, "provision") as provision:
                snp.setup(Mock(iso=None, ram=4096, cpus=2, password="dev", baseline=False))
            self.assertFalse(state.exists())
        unattended = next(call.args for call in vbm.call_args_list if call.args[:2] == ("unattended", "install"))
        self.assertIn("--no-install-additions", unattended)
        self.assertNotIn("--install-additions", unattended)
        late = unattended[unattended.index("--post-install-command") + 1]
        self.assertIn("apt-get install -y openssh-server virtualbox-guest-utils", late)
        self.assertTrue(late.endswith("&& printf complete > /var/lib/snp-install-complete"))
        harden = next(call.args for call in vbm.call_args_list if call.args[0] == "modifyvm" and "--memory" in call.args)
        for nic in range(2, 9):
            self.assertEqual(harden[harden.index(f"--nic{nic}") + 1], "none")
        for option in ("--usb-ohci", "--usb-ehci", "--usb-xhci"):
            self.assertEqual(harden[harden.index(option) + 1], "off")
        self.assertEqual(harden[harden.index("--clipboard-mode") + 1], "disabled")
        self.assertEqual(harden[harden.index("--drag-and-drop") + 1], "disabled")
        wait.assert_called_once()
        self.assertIs(wait.call_args.args[1], snp.install_complete)
        self.assertEqual(wait.call_args.args[2], 90)
        provision.assert_called_once()


if __name__ == "__main__":
    unittest.main()
