"""Offline firewall regressions. Windows also executes the generated policy against fake cmdlets.

No test installs, removes or queries actual host firewall rules.
"""
import base64
import contextlib
import io
import ipaddress
import json
import os
import subprocess
import unittest
from unittest import mock

import firewall


# These functions shadow every host query/mutation used by the generated script.
# Executing the whole script catches PowerShell binding, quoting, loop and failure-path bugs.
FAKE_WINDOWS = r"""$global:rules = [System.Collections.Generic.List[object]]::new()
$global:removed = [System.Collections.Generic.List[string]]::new()
$global:trace = [System.Collections.Generic.List[string]]::new()
function Get-NetFirewallRule {
    param($PolicyStore, $Enabled, $Direction, $Action)
    if ($PolicyStore -eq 'PersistentStore') {
        [pscustomobject]@{Name='previous'; Group='ShouldNotPass'; DisplayName='SNP previous'}
    } elseif ($Enabled) {
        [pscustomobject]@{Name='bypass-check'}
    } elseif ($global:mode -eq 'ineffective') {
        $global:rules.ToArray() | Select-Object -SkipLast 1
    } else { $global:rules.ToArray() }
}
function Get-NetFirewallSecurityFilter {
    param([Parameter(ValueFromPipeline=$true)]$Rule)
    process { [pscustomobject]@{OverrideBlockRules=($global:mode -eq 'bypass')} }
}
function Get-Service {
    param($Name)
    [pscustomobject]@{Status=$(if ($global:mode -eq 'service') {'Stopped'} else {'Running'})}
}
function Get-NetFirewallProfile {
    param($PolicyStore)
    1..3 | ForEach-Object {
        [pscustomobject]@{
            Enabled=($global:mode -ne 'disabled');
            AllowLocalFirewallRules=($global:mode -ne 'local-policy');
            AllowInboundRules=($global:mode -ne 'shields-up')
        }
    }
}
function Get-NetIPAddress {
    param($AddressFamily)
    [pscustomobject]@{IPAddress='192.168.56.1'; InterfaceAlias=$global:testAlias; InterfaceIndex=42}
}
function Get-NetAdapter {
    param($InterfaceIndex)
    [pscustomobject]@{ifIndex=42; InterfaceGuid='00000000-0000-0000-0000-000000000042'}
}
function Get-NetIPInterface {
    param($InterfaceIndex)
    [pscustomobject]@{Forwarding=$(if ($global:mode -eq 'forwarding') {'Enabled'} else {'Disabled'})}
}
function Get-NetAdapterBinding {
    param($Name, [switch]$AllBindings)
    [pscustomobject]@{ComponentID='ms_bridge'; Enabled=($global:mode -eq 'bridge')}
}
function New-Object {
    param($ComObject)
    if ($ComObject -ne 'HNetCfg.HNetShare') { throw 'unexpected object' }
    $propertiesGetter = [pscustomobject]@{}
    $propertiesGetter | Add-Member -MemberType ScriptMethod -Name Invoke -Value {
        param($Connection) [pscustomobject]@{Guid='00000000-0000-0000-0000-000000000042'}
    }
    $configGetter = [pscustomobject]@{}
    $configGetter | Add-Member -MemberType ScriptMethod -Name Invoke -Value {
        param($Connection) [pscustomobject]@{SharingEnabled=($global:mode -eq 'ics')}
    }
    [pscustomobject]@{
        EnumEveryConnection=@([pscustomobject]@{Id=1});
        NetConnectionProps=$propertiesGetter; INetSharingConfigurationForINetConnection=$configGetter
    }
}
function New-NetFirewallRule {
    param($Name, $DisplayName, $Group, $PolicyStore, $Direction, $InterfaceAlias, $Profile,
          $Enabled, $EdgeTraversalPolicy, $Action, [string]$Protocol,
          [string[]]$LocalPort, [string[]]$RemotePort, [string[]]$LocalAddress)
    if (@($LocalAddress | Where-Object { $_ -match '/0$' }).Count) { throw 'Windows firewall provider rejects /0 address prefixes' }
    if ($global:mode -eq 'creation-error' -and $global:rules.Count -eq 2) { throw 'simulated rule creation error' }
    $rule = [pscustomobject]@{
        Name=$Name; DisplayName=$DisplayName; Group=$Group; PolicyStore=$PolicyStore;
        Direction=$Direction; InterfaceAlias=$InterfaceAlias; Profile=$Profile; Enabled=$Enabled;
        EdgeTraversalPolicy=$EdgeTraversalPolicy; Action=$Action; Protocol=$Protocol;
        LocalPort=$LocalPort; RemotePort=$RemotePort; LocalAddress=$LocalAddress
    }
    $global:rules.Add($rule)
    $global:trace.Add('create')
    $rule
}
function Remove-NetFirewallRule {
    param([Parameter(ValueFromPipeline=$true)]$Rule)
    process { $global:removed.Add($Rule.Name); $global:trace.Add('remove') }
}
"""


def matches(rule, protocol, address, local_port=0, remote_port=0):
    proto = rule["Protocol"]
    proto = {"TCP": "6", "UDP": "17"}.get(proto, proto)
    if proto != "Any" and int(proto) != protocol:
        return False
    addresses = rule["LocalAddress"]
    if addresses:
        addr = ipaddress.ip_address(address)
        found = False
        for item in addresses:
            if "-" in item:
                start, end = map(ipaddress.ip_address, item.split("-"))
                found |= addr.version == start.version and int(start) <= int(addr) <= int(end)
            else:
                found |= addr in ipaddress.ip_network(item)
        if not found:
            return False
    for field, port in (("LocalPort", local_port), ("RemotePort", remote_port)):
        ranges = rule[field]
        if ranges and not any(int(parts[0]) <= port <= int(parts[-1])
                              for parts in (s.split("-") for s in ranges)):
            return False
    return True


class FirewallTests(unittest.TestCase):
    def test_powershell_uses_utf16_encoded_command(self):
        source = "Write-Output 'Réseau d''essai'"
        command = firewall.powershell(source)
        self.assertTrue(command[0].replace("\\", "/").lower().endswith("windowspowershell/v1.0/powershell.exe"))
        self.assertEqual(command[-2], "-EncodedCommand")
        decoded = base64.b64decode(command[-1]).decode("utf-16le")
        self.assertTrue(decoded.endswith(source))
        self.assertTrue(decoded.startswith("$env:PSModulePath = $PSHOME + '\\Modules'"))
        self.assertIn("-NonInteractive", command)

    def test_adapter_discovery_unicode_and_duplicates(self):
        alias = "VirtualBox Réseau d'essai"
        with mock.patch.object(firewall, "OS", "Windows"), mock.patch.object(firewall.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, json.dumps([alias]), "")
            self.assertEqual(firewall.interface(), alias)
            self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
            for addresses in ([], [alias, "another"]):
                run.return_value = subprocess.CompletedProcess([], 0, json.dumps(addresses), "")
                with self.assertRaisesRegex(SystemExit, "expected one adapter"):
                    firewall.interface()
            run.return_value = subprocess.CompletedProcess([], 1, "", "CIM query failed")
            with self.assertRaisesRegex(SystemExit, "CIM query failed"):
                firewall.interface()

    def test_windows_errors_are_fatal(self):
        failed = subprocess.CompletedProcess([], 1, "", "Access denied")
        with mock.patch.object(firewall, "DRY", False), mock.patch.object(firewall.subprocess, "run", return_value=failed), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "Access denied"):
                firewall.windows("VirtualBox", "up")

    def test_silent_powershell_exit_is_fatal(self):
        with mock.patch.object(firewall, "DRY", False), mock.patch.object(firewall, "sh", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "without verifying"):
                firewall.windows("VirtualBox", "up")

    def test_windows_environment_uses_only_system_modules(self):
        with mock.patch.dict(os.environ, {"PSModulePath": "PowerShell7;third-party", "PSMODULEPATH": "duplicate"}):
            env = firewall.windows_env()
        self.assertEqual(sum(k.casefold() == "psmodulepath" for k in env), 1)
        self.assertTrue(env["PSModulePath"].replace("\\", "/").lower().endswith("windowspowershell/v1.0/modules"))
        self.assertNotIn("PowerShell7", env["PSModulePath"])

    def test_generated_file_uses_bom_and_is_removed(self):
        from pathlib import Path
        source = "Write-Output 'Réseau d''essai'"
        with firewall.powershell_file(source) as command:
            self.assertIn("-File", command)
            self.assertNotIn("-EncodedCommand", command)
            path = Path(command[-1])
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))
            self.assertTrue(path.read_text(encoding="utf-8-sig").endswith(source))
        self.assertFalse(path.exists())

    def test_down_and_status_do_not_need_existing_adapter(self):
        for action in ("down", "status"):
            with mock.patch.object(firewall, "OS", "Windows"), mock.patch.object(firewall, "DRY", True), \
                    mock.patch.object(firewall.sys, "argv", ["firewall.py", action, "--dry-run"]), \
                    mock.patch.object(firewall, "interface", side_effect=AssertionError("queried adapter")), \
                    contextlib.redirect_stdout(io.StringIO()):
                firewall.main()

    def test_dry_run_never_invokes_powershell_mutations(self):
        with mock.patch.object(firewall, "DRY", True), mock.patch.object(firewall.subprocess, "run") as run, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            firewall.windows("VirtualBox", "up")
        run.assert_not_called()
        self.assertIn("New-NetFirewallRule", out.getvalue())


@unittest.skipUnless(os.name == "nt", "Windows PowerShell script execution requires Windows")
class WindowsPolicyTests(unittest.TestCase):
    alias = "VirtualBox Réseau d'essai [2]"

    def execute_policy(self, mode="normal"):
        setup = "$global:testAlias = '" + self.alias.replace("'", "''") + "'\n$global:mode = '" + mode + "'\n"
        script = setup + FAKE_WINDOWS + "\n$errorText = $null\ntry {\n" + firewall.windows_script(self.alias, "up") + "\n} catch { $errorText = $_.Exception.Message }\n"
        script += "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        script += "@{Rules=$global:rules.ToArray(); Removed=$global:removed.ToArray(); Trace=$global:trace.ToArray(); Error=$errorText} | ConvertTo-Json -Depth 8 -Compress\n"
        with firewall.powershell_file(script) as command:
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                    timeout=30, env=firewall.windows_env())
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_effective_policy_and_block_precedence(self):
        result = self.execute_policy()
        self.assertIsNone(result["Error"])
        rules = result["Rules"]
        self.assertEqual(len(rules), 261)
        self.assertEqual(result["Removed"], ["previous"])
        self.assertEqual(result["Trace"], ["create"] * len(rules) + ["remove"])
        for rule in rules:
            self.assertEqual(rule["Profile"], "Any")
            self.assertEqual(rule["Direction"], "Inbound")
            self.assertEqual(rule["Enabled"], "True")
            self.assertEqual(rule["Group"], "ShouldNotPass")

        def actions(protocol, address, port=0, remote=0):
            return {r["Action"] for r in rules if matches(r, protocol, address, port, remote)}

        self.assertEqual(actions(6, firewall.HOST_IP, 3128), {"Allow"})
        self.assertEqual(actions(17, firewall.HOST_IP, 67, 68), {"Allow"})
        for proto, addr, port, remote in (
                (6, firewall.HOST_IP, 0, 0), (6, firewall.HOST_IP, 22, 0),
                (6, firewall.HOST_IP, 65535, 0), (17, firewall.HOST_IP, 0, 0),
                (17, firewall.HOST_IP, 53, 0), (17, firewall.HOST_IP, 67, 22),
                (6, "10.0.0.1", 3128, 0), (6, "fe80::1", 3128, 0),
                (17, "fe80::1", 67, 68), (58, "fe80::1", 0, 0)):
            self.assertIn("Block", actions(proto, addr, port, remote), (proto, addr, port, remote))
        for protocol in set(range(256)) - {6, 17}:
            self.assertIn("Block", actions(protocol, firewall.HOST_IP), protocol)

    def test_unsafe_preflight_creates_no_rules(self):
        for mode, message in (("disabled", "firewall profiles"), ("local-policy", "firewall profiles"),
                              ("shields-up", "firewall profiles"), ("service", "service is not running"),
                              ("forwarding", "IP forwarding"), ("bridge", "network bridge"),
                              ("ics", "Internet Connection Sharing"), ("bypass", "bypass rules")):
            with self.subTest(mode=mode):
                result = self.execute_policy(mode)
                self.assertIn(message, result["Error"])
                self.assertEqual(result["Rules"], [])
                self.assertEqual(result["Removed"], [])

    def test_creation_failure_keeps_previous_protection(self):
        result = self.execute_policy("creation-error")
        self.assertIn("simulated rule creation error", result["Error"])
        self.assertEqual(len(result["Rules"]), 2)
        self.assertEqual(result["Removed"], [])

    def test_missing_effective_rules_keeps_previous_protection(self):
        result = self.execute_policy("ineffective")
        self.assertIn("missing from the effective firewall policy", result["Error"])
        self.assertEqual(len(result["Rules"]), 261)
        self.assertEqual(result["Removed"], [])


if __name__ == "__main__":
    unittest.main()
