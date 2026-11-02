"""Offline proxy readiness tests: never query real processes or open sockets."""
import base64
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import psutil

import snp
import proxy_health


def connection(address=snp.HOST_IP, port=snp.PORT, status=psutil.CONN_LISTEN,
               family=socket.AF_INET, type_=socket.SOCK_STREAM):
    return SimpleNamespace(family=family, type=type_, status=status,
                           laddr=SimpleNamespace(ip=address, port=port))


class ProxyReadinessTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        state = Path(directory.name)
        (state / 'proxy.pid').write_text('123', encoding='utf-8')
        self.state_patch = patch.object(snp, 'STATE', state)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)

    def test_managed_process_must_own_exact_listener(self):
        process = Mock()
        process.net_connections.return_value = [connection()]
        with patch.object(snp, "proxy_process", return_value=process), \
                patch.object(snp, "port_open", side_effect=AssertionError("unowned port probe")):
            self.assertTrue(snp.proxy_up())
        process.net_connections.assert_called_once_with(kind="tcp")

    def test_unrelated_open_port_is_insufficient(self):
        process = Mock()
        process.net_connections.return_value = [connection(port=snp.PORT + 1)]
        with patch.object(snp, "proxy_process", return_value=process), \
                patch.object(snp, "port_open", return_value=True):
            self.assertFalse(snp.proxy_up())

    def test_no_managed_process_is_not_ready(self):
        with patch.object(snp, "proxy_process", return_value=None), \
                patch.object(snp, "port_open", return_value=True):
            self.assertFalse(snp.proxy_up())

    def test_wrong_addresses_states_and_socket_types_are_rejected(self):
        cases = [
            connection(address="0.0.0.0"),
            connection(address="127.0.0.1"),
            connection(address="192.168.1.1"),
            connection(address="::", family=socket.AF_INET6),
            connection(status=psutil.CONN_ESTABLISHED),
            connection(status=psutil.CONN_CLOSE_WAIT),
            connection(type_=socket.SOCK_DGRAM),
            SimpleNamespace(family=socket.AF_INET, type=socket.SOCK_STREAM,
                            status=psutil.CONN_LISTEN, laddr=()),
        ]
        for item in cases:
            with self.subTest(connection=item):
                process = Mock()
                process.net_connections.return_value = [item]
                with patch.object(snp, "proxy_process", return_value=process):
                    self.assertFalse(snp.proxy_up())

    def test_empty_connections_are_not_ready(self):
        process = Mock()
        process.net_connections.return_value = []
        with patch.object(snp, "proxy_process", return_value=process):
            self.assertFalse(snp.proxy_up())

    def test_process_query_errors_fail_closed(self):
        for error in (psutil.AccessDenied(123), psutil.NoSuchProcess(123),
                      psutil.ZombieProcess(123), OSError("socket query failed")):
            with self.subTest(error=type(error).__name__):
                process = Mock()
                process.net_connections.side_effect = error
                with patch.object(snp, "proxy_process", return_value=process):
                    self.assertFalse(snp.proxy_up())


class ProxyEntryTests(unittest.TestCase):
    def test_actual_interpreter_publishes_identity_before_proxy_starts(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "proxy.pid"
            process = Mock(pid=123)
            process.create_time.return_value = 456.0

            def start_proxy():
                self.assertEqual(json.loads(record.read_text(encoding="utf-8")),
                                 {"pid": 123, "created": 456.0})
                self.assertEqual(list(record.parent.glob("*.tmp")), [])

            module = SimpleNamespace(mitmdump=Mock(side_effect=start_proxy))
            with patch.dict(os.environ, {"SNP_PROXY_PIDFILE": str(record)}), \
                    patch.object(snp, "WIN", False), \
                    patch.object(snp.os, "getpid", return_value=123), \
                    patch.object(psutil, "Process", return_value=process) as identify, \
                    patch.dict(sys.modules, {"mitmproxy.tools.main": module}):
                snp.proxy_entry()
            identify.assert_called_once_with(123)
            module.mitmdump.assert_called_once_with()

    def test_windows_publishes_a_fresh_private_health_key(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'proxy.pid'
            process = Mock(pid=123)
            process.create_time.return_value = 456.0
            keys = []

            def start_proxy():
                identity = json.loads(record.read_text(encoding='utf-8'))
                self.assertEqual((identity['pid'], identity['created']), (123, 456.0))
                key = identity['health_key']
                self.assertRegex(key, r'^[0-9a-f]{64}$')
                self.assertEqual(key, os.environ['SNP_PROXY_HEALTH_KEY'])
                keys.append(key)

            with patch.dict(os.environ, {'SNP_PROXY_PIDFILE': str(record)}), \
                    patch.object(snp, 'WIN', True), patch.object(psutil, 'Process', return_value=process), \
                    patch.dict(sys.modules, {'mitmproxy.tools.main': SimpleNamespace(mitmdump=start_proxy)}):
                snp.proxy_entry()
                snp.proxy_entry()
            self.assertNotEqual(*keys)

    def test_failed_identity_publication_never_starts_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "missing" / "proxy.pid"
            process = Mock(pid=123)
            process.create_time.return_value = 456.0
            module = SimpleNamespace(mitmdump=Mock())
            with patch.dict(os.environ, {"SNP_PROXY_PIDFILE": str(record)}), \
                    patch.object(psutil, "Process", return_value=process), \
                    patch.dict(sys.modules, {"mitmproxy.tools.main": module}), \
                    self.assertRaises(OSError):
                snp.proxy_entry()
            module.mitmdump.assert_not_called()
            self.assertFalse(record.exists())


class WindowsHealthReadinessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        self.process = Mock(pid=123)
        self.process.create_time.return_value = 456.0
        self.process.net_connections.side_effect = AssertionError('Windows socket table is unreliable')
        self.key = 'a' * 64
        self.record = {'pid': 123, 'created': 456.0, 'health_key': self.key}

    def ready(self, record, process=True, proof=True):
        (self.state / 'proxy.pid').write_text(json.dumps(record), encoding='utf-8')
        with patch.object(snp, 'STATE', self.state), patch.object(snp, 'WIN', True), \
                patch.object(snp, 'proxy_process', return_value=self.process if process else None), \
                patch.object(proxy_health, 'check', return_value=proof) as check:
            result = snp.proxy_up()
        return result, check

    def test_signed_response_replaces_unreliable_windows_socket_query(self):
        result, check = self.ready(self.record)
        self.assertTrue(result)
        check.assert_called_once_with(snp.HOST_IP, snp.PORT, self.key)

    def test_missing_managed_process_cannot_use_health_proof(self):
        result, check = self.ready(self.record, process=False)
        self.assertFalse(result)
        check.assert_not_called()

    def test_pid_file_replacement_does_not_validate_another_process(self):
        for record in ({**self.record, 'pid': 999}, {**self.record, 'created': 455.0},
                       {'health_key': self.key}):
            with self.subTest(record=record):
                result, check = self.ready(record)
                self.assertFalse(result)
                check.assert_not_called()

    def test_failed_health_proof_is_not_replaced_by_an_open_port(self):
        with patch.object(snp, 'port_open', return_value=True):
            result, _ = self.ready(self.record, proof=False)
        self.assertFalse(result)


class HealthProofTests(unittest.TestCase):
    key = 'a' * 64
    nonce = 'b' * 64

    def check(self, body, status=200, error=None):
        connection = Mock()
        connection.getresponse.return_value = SimpleNamespace(status=status, read=lambda limit: body[:limit])
        if error:
            connection.request.side_effect = error
        with patch.object(proxy_health.secrets, 'token_hex', return_value=self.nonce), \
                patch.object(proxy_health.http.client, 'HTTPConnection', return_value=connection) as connect:
            result = proxy_health.check('192.168.56.1', 3128, self.key)
        connection.close.assert_called_once_with()
        connect.assert_called_once_with('192.168.56.1', 3128, timeout=2)
        # The private key must not appear anywhere in the outgoing request.
        self.assertNotIn(self.key, repr(connection.request.call_args))
        return result

    def test_valid_signature_is_accepted(self):
        self.assertTrue(self.check(proxy_health.proof(self.key, self.nonce)))

    def test_arbitrary_success_redirect_replay_and_reflection_are_rejected(self):
        bad = [b'OK', self.nonce.encode(), proxy_health.proof('c' * 64, self.nonce),
               proxy_health.proof(self.key, 'd' * 64), proxy_health.proof(self.key, self.nonce) + b'x']
        for body in bad:
            with self.subTest(body=body):
                self.assertFalse(self.check(body))
        self.assertFalse(self.check(proxy_health.proof(self.key, self.nonce), status=302))

    def test_connection_errors_fail_closed(self):
        for error in (OSError('offline'), http.client.BadStatusLine('bad response')):
            with self.subTest(error=error):
                self.assertFalse(self.check(b'', error=error))

    def test_malformed_private_key_never_opens_a_socket(self):
        for key in (None, 123, '', 'x' * 64, 'a' * 63, 'a' * 65):
            with self.subTest(key=key), patch.object(proxy_health.http.client, 'HTTPConnection') as connect:
                self.assertFalse(proxy_health.check('192.168.56.1', 3128, key))
                connect.assert_not_called()

    def test_each_probe_uses_a_new_challenge(self):
        urls = []
        connection = Mock()
        connection.request.side_effect = lambda method, url, **kw: urls.append(url)
        connection.getresponse.return_value = SimpleNamespace(status=200, read=lambda limit: b'bad')
        with patch.object(proxy_health.http.client, 'HTTPConnection', return_value=connection):
            proxy_health.check('192.168.56.1', 3128, self.key)
            proxy_health.check('192.168.56.1', 3128, self.key)
        self.assertNotEqual(*urls)


class HealthEndpointTests(unittest.TestCase):
    def setUp(self):
        import proxy_addon
        self.module = proxy_addon
        self.key = 'a' * 64
        with patch.dict(os.environ, {'SNP_PROXY_HEALTH_KEY': self.key}), patch.object(proxy_addon, 'Rules'):
            self.addon = proxy_addon.Sandbox()

    def flow(self, method='GET', path=None, host=proxy_health.HOST):
        from mitmproxy import http
        return SimpleNamespace(request=http.Request.make(method, 'http://' + host + (path or proxy_health.PATH + 'b' * 64)), response=None)

    def test_health_reply_is_local_and_independent_of_allow_list(self):
        flow = self.flow()
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(flow.response.content, proxy_health.proof(self.key, 'b' * 64))
        self.assertEqual(flow.response.headers['cache-control'], 'no-store')
        self.addon.rules.host_allowed.assert_not_called()
        self.addon.rules.resolve.assert_not_called()

    def test_invalid_health_requests_cannot_be_forwarded(self):
        for method, path in (('POST', proxy_health.PATH + 'b' * 64), ('GET', '/wrong'),
                             ('GET', proxy_health.PATH + 'z' * 64)):
            with self.subTest(method=method, path=path):
                flow = self.flow(method, path)
                self.addon.request(flow)
                self.assertEqual(flow.response.status_code, 404)
        self.addon.rules.resolve.assert_not_called()

    def test_no_private_key_means_no_health_proof(self):
        self.addon.health_key = ''
        flow = self.flow()
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 404)

    def test_health_path_on_another_host_does_not_bypass_policy(self):
        self.addon.rules.host_allowed.return_value = False
        flow = self.flow(host='127.0.0.1')
        with patch.object(self.module, 'log'):
            self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertNotIn(proxy_health.proof(self.key, 'b' * 64), flow.response.content)


@unittest.skipUnless(os.name == "nt", "Windows PowerShell launcher requires Windows")
class PowerShellLauncherTests(unittest.TestCase):
    def test_elevation_preserves_literal_arguments_and_requests_hidden_uac(self):
        # Replace every process/file operation with a fake. Only parse the
        # generated elevated command; never execute it or request elevation.
        source = (Path(__file__).parent / "snp.ps1").read_text(encoding="utf-8-sig")
        arguments = ["--state-dir", r"C:\Review's état [1]" + "\\", "setup", "--password",
                     'literal \'quote\' "double" $(Get-Item secret); & command',
                     "", "line one\nline two", "parolă 日本語"]
        encoded_source = base64.b64encode(source.encode("utf-8")).decode("ascii")
        encoded_arguments = base64.b64encode(json.dumps(arguments).encode("utf-8")).decode("ascii")
        script = r"""$ErrorActionPreference = 'Stop'
$global:testRoot = 'C:\Review''s suite [1]'
$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__'))
$source = $source.Replace('$PSScriptRoot', '$global:testRoot').Replace('exit $LASTEXITCODE', 'return').Replace('exit $process.ExitCode', 'return')
$source = $source.Replace('[System.IO.File]::WriteAllText($commandPath, $script, [Text.UTF8Encoding]::new($true))', '$global:writtenScript = $script')
$global:testArgs = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ARGUMENTS__')) | ConvertFrom-Json
$env:SNP_STATE_DIR = $null
function Test-Path { param($LiteralPath, $PathType) return $true }
function Resolve-Path { param($LiteralPath) [pscustomobject]@{Path='C:\Tools\Python''s runtime\python.exe'} }
function New-Item { param($ItemType, [switch]$Force, $Path) }
function Get-Content { param($LiteralPath, [switch]$Raw) if ($LiteralPath.EndsWith('.exit')) { '0' } }
function Remove-Item { param($LiteralPath, [switch]$Force, $ErrorAction) }
function Start-Process {
    param($FilePath, $Verb, $WindowStyle, [switch]$Wait, [switch]$PassThru, $ArgumentList)
    $global:launch = [pscustomobject]@{
        FilePath=$FilePath; Verb=$Verb; WindowStyle=$WindowStyle;
        Wait=$Wait.IsPresent; PassThru=$PassThru.IsPresent; ArgumentList=$ArgumentList
    }
    $process = [pscustomobject]@{ExitCode=0}
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { $global:waitedForCommand = $true }
    $process
}
& ([scriptblock]::Create($source)) -Elevate @global:testArgs
$decoded = $global:writtenScript
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($decoded, [ref]$tokens, [ref]$errors)
$commands = @($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.InvocationOperator -eq 'Ampersand'}, $true))
$literal = @($commands[0].CommandElements | ForEach-Object { $_.Value })
$locations = @($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst]}, $true) | ForEach-Object { $_.Value })
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
@{Launch=$global:launch; WaitedForCommand=$global:waitedForCommand; Arguments=$literal; ParseErrors=@($errors | ForEach-Object Message); Literals=$locations} | ConvertTo-Json -Depth 6 -Compress
""".replace("__SOURCE__", encoded_source).replace("__ARGUMENTS__", encoded_arguments)
        command = [str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" /
                       "WindowsPowerShell" / "v1.0" / "powershell.exe"),
                   "-NoProfile", "-NonInteractive", "-EncodedCommand",
                   base64.b64encode(script.encode("utf-16le")).decode("ascii")]
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(result["ParseErrors"], [])
        self.assertEqual(result["Arguments"][:3], [r"C:\Tools\Python's runtime\python.exe", "-u", "-c"])
        self.assertEqual(len(result["Arguments"]), 5)
        self.assertNotIn('"', result["Arguments"][3])
        self.assertEqual(json.loads(base64.b64decode(result["Arguments"][4])),
                         [r"C:\Review's suite [1]\snp.py", *arguments])
        self.assertEqual(result["Launch"]["Verb"], "RunAs")
        self.assertEqual(result["Launch"]["WindowStyle"], "Hidden")
        self.assertFalse(result["Launch"]["Wait"])
        self.assertTrue(result["WaitedForCommand"])
        self.assertTrue(result["Launch"]["PassThru"])
        self.assertIn("-File", result["Launch"]["ArgumentList"])
        self.assertNotIn("-EncodedCommand", result["Launch"]["ArgumentList"])
        self.assertTrue(result["Launch"]["ArgumentList"][-1].startswith('"C:\\Review'))
        self.assertTrue(result["Launch"]["ArgumentList"][-1].endswith('.ps1"'))
        self.assertIn(r"C:\Review's suite [1]", result["Literals"])
        self.assertIn(r"C:\Review's suite [1]\.snp\elevated.log", result["Literals"])

        # A native host can exit zero before running the command. Missing
        # completion evidence must fail even when Start-Process says success.
        failed_script = script.replace(
            "function Test-Path { param($LiteralPath, $PathType) return $true }",
            "function Test-Path { param($LiteralPath, $PathType) return (-not $LiteralPath.EndsWith('.exit')) }")
        failed_command = command[:-1] + [base64.b64encode(failed_script.encode("utf-16le")).decode("ascii")]
        failed = subprocess.run(failed_command, capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("without a verified result", failed.stderr)

    def test_native_python_receives_unicode_quotes_empty_and_trailing_slash(self):
        # Use the launcher's actual bootstrap, replacing runpy's file execution
        # with an argv echo. No file, sandbox command or UAC dialog is involved.
        source = (Path(__file__).parent / "snp.ps1").read_text(encoding="utf-8-sig")
        expected = [r"C:\Réseau d'essai [1]\snp.py", "--state-dir", r"C:\state space" + "\\",
                    "setup", "--password", 'literal \'quote\' "double" $(Get-Item secret); & command',
                    "", "line one\nline two", "parolă 日本語"]
        payload = base64.b64encode(json.dumps(expected).encode("utf-8")).decode("ascii")
        source_b64 = base64.b64encode(source.encode("utf-8")).decode("ascii")
        python_literal = str(sys.executable).replace("'", "''")
        script = r"""$ErrorActionPreference = 'Stop'
$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__'))
$tokens=$null; $errors=$null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'launcher parse error' }
$assignment = @($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.VariablePath.UserPath -eq 'bootstrap'}, $true))[0]
$literal = $assignment.Right.Find({param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst]}, $true)
if (-not $literal) { throw 'bootstrap must be a literal string' }
$bootstrap = 'import json,runpy,sys;runpy.run_path=lambda *a,**k: print(json.dumps(sys.argv));' + $literal.Value
$arguments = @('-u', '-c', $bootstrap, '__PAYLOAD__')
& '__PYTHON__' @arguments
if ($LASTEXITCODE) { throw 'native argv probe failed' }
""".replace("__SOURCE__", source_b64).replace("__PAYLOAD__", payload).replace("__PYTHON__", python_literal)
        command = [str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" /
                       "WindowsPowerShell" / "v1.0" / "powershell.exe"),
                   "-NoProfile", "-NonInteractive", "-EncodedCommand",
                   base64.b64encode(script.encode("utf-16le")).decode("ascii")]
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), expected)


if __name__ == "__main__":
    unittest.main()
