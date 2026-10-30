"""Windows host helpers; imported safely on other hosts, executed only on Windows."""
import base64
import contextlib
import os
import tempfile
from pathlib import Path


def windows_env():
    """Do not let a parent pwsh session feed incompatible PowerShell 7 modules to Windows PowerShell 5.1."""
    env = {k: v for k, v in os.environ.items() if k.casefold() != "psmodulepath"}
    env["PSModulePath"] = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                    "System32", "WindowsPowerShell", "v1.0", "Modules")
    return env


def powershell(script):
    """Use Windows PowerShell: NetSecurity is built in there, independently of pwsh installations."""
    binary = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    script = "$env:PSModulePath = $PSHOME + '\\Modules'\n" + script
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return [binary, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


@contextlib.contextmanager
def powershell_file(script):
    """Windows NetSecurity can terminate silently under EncodedCommand; use the verified -File path.

    A unique temporary directory avoids shell quoting, command length limits and predictable script paths.
    UTF-8 with BOM is required for Windows PowerShell 5.1 to read non-ASCII adapter names correctly.
    """
    with tempfile.TemporaryDirectory(prefix="snp-firewall-") as directory:
        path = Path(directory) / "firewall.ps1"
        path.write_text("$env:PSModulePath = $PSHOME + '\\Modules'\n" + script, encoding="utf-8-sig")
        yield [powershell("")[0], "-NoLogo", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-File", str(path)]


def private_state_command(state):
    """Restrict a dedicated state directory to its owner, SYSTEM and Administrators."""
    path = str(state).replace("'", "''")
    script = f"""$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module ($PSHOME + '\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1')
$path = '{path}'
$directory = [System.IO.DirectoryInfo]::new($path)
$acl = $directory.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
$identities = @(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
)
$expected = @($identities | ForEach-Object {{ $_.Value }} | Select-Object -Unique)
$existing = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
$inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$unsafe = @($existing | Where-Object {{
    $_.IsInherited -or $_.IdentityReference.Value -notin $expected -or
    $_.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
    $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
    $_.InheritanceFlags -ne $inheritance -or
    $_.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
}})
if ($acl.AreAccessRulesProtected -and $existing.Count -eq $expected.Count -and -not $unsafe.Count) {{
    Write-Output 'SNP_STATE_PRIVATE'
    exit 0
}}
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in $existing) {{
    $acl.RemoveAccessRuleSpecific($entry)
}}
foreach ($sid in $identities) {{
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}}
$directory.SetAccessControl($acl)
Write-Output 'SNP_STATE_PRIVATE'
"""
    return powershell(script)
