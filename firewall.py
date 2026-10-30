#!/usr/bin/env python3
"""Close the host to the sandbox VM: from the host-only interface allow only DHCP (udp 67), the proxy and replies.

  python3 firewall.py up|down|status [--dry-run]

Uses the firewall tool of this OS: nft or iptables (Linux), pf (macOS), Windows Firewall (PowerShell).
Needs admin: re-runs itself with sudo on Linux/macOS, asks for an elevated terminal on Windows.
Run `up` again before starting the VM. Windows rules persist until `down`; the other backends are not saved across reboots.
Windows requires Windows PowerShell and the built-in NetSecurity/NetTCPIP modules.
"""
import json
import os
import platform
import shutil
import subprocess
import sys

from windows_host import powershell, powershell_file, windows_env

HOST_IP, PROXY_PORT = "192.168.56.1", 3128
OS = platform.system()
DRY = "--dry-run" in sys.argv


def sh(cmd, stdin=None, check=True, label=None):
    command = label or " ".join(cmd)
    print("+", command + ("   <<< (rules below)" if stdin else ""))
    if stdin:
        print(stdin.rstrip())
    if DRY:
        return ""
    r = subprocess.run(cmd, input=stdin, text=True, capture_output=True,
                       encoding="utf-8" if OS == "Windows" else None,
                       env=windows_env() if OS == "Windows" else None)
    if check and r.returncode:
        details = "\n".join(s.strip() for s in (r.stdout, r.stderr) if s and s.strip())
        sys.exit(f"failed: {command}\n{details}")
    return r.stdout


def interface():
    """Name of the host-only adapter that owns HOST_IP, in the form this OS firewall expects."""
    if OS == "Windows":
        # JSON and UTF-8 avoid localized adapter names being decoded using the console's code page.
        ps = ("$ErrorActionPreference = 'Stop'; "
              "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
              f"@(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '{HOST_IP}' | "
              "Select-Object -ExpandProperty InterfaceAlias) | ConvertTo-Json -Compress")
        with powershell_file(ps) as command:
            r = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", env=windows_env())
        if r.returncode:
            sys.exit(f"cannot inspect the host-only adapter: {r.stderr.strip()}")
        names = json.loads(r.stdout or "null")
        names = [names] if isinstance(names, str) else names or []
        if len(names) != 1:
            sys.exit(f"expected one adapter with {HOST_IP}; found {len(names)}: create the host-only network first")
        return names[0]
    import psutil  # ponytail: same dependency as netinfo.py
    for name, addrs in psutil.net_if_addrs().items():
        if any(a.address == HOST_IP for a in addrs):
            return name
    sys.exit(f"no interface with {HOST_IP}: create the host-only network first (`python3 snp.py setup` does it)")


def nft(IF, action):
    if action == "up":
        sh(["nft", "-f", "-"], f"""table inet sandbox
delete table inet sandbox
table inet sandbox {{
  chain input {{
    type filter hook input priority 0; policy accept;
    iifname "{IF}" udp dport 67 accept
    iifname "{IF}" tcp dport {PROXY_PORT} accept
    iifname "{IF}" ct state established,related accept
    iifname "{IF}" drop
  }}
}}
""")  # first two lines make a re-run replace the table instead of failing
    elif action == "down":
        sh(["nft", "delete", "table", "inet", "sandbox"], check=False)
    else:
        print(sh(["nft", "list", "table", "inet", "sandbox"], check=False) or "(not loaded)")


def iptables(IF, action):
    for ipt in [t for t in ("iptables", "ip6tables") if shutil.which(t)]:
        hook = [ipt, "-C", "INPUT", "-i", IF, "-j", "SNP"]
        if action in ("up", "down"):
            sh([ipt, "-D", "INPUT", "-i", IF, "-j", "SNP"], check=False)
            sh([ipt, "-F", "SNP"], check=False)
            sh([ipt, "-X", "SNP"], check=False)
        if action == "up":
            sh([ipt, "-N", "SNP"])
            for rule in (["-p", "udp", "--dport", "67", "-j", "ACCEPT"], ["-p", "tcp", "--dport", str(PROXY_PORT), "-j", "ACCEPT"],
                         ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], ["-j", "DROP"]):
                sh([ipt, "-A", "SNP", *rule])
            sh([ipt, "-I", "INPUT", "-i", IF, "-j", "SNP"])
        elif action == "status":
            print(sh([ipt, "-S", "SNP"], check=False) or f"({ipt}: not loaded)")


def pf(IF, action):
    anchor = "com.apple/snp"  # com.apple/* anchors are evaluated by the stock macOS ruleset, no pf.conf edit
    if action == "up":
        sh(["pfctl", "-E"], check=False)
        sh(["pfctl", "-a", anchor, "-f", "-"], f"""pass in quick on {IF} proto udp to any port 67
pass in quick on {IF} proto tcp to {HOST_IP} port {PROXY_PORT}
block in quick on {IF} all
""")
    elif action == "down":
        sh(["pfctl", "-a", anchor, "-F", "all"], check=False)
    else:
        print(sh(["pfctl", "-a", anchor, "-s", "rules"], check=False) or "(not loaded)")


def windows_script(IF, action):
    """Build the script separately so all Windows policy can be inspected/tested without elevation."""
    alias = IF.replace("'", "''")
    preamble = f"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$group = 'ShouldNotPass'
$alias = '{alias}'
Write-Output 'SNP: inspecting Windows firewall policy'
# Only our group and the two exact legacy names belong to this project.
$old = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {{
    $_.Group -eq $group -or $_.DisplayName -in @('SNP block tcp', 'SNP block udp')
}})
"""
    if action == "down":
        return preamble + "$old | Remove-NetFirewallRule\n"
    if action == "status":
        return preamble + "$old | Format-Table DisplayName,Enabled,Action,Profile\n"
    if action != "up":
        raise ValueError(f"unknown firewall action: {action}")
    return preamble + f"""# Never start a guest when local rules are disabled, ignored by policy, or bypassed.
Write-Output 'SNP: checking firewall profiles'
if ((Get-Service MpsSvc).Status -ne 'Running') {{ throw 'Windows Defender Firewall service is not running' }}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if ($profiles.Count -ne 3 -or @($profiles | Where-Object {{
    [string]$_.Enabled -ne 'True' -or [string]$_.AllowLocalFirewallRules -eq 'False' -or [string]$_.AllowInboundRules -eq 'False'
}}).Count) {{ throw 'All firewall profiles must be enabled and permit local rules and inbound exceptions' }}
$bypass = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow |
    Get-NetFirewallSecurityFilter | Where-Object {{ [string]$_.OverrideBlockRules -eq 'True' }})
if ($bypass.Count) {{ throw 'Authenticated firewall bypass rules are incompatible with the sandbox' }}
Write-Output 'SNP: checking host-only adapter and routing'
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{
    $_.IPAddress -eq '{HOST_IP}' -and $_.InterfaceAlias -eq $alias
}})
if ($addresses.Count -ne 1) {{ throw 'The host-only address no longer identifies one adapter' }}
$adapter = Get-NetAdapter -InterfaceIndex $addresses[0].InterfaceIndex
$ipInterfaces = @(Get-NetIPInterface -InterfaceIndex $adapter.ifIndex)
if (-not $ipInterfaces.Count -or @($ipInterfaces | Where-Object Forwarding -eq 'Enabled').Count) {{
    throw 'Disable IP forwarding on the host-only adapter before starting the sandbox'
}}
$escapedAlias = [System.Management.Automation.WildcardPattern]::Escape($alias)
if (@(Get-NetAdapterBinding -Name $escapedAlias -AllBindings |
    Where-Object {{ $_.ComponentID -eq 'ms_bridge' -and $_.Enabled }}).Count) {{
    throw 'Remove the host-only adapter from the Windows network bridge before starting the sandbox'
}}
# ICS can route guest packets around INPUT-style host firewall rules. Inspect, never reconfigure it.
Write-Output 'SNP: checking Internet Connection Sharing'
$sharing = New-Object -ComObject HNetCfg.HNetShare
foreach ($connection in $sharing.EnumEveryConnection) {{
    $properties = $sharing.NetConnectionProps.Invoke($connection)
    if ([guid]$properties.Guid -eq [guid]$adapter.InterfaceGuid -and
        $sharing.INetSharingConfigurationForINetConnection.Invoke($connection).SharingEnabled) {{
        throw 'Disable Internet Connection Sharing on the host-only adapter before starting the sandbox'
    }}
}}
# Keep the previous generation installed until the new generation is complete and effective.
$prefix = 'SNP-' + $adapter.ifIndex + '-' + [guid]::NewGuid().ToString('N') + '-'
$common = @{{
    Group = $group; PolicyStore = 'PersistentStore'; Direction = 'Inbound';
    InterfaceAlias = $escapedAlias; Profile = 'Any'; Enabled = 'True'; EdgeTraversalPolicy = 'Block'
}}
Write-Output 'SNP: installing Windows firewall rules'
$newRules = @()
$newRules += New-NetFirewallRule @common -Name ($prefix + 'tcp') -DisplayName 'SNP block TCP except proxy' -Action Block -Protocol TCP -LocalPort '0-{PROXY_PORT - 1}','{PROXY_PORT + 1}-65535'
$newRules += New-NetFirewallRule @common -Name ($prefix + 'udp') -DisplayName 'SNP block UDP except DHCP' -Action Block -Protocol UDP -LocalPort '0-66','68-65535'
$newRules += New-NetFirewallRule @common -Name ($prefix + 'dhcp-source') -DisplayName 'SNP restrict DHCP client port' -Action Block -Protocol UDP -LocalPort 67 -RemotePort '0-67','69-65535'
# The provider rejects /0 prefixes: two /1 prefixes cover each address family without that ambiguity.
# The sandbox uses IPv4 only. Do not leave IPv6 services or an IPv6 proxy-port exception reachable.
$newRules += New-NetFirewallRule @common -Name ($prefix + 'ipv6') -DisplayName 'SNP block IPv6' -Action Block -Protocol Any -LocalAddress '::/1','8000::/1'
# A public/LAN service on port 3128 is not the proxy bound to HOST_IP.
$newRules += New-NetFirewallRule @common -Name ($prefix + 'proxy-address') -DisplayName 'SNP restrict proxy address' -Action Block -Protocol TCP -LocalPort {PROXY_PORT} -LocalAddress '0.0.0.0-192.168.56.0','192.168.56.2-255.255.255.255'
# Windows has no protocol-complement match. Explicit blocks also defeat existing broad app allows.
foreach ($protocol in 0..255) {{
    if ($protocol -in @(6,17)) {{ continue }}
    $newRules += New-NetFirewallRule @common -Name ($prefix + 'protocol-' + $protocol) -DisplayName ('SNP block protocol ' + $protocol) -Action Block -Protocol $protocol -LocalAddress '0.0.0.0/1','128.0.0.0/1'
}}
# Block rules take precedence, so only the excluded ports can be allowed.
$newRules += New-NetFirewallRule @common -Name ($prefix + 'proxy') -DisplayName 'SNP allow proxy' -Action Allow -Protocol TCP -LocalAddress '{HOST_IP}' -LocalPort {PROXY_PORT}
$newRules += New-NetFirewallRule @common -Name ($prefix + 'dhcp') -DisplayName 'SNP allow DHCP' -Action Allow -Protocol UDP -LocalAddress '0.0.0.0/1','128.0.0.0/1' -LocalPort 67 -RemotePort 68
Write-Output 'SNP: verifying effective Windows firewall rules'
$effective = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {{
    $_.Group -eq $group -and $_.Name.StartsWith($prefix) -and [string]$_.Enabled -eq 'True'
}})
if ($newRules.Count -ne 261 -or $effective.Count -ne 261) {{ throw 'New sandbox rules are missing from the effective firewall policy' }}
$old | Remove-NetFirewallRule
Write-Output ('Loaded ' + $effective.Count + ' sandbox firewall rules on ' + $alias)
Write-Output 'SNP_FIREWALL_READY'
"""


def windows(IF, action):
    script = windows_script(IF, action)
    # Keep dry runs readable and avoid creating even a temporary script during a dry run.
    if DRY:
        print(script.rstrip())
        return
    with powershell_file(script) as command:
        output = sh(command, label=f"Windows PowerShell sandbox firewall {action}")
    print(output)
    if action == "up" and "SNP_FIREWALL_READY" not in output.splitlines():
        sys.exit("Windows PowerShell exited without verifying the sandbox firewall; the VM must remain stopped")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1 or args[0] not in ("up", "down", "status"):
        sys.exit(__doc__)
    action = args[0]
    if OS == "Linux":
        tool = nft if shutil.which("nft") else iptables if shutil.which("iptables") else sys.exit("need nft or iptables")
    elif OS == "Darwin":
        tool = pf
    elif OS == "Windows":
        tool = windows
    else:
        sys.exit(f"unsupported OS: {OS}")
    if not DRY:
        if OS == "Windows":
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                sys.exit("run this from an elevated (administrator) terminal")
        elif os.geteuid() != 0:
            os.execvp("sudo", ["sudo", sys.executable, *sys.argv])
    # Removal/status are group based on Windows, so they still work after an adapter was deleted.
    IF = interface() if OS != "Windows" or action == "up" else ""
    print(f"{OS}: using {tool.__name__}, interface {IF or '(all SNP rules)'}")
    tool(IF, action)


if __name__ == "__main__":
    main()
