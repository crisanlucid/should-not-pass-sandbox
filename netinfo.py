#!/usr/bin/env python3
"""Show which networks and addresses of THIS host the VM must never reach.

  python3 -I netinfo.py              report
  python3 -I netinfo.py --deny       merged deny list, one CIDR per line (for the proxy addon)
  python3 -I netinfo.py --public-ip  also look up the public IP (one request to api.ipify.org)
  python3 -I netinfo.py --exposure   host services the VM can reach at 192.168.56.1; exit 1 if any besides the proxy

Needs psutil (pip install psutil). Works on Linux, macOS and Windows. Read-only.
"""
import ipaddress as ip
import json
import platform
import re
import socket
import subprocess
import sys

from windows_host import powershell

try:
    import psutil
except ImportError:
    sys.exit("pip install psutil")

# Always denied, whatever the interfaces say.
STATIC = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
          "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
          "::/128", "::1/128", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
          # Translation/tunnelling may embed private IPv4 destinations. Reject
          # these mechanisms rather than let them bypass the IPv4 deny ranges.
          "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"]


def interfaces():
    """(name, network, address) for every configured interface address."""
    out = []
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            addr = a.address.split("%")[0]  # drop IPv6 zone id
            address = ip.ip_address(addr)
            # Some Windows interfaces have no netmask. Still deny the host's
            # own address, rather than accidentally making it a public target.
            prefix = address.max_prefixlen
            if a.netmask:
                mask = ip.ip_address(a.netmask.split("%")[0])
                if mask.version != address.version:
                    raise ValueError(f"invalid netmask for interface {name}")
                prefix = int(mask).bit_count()
                expected = ((1 << prefix) - 1) << (address.max_prefixlen - prefix)
                if int(mask) != expected:
                    raise ValueError(f"non-contiguous netmask for interface {name}")
            out.append((name, ip.ip_network(f"{addr}/{prefix}", strict=False), addr))
    return out


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout


def windows_addresses(query):
    """Read address properties as JSON, independent of Windows display language."""
    script = ("$ErrorActionPreference = 'Stop'; "
              "$env:PSModulePath = Join-Path $PSHOME 'Modules'; "
              "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
              f"$values = @({query}); ConvertTo-Json -InputObject $values -Compress")
    result = subprocess.run(powershell(script),
                            capture_output=True, text=True, encoding="utf-8", timeout=10, check=True)
    values = json.loads(result.stdout.lstrip("\ufeff"))
    if not isinstance(values, list):
        values = [values]
    addresses = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        # IPv6 scope ids are meaningful to the OS, not to ipaddress networks.
        address = ip.ip_address(value.strip().split("%")[0])
        if not address.is_unspecified:
            addresses.append(str(address))
    return list(dict.fromkeys(addresses))


def gateways():
    # ponytail: best effort per OS, the interface subnets already cover most gateways
    try:
        os_ = platform.system()
        if os_ == "Linux":
            return re.findall(r"default via (\S+)", run("ip", "route", "show", "default"))
        if os_ == "Darwin":
            return re.findall(r"gateway: (\S+)", run("route", "-n", "get", "default"))
        if os_ == "Windows":
            return windows_addresses("Get-NetRoute | Where-Object { "
                                     "$_.DestinationPrefix -in '0.0.0.0/0','::/0' } | "
                                     "Select-Object -ExpandProperty NextHop")
        return []
    except Exception:
        return []


def dns_servers():
    try:
        if platform.system() == "Windows":
            return windows_addresses("Get-DnsClientServerAddress | "
                                     "Select-Object -ExpandProperty ServerAddresses")
        with open("/etc/resolv.conf") as config:
            return re.findall(r"^nameserver\s+(\S+)", config.read(), re.M)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def public_ip():
    import urllib.request
    return urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip()


def deny_list(extra=()):
    nets = [ip.ip_network(n) for n in STATIC]
    nets += [n for _, n, _ in interfaces()]
    nets += [ip.ip_network(f"{a}/{32 if ':' not in a else 128}") for a in (*extra, *gateways())
             if a and "%" not in a]
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    return [*ip.collapse_addresses(v4), *ip.collapse_addresses(v6)]


HOST_ONLY_IP, PROXY_PORT = "192.168.56.1", 3128


def exposure():
    """Listening sockets the VM can reach: bound to all interfaces or to the host-only address."""
    seen = {}
    for c in psutil.net_connections("inet"):
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        if c.laddr.ip not in ("0.0.0.0", "::", HOST_ONLY_IP):
            continue  # loopback or another specific interface, not reachable from the VM
        who = "?"
        if c.pid:
            try:
                p = psutil.Process(c.pid)
                who = f"{p.name()} ({p.username()})"
            except psutil.Error:
                pass
        seen.setdefault((c.laddr.port, c.laddr.ip), who)
    return sorted(seen.items())


if __name__ == "__main__":
    if "--exposure" in sys.argv:
        try:
            found = exposure()
        except psutil.AccessDenied:
            sys.exit("needs root on macOS to list sockets; try: sudo lsof -nP -iTCP -sTCP:LISTEN")
        bad = {k[0] for k, _ in found} - {PROXY_PORT}  # unique ports, IPv4 and IPv6 rows count once
        print(f"Reachable from the VM at {HOST_ONLY_IP} (process unknown means another user or root):")
        for (port, addr), who in found:
            print(f"  {port:<6} {addr:<14} {who}{'   <- proxy' if port == PROXY_PORT else ''}")
        print(f"\n{len(bad)} exposed besides the proxy." if bad else "\nOnly the proxy is exposed.")
        sys.exit(1 if bad else 0)
    want_public = "--public-ip" in sys.argv
    pub = public_ip() if want_public else None
    extra = [pub] if pub else []
    if "--deny" in sys.argv:
        print(*deny_list(extra), sep="\n")
        sys.exit()

    print(f"OS: {platform.system()} {platform.release()}\n\nInterfaces (host addresses and networks):")
    for name, net, addr in interfaces():
        print(f"  {name:<20} {addr:<40} {net}")
    print("\nDefault gateway:", *gateways() or ["not found"])
    print("DNS servers:    ", *dns_servers() or ["not found"])
    print("Public IP:      ", pub or "not checked (use --public-ip)")
    print(f"\nDeny list ({len(deny_list(extra))} entries, loaded by the proxy):")
    print(*("  " + str(n) for n in deny_list(extra)), sep="\n")
