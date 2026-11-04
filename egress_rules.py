"""Egress rules for the sandbox proxy: pure logic, no mitmproxy import, so it is testable alone."""
import ipaddress as ip
import socket
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import netinfo  # noqa: E402  (deny list: static private ranges + this host's networks)

RELOAD_SECONDS = 60


class Denied(Exception):
    pass


class Rules:
    def __init__(self, allow_file=HERE / "allow.txt", resolver=socket.getaddrinfo,
                 deny_list=netinfo.deny_list):
        self.allow_file, self.resolver, self.deny_list = Path(allow_file), resolver, deny_list
        self._nets, self._loaded = [], 0.0

    def deny_nets(self):
        # networks change (Wi-Fi switch, VPN), so reload the host's view periodically
        if time.monotonic() - self._loaded > RELOAD_SECONDS or not self._nets:
            self._nets, self._loaded = list(self.deny_list()), time.monotonic()
        return self._nets

    def allow_entries(self):
        try:
            lines = self.allow_file.read_text().splitlines()
        except OSError:
            return []
        return [l.strip().lower().rstrip(".") for l in lines if l.strip() and not l.startswith("#")]

    def host_allowed(self, host):
        """Empty or missing allow.txt means open: any public host. Entries match the domain and its subdomains."""
        entries = self.allow_entries()
        host = host.lower().rstrip(".")
        return not entries or any(host == e or host.endswith("." + e) for e in entries)

    def resolve(self, host, port):
        """Resolve once, reject if ANY answer is private, return the IP to connect to (pins against DNS rebinding)."""
        infos = self.resolver(host, port, type=socket.SOCK_STREAM)
        addrs = []
        for info in infos:
            a = ip.ip_address(info[4][0].split("%")[0])
            addrs.append(a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a)
        if not addrs:
            raise Denied(f"{host}: no address")
        for a in addrs:
            for net in self.deny_nets():
                if a in net:
                    raise Denied(f"{host} -> {a} is in {net}")
        return str(addrs[0])
