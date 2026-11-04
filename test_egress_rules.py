"""python3 test_egress_rules.py  (offline, no mitmproxy needed)"""
import ipaddress as ip
import tempfile
from pathlib import Path

from egress_rules import Denied, Rules
import netinfo

LAN = lambda: [ip.ip_network(n) for n in ("10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "192.168.0.0/16",
                                          "::1/128", "203.0.113.0/24")]


def fake(*addrs):
    return lambda host, port, type=0: [(2, 1, 6, "", (a, port)) for a in addrs]


def rules(resolver, allow=""):
    f = Path(tempfile.mkdtemp()) / "allow.txt"
    f.write_text(allow)
    return Rules(allow_file=f, resolver=resolver, deny_list=LAN)


def denied(r, host):
    try:
        r.resolve(host, 443)
    except Denied:
        return True
    return False


def main():
    assert rules(fake("93.184.216.34")).resolve("example.com", 443) == "93.184.216.34"      # public ok, pinned IP
    assert denied(rules(fake("10.1.2.3")), "evil.test")                                      # hostname -> private
    assert denied(rules(fake("127.0.0.1")), "evil.test")                                     # loopback
    assert denied(rules(fake("169.254.169.254")), "evil.test")                               # metadata
    assert denied(rules(fake("::ffff:127.0.0.1")), "evil.test")                              # IPv4-mapped IPv6
    assert denied(rules(fake("93.184.216.34", "192.168.1.5")), "rebind.test")                # one private answer is enough
    assert denied(rules(fake("203.0.113.9")), "evil.test")                                   # host's own public-looking LAN
    assert denied(rules(fake("93.184.216.34")), "evil.test") is False

    # Upstream IPv6 connections originate on the host, so guest IPv6 firewall
    # rules cannot protect against unspecified or IPv4 transition destinations.
    static = lambda: [ip.ip_network(n) for n in netinfo.STATIC]
    for address in ("::", "64:ff9b::7f00:1", "64:ff9b::c0a8:1", "64:ff9b:1::a00:1",
                    "2002:7f00:1::", "2002:c0a8:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2"):
        r = Rules(allow_file="/nonexistent", resolver=fake(address), deny_list=static)
        assert denied(r, "transition.test"), address

    import socket                                                                           # odd literals, real resolver
    for h in ("2130706433", "0x7f.1", "127.1", "0177.0.0.1"):
        r = Rules(allow_file="/nonexistent", deny_list=LAN)
        try:
            address = r.resolve(h, 443)
            # Literal syntax varies by OS; an accepted result must not be loopback.
            assert not ip.ip_address(address).is_loopback, (h, address)
        except (Denied, socket.gaierror):
            pass  # blocked or not resolvable on this OS

    assert rules(fake()).host_allowed("anything.com")                                        # no allow.txt entries: open
    r = rules(fake(), "# comment\npypi.org\nnpmjs.org\n")
    assert r.host_allowed("pypi.org") and r.host_allowed("files.pypi.org") and r.host_allowed("PyPI.org.")
    assert not r.host_allowed("evilpypi.org") and not r.host_allowed("example.com")
    print("ok")


main()
