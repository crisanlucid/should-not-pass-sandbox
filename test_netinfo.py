"""Offline tests for network discovery, including Windows PowerShell output."""
import base64
import ipaddress as ip
import json
import socket
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import mock_open, patch

import netinfo


def address(family, value, mask):
    return SimpleNamespace(family=family, address=value, netmask=mask)


class InterfaceTests(unittest.TestCase):
    def test_windows_names_and_ipv6_scope(self):
        entries = {"Ethernet réseau d'entreprise": [
            address(socket.AF_INET, "192.168.50.7", "255.255.255.0"),
            address(socket.AF_INET6, "2001:db8:1::7%12", "ffff:ffff:ffff:ffff::"),
            address(-1, "00:00:00:00:00:00", None),
        ]}
        with patch.object(netinfo.psutil, "net_if_addrs", return_value=entries):
            self.assertEqual(netinfo.interfaces(), [
                ("Ethernet réseau d'entreprise", ip.ip_network("192.168.50.0/24"), "192.168.50.7"),
                ("Ethernet réseau d'entreprise", ip.ip_network("2001:db8:1::/64"), "2001:db8:1::7"),
            ])

    def test_missing_netmask_still_denies_host_address(self):
        entries = {"VPN": [address(socket.AF_INET, "203.0.113.5", None),
                           address(socket.AF_INET6, "2001:db8::5", None)]}
        with patch.object(netinfo.psutil, "net_if_addrs", return_value=entries), \
                patch.object(netinfo, "gateways", return_value=[]):
            nets = netinfo.deny_list()
        self.assertTrue(any(ip.ip_address("203.0.113.5") in n for n in nets))
        self.assertTrue(any(ip.ip_address("2001:db8::5") in n for n in nets))
        self.assertFalse(any(ip.ip_address("203.0.113.6") in n for n in nets))

    def test_noncontiguous_mask_is_rejected(self):
        entries = {"Ethernet": [address(socket.AF_INET, "203.0.113.5", "255.0.255.0")]}
        with patch.object(netinfo.psutil, "net_if_addrs", return_value=entries):
            with self.assertRaisesRegex(ValueError, "non-contiguous"):
                netinfo.interfaces()

    def test_windows_legacy_site_local_dns_is_denied(self):
        with patch.object(netinfo, "interfaces", return_value=[]), \
                patch.object(netinfo, "gateways", return_value=[]):
            nets = netinfo.deny_list()
        self.assertTrue(any(ip.ip_address("fec0:0:0:ffff::1") in n for n in nets))


class WindowsDiscoveryTests(unittest.TestCase):
    def query(self, output, query="Get-Example"):
        completed = SimpleNamespace(stdout=output)
        with patch.object(netinfo.subprocess, "run", return_value=completed) as run:
            result = netinfo.windows_addresses(query)
        return result, run.call_args

    def test_json_addresses_are_normalized_and_deduplicated(self):
        values = ["192.168.50.1", "2001:0db8::1", "fe80::1%12", "192.168.50.1", "::", "0.0.0.0", "", None]
        result, _ = self.query("\ufeff" + json.dumps(values))
        self.assertEqual(result, ["192.168.50.1", "2001:db8::1", "fe80::1"])

    def test_scalar_and_empty_json(self):
        self.assertEqual(self.query('"192.168.50.1"')[0], ["192.168.50.1"])
        self.assertEqual(self.query("[]")[0], [])

    def test_command_uses_json_utf8_and_noninteractive_powershell(self):
        _, call = self.query("[]", "Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses")
        command = call.args[0]
        self.assertIn("-NoProfile", command)
        self.assertIn("-NonInteractive", command)
        script = base64.b64decode(command[-1]).decode("utf-16le")
        self.assertIn("Get-DnsClientServerAddress", script)
        self.assertIn("ConvertTo-Json -InputObject $values -Compress", script)
        self.assertIn("OutputEncoding", script)
        self.assertIn("$env:PSModulePath = Join-Path $PSHOME 'Modules'", script)
        self.assertTrue(call.kwargs["check"])
        self.assertEqual(call.kwargs["encoding"], "utf-8")
        self.assertEqual(call.kwargs["timeout"], 10)

    def test_gateway_query_handles_ipv4_and_ipv6_without_missing_route_errors(self):
        with patch.object(netinfo.platform, "system", return_value="Windows"), \
                patch.object(netinfo, "windows_addresses", return_value=["192.168.50.1", "fe80::1"]) as query:
            self.assertEqual(netinfo.gateways(), ["192.168.50.1", "fe80::1"])
        script = query.call_args.args[0]
        self.assertIn("0.0.0.0/0", script)
        self.assertIn("::/0", script)
        self.assertIn("Where-Object", script)
        self.assertIn("NextHop", script)

    def test_dns_uses_serveraddresses(self):
        with patch.object(netinfo.platform, "system", return_value="Windows"), \
                patch.object(netinfo, "windows_addresses", return_value=["192.168.50.1"]) as query:
            self.assertEqual(netinfo.dns_servers(), ["192.168.50.1"])
        self.assertIn("Get-DnsClientServerAddress", query.call_args.args[0])
        self.assertIn("ServerAddresses", query.call_args.args[0])

    def test_windows_query_errors_remain_best_effort(self):
        for error in (OSError("unavailable"), subprocess.CalledProcessError(1, "powershell"),
                      subprocess.TimeoutExpired("powershell", 10), ValueError("invalid JSON")):
            with self.subTest(error=type(error).__name__), \
                    patch.object(netinfo.platform, "system", return_value="Windows"), \
                    patch.object(netinfo, "windows_addresses", side_effect=error):
                self.assertEqual(netinfo.gateways(), [])
                self.assertEqual(netinfo.dns_servers(), [])

    def test_invalid_ip_json_is_rejected(self):
        with self.assertRaises(ValueError):
            self.query('["localized diagnostic output"]')


class UnixDiscoveryTests(unittest.TestCase):
    def test_linux_gateway(self):
        with patch.object(netinfo.platform, "system", return_value="Linux"), \
                patch.object(netinfo, "run", return_value="default via 192.168.1.1 dev eth0\n"):
            self.assertEqual(netinfo.gateways(), ["192.168.1.1"])

    def test_macos_gateway(self):
        with patch.object(netinfo.platform, "system", return_value="Darwin"), \
                patch.object(netinfo, "run", return_value="   gateway: 192.168.1.1\n"):
            self.assertEqual(netinfo.gateways(), ["192.168.1.1"])

    def test_resolv_conf_dns(self):
        with patch.object(netinfo.platform, "system", return_value="Linux"), \
                patch("builtins.open", mock_open(read_data="nameserver 192.168.1.1\nnameserver 2001:db8::53\n")):
            self.assertEqual(netinfo.dns_servers(), ["192.168.1.1", "2001:db8::53"])


if __name__ == "__main__":
    unittest.main()
