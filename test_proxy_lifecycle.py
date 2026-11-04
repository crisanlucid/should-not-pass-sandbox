"""Offline proxy readiness tests: never query real processes or open sockets."""
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import psutil

import snp


def connection(address=snp.HOST_IP, port=snp.PORT, status=psutil.CONN_LISTEN,
               family=socket.AF_INET, type_=socket.SOCK_STREAM):
    return SimpleNamespace(family=family, type=type_, status=status,
                           laddr=SimpleNamespace(ip=address, port=port))


class ProxyReadinessTests(unittest.TestCase):
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
                    patch.object(snp.os, "getpid", return_value=123), \
                    patch.object(psutil, "Process", return_value=process) as identify, \
                    patch.dict(sys.modules, {"mitmproxy.tools.main": module}):
                snp.proxy_entry()
            identify.assert_called_once_with(123)
            module.mitmdump.assert_called_once_with()

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


if __name__ == "__main__":
    unittest.main()
