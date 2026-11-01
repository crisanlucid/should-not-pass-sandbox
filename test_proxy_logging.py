"""Security decisions must survive an unwritable audit log and broken stderr."""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest import mock

from mitmproxy import http

import proxy_addon
from egress_rules import Denied


class ProxyLoggingTests(unittest.TestCase):
    def setUp(self):
        self.addon = proxy_addon.Sandbox()
        self.addon.rules = mock.Mock()
        self.bad_log = mock.Mock()
        self.bad_log.open.side_effect = OSError("disposable disk-full simulation")
        self.patches = (
            mock.patch.object(proxy_addon, "LOG", self.bad_log),
            mock.patch.object(proxy_addon, "_LOG_WARNING_SENT", False),
            mock.patch.object(proxy_addon, "LOG_ONLY", False),
        )
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_audit_open_failure_warns_once_without_raising(self):
        with contextlib.redirect_stderr(io.StringIO()) as warning:
            proxy_addon.log("deny", "127.0.0.1", "private")
            proxy_addon.log("deny", "127.0.0.1", "private")
        self.assertEqual(warning.getvalue().count("cannot write proxy audit log"), 1)
        self.assertEqual(self.bad_log.open.call_count, 2)

    def test_audit_write_failure_warns_without_raising(self):
        self.bad_log.open.side_effect = None
        stream = mock.MagicMock()
        stream.__enter__.return_value.write.side_effect = OSError("disposable write failure")
        self.bad_log.open.return_value = stream
        with contextlib.redirect_stderr(io.StringIO()) as warning:
            proxy_addon.log("deny", "127.0.0.1", "private")
        self.assertIn("cannot write proxy audit log", warning.getvalue())

    def test_broken_stderr_cannot_interrupt_denial(self):
        self.addon.rules.resolve.side_effect = Denied("private destination")
        data = SimpleNamespace(server=SimpleNamespace(address=("127.0.0.1", 80), error=None))
        broken_stderr = mock.Mock()
        broken_stderr.write.side_effect = OSError("disposable stderr failure")
        with mock.patch.object(proxy_addon.sys, "stderr", broken_stderr):
            self.addon.server_connect(data)
        self.assertEqual(data.server.error, "blocked: private destination")

    def test_private_destination_remains_denied_when_log_is_unwritable(self):
        self.addon.rules.resolve.side_effect = Denied("127.0.0.1 is private")
        data = SimpleNamespace(server=SimpleNamespace(address=("127.0.0.1", 80), error=None))
        with contextlib.redirect_stderr(io.StringIO()):
            self.addon.server_connect(data)
        self.assertIn("blocked:", data.server.error)
        self.assertEqual(data.server.address, ("127.0.0.1", 80))

    def test_allow_list_response_remains_denied_when_log_is_unwritable(self):
        self.addon.rules.host_allowed.return_value = False
        flow = SimpleNamespace(request=http.Request.make("GET", "http://example.com/"), response=None)
        with contextlib.redirect_stderr(io.StringIO()):
            self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertIn(b"blocked:", flow.response.content)

    def test_public_destination_is_pinned_when_log_is_unwritable(self):
        self.addon.rules.resolve.return_value = "93.184.216.34"
        data = SimpleNamespace(server=SimpleNamespace(address=("example.com", 80), error=None))
        with contextlib.redirect_stderr(io.StringIO()):
            self.addon.server_connect(data)
        self.assertEqual(data.server.address, ("93.184.216.34", 80))
        self.assertIsNone(data.server.error)

    def test_denial_is_applied_before_audit_callback(self):
        self.addon.rules.resolve.side_effect = Denied("private")
        data = SimpleNamespace(server=SimpleNamespace(address=("127.0.0.1", 80), error=None))
        with mock.patch.object(proxy_addon, "log", side_effect=RuntimeError("custom audit callback failure")):
            with self.assertRaisesRegex(RuntimeError, "custom audit"):
                self.addon.server_connect(data)
        self.assertEqual(data.server.error, "blocked: private")
        self.addon.rules.host_allowed.return_value = False
        flow = SimpleNamespace(request=http.Request.make("GET", "http://example.com/"), response=None)
        with mock.patch.object(proxy_addon, "log", side_effect=RuntimeError("custom audit callback failure")):
            with self.assertRaisesRegex(RuntimeError, "custom audit"):
                self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
