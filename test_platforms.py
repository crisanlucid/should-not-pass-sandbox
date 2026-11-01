"""Regression coverage for existing Unix installations and OS backend selection."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import firewall
import snp


class PlatformCompatibilityTests(unittest.TestCase):
    def setUp(self):
        for attribute in ('VM', 'STATE', 'DRY'):
            context = patch.object(snp, attribute, getattr(snp, attribute))
            context.start()
            self.addCleanup(context.stop)

    def test_firewall_selects_native_backend_without_os_configuration(self):
        for host, tools, selected in [('Linux', {'nft'}, 'nft'),
                                      ('Linux', {'iptables'}, 'iptables'),
                                      ('Darwin', set(), 'pf'),
                                      ('Windows', set(), 'windows')]:
            with self.subTest(host=host, backend=selected), \
                    patch.object(firewall, 'OS', host), patch.object(firewall, 'DRY', True), \
                    patch.object(firewall.sys, 'argv', ['firewall.py', 'up']), \
                    patch.object(firewall, 'interface', return_value='sandbox'), \
                    patch.object(firewall.shutil, 'which', side_effect=lambda name: name if name in tools else None), \
                    patch.object(firewall, selected) as backend, patch('builtins.print'):
                backend.__name__ = selected
                firewall.main()
                backend.assert_called_once_with('sandbox', 'up')

    def test_posix_vm_names_keep_spaces_and_unicode(self):
        with patch.object(snp, 'WIN', False), \
                patch.object(snp.sys, 'argv', ['snp.py', '--name', 'Frontend dev α', '--dry-run', 'status']), \
                patch.object(snp, 'status') as status:
            snp.main()
            self.assertEqual(snp.VM, 'Frontend dev α')
        status.assert_called_once()

    def test_existing_plain_pid_proxy_is_recognized_and_stoppable(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(snp, 'STATE', Path(directory)), patch.object(snp, 'DRY', False), \
                patch.object(snp, 'stop_vm'), patch.object(snp, 'WIN', False):
            pidfile = snp.STATE / 'proxy.pid'
            pidfile.write_text('123')
            process = Mock()
            process.create_time.return_value = pidfile.stat().st_mtime - 1
            process.cmdline.return_value = [snp.exe('mitmdump'), '--set',
                f"confdir={snp.STATE / 'mitmproxy'}", '-s', str(snp.HERE / 'proxy_addon.py')]
            with patch('psutil.Process', return_value=process):
                self.assertIs(snp.proxy_process(), process)
                snp.down()
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=10)
            self.assertFalse(pidfile.exists())

    def test_plain_pid_cannot_identify_a_new_or_unrelated_process(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(snp, 'STATE', Path(directory)):
            pidfile = snp.STATE / 'proxy.pid'
            pidfile.write_text(json.dumps(123))
            process = Mock()
            process.create_time.return_value = pidfile.stat().st_mtime + 1
            process.cmdline.return_value = [snp.exe('mitmdump'), '--set',
                f"confdir={snp.STATE / 'mitmproxy'}", '-s', str(snp.HERE / 'proxy_addon.py')]
            with patch('psutil.Process', return_value=process):
                self.assertIsNone(snp.proxy_process())
                process.create_time.return_value = pidfile.stat().st_mtime - 1
                process.cmdline.return_value = ['unrelated-program']
                self.assertIsNone(snp.proxy_process())


if __name__ == '__main__':
    unittest.main()
