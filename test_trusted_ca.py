"""Only explicitly supplied public CA certificates may enter guest trust."""
import datetime
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

import snp


class TrustedCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ed25519.Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable SNP test CA')])
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(cls.key.public_key()).serial_number(1)
                   .not_valid_before(datetime.datetime(2020, 1, 1))
                   .not_valid_after(datetime.datetime(2100, 1, 1)))
        cls.ca = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(cls.key, None)
        cls.leaf = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(cls.key, None)

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.state = self.root / 'state'
        for attribute, value in [('STATE', self.state), ('VM', 'windows-ca-test'), ('DRY', False)]:
            context = patch.object(snp, attribute, value)
            context.start()
            self.addCleanup(context.stop)

    def test_pem_and_der_become_one_canonical_public_certificate_per_vm(self):
        pem = self.root / "développeur's public root.pem"
        der = self.root / 'root.cer'
        pem.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        der.write_bytes(self.ca.public_bytes(serialization.Encoding.DER))
        snp.store_trusted_ca([pem, der])
        digest = hashlib.sha256(der.read_bytes()).hexdigest()
        target = self.state / 'windows-ca-test' / 'trusted-ca' / (digest + '.crt')
        self.assertEqual(target.read_bytes(), pem.read_bytes())
        self.assertEqual(list(target.parent.iterdir()), [target])
        self.assertNotIn(b'PRIVATE KEY', target.read_bytes())

    def test_private_keys_bundles_leaf_certificates_and_malformed_data_are_rejected(self):
        public = self.ca.public_bytes(serialization.Encoding.PEM)
        private = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        inputs = [private, public + private, public + public,
                  self.leaf.public_bytes(serialization.Encoding.PEM), b'not a certificate']
        for number, data in enumerate(inputs):
            with self.subTest(number=number):
                source = self.root / ('invalid-' + str(number) + '.pem')
                source.write_bytes(data)
                with self.assertRaises(SystemExit):
                    snp.store_trusted_ca([source])
                self.assertFalse(self.state.exists())

    def test_dry_run_does_not_create_trust_state(self):
        source = self.root / 'root.pem'
        source.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        with patch.object(snp, 'DRY', True):
            snp.store_trusted_ca([source])
        self.assertFalse(self.state.exists())

    def test_missing_certificate_fails_without_creating_state(self):
        with self.assertRaisesRegex(SystemExit, 'CA certificate not found'):
            snp.store_trusted_ca([self.root / 'missing.crt'])
        self.assertFalse(self.state.exists())

    def test_proxy_bundle_preserves_baseline_trust_and_adds_only_supplied_roots(self):
        source = self.root / 'root.crt'
        source.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        baseline = self.root / 'baseline.pem'
        baseline.write_bytes(b'# baseline trust remains present\n' + source.read_bytes())
        snp.store_trusted_ca([source])
        with patch('certifi.where', return_value=str(baseline)):
            target = snp.proxy_ca_bundle()
        self.assertTrue(target.read_bytes().startswith(baseline.read_bytes()))
        self.assertTrue(target.read_bytes().endswith(source.read_bytes()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=target)
        self.assertTrue(context.get_ca_certs())

    def test_proxy_without_supplied_roots_keeps_default_trust(self):
        self.assertIsNone(snp.proxy_ca_bundle())
        self.assertFalse(self.state.exists())


if __name__ == '__main__':
    unittest.main()
