"""Tests for audit_trust.py.  Run: python3 -m unittest discover -s security/emudhra/tests"""
import contextlib
import datetime
import io
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_trust  # noqa: E402

ROOTS = Path(__file__).resolve().parents[1] / "blocked-roots"


def make_ca(key, cn):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA384()))


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


class AuditTrustTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checker = audit_trust.Checker(weak_max=300)
        # Same defect as the eMudhra intermediates: P-384 private key = 4.
        cls.weak = make_ca(ec.derive_private_key(4, ec.SECP384R1()), "Weak k=4 CA")
        cls.strong = make_ca(ec.generate_private_key(ec.SECP384R1()), "Strong CA")
        cls.emsign = (ROOTS / "emSign_ECC_Root_CA_-_G3.crt").read_bytes()
        cls.aaa = (ROOTS / "Comodo_AAA_Services_root.crt").read_bytes()

    def run_scan(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = audit_trust.cmd_scan(
                audit_trust.argparse.Namespace(bundle=list(argv[0]), fix=argv[1]),
                self.checker)
        return rc, out.getvalue()

    def test_weak_key_detected(self):
        reason = self.checker.check(self.weak)
        self.assertIn("WEAK EC KEY", reason)
        self.assertIn("k=4", reason)

    def test_weak_key_detected_at_upper_bound(self):
        cert = make_ca(ec.derive_private_key(300, ec.SECP256R1()), "k=300")
        self.assertIn("k=300", self.checker.check(cert))

    def test_strong_key_clean(self):
        self.assertIsNone(self.checker.check(self.strong))

    def test_blocked_roots_detected(self):
        for data in (self.emsign, self.aaa):
            cert = x509.load_pem_x509_certificate(data)
            self.assertIn("blocked", self.checker.check(cert))

    def test_scan_and_fix_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            b = Path(d) / "bundle.pem"
            b.write_bytes(pem(self.strong) + b"\n" + self.emsign + b"\n"
                          + pem(self.weak) + b"\n" + self.aaa)
            rc, out = self.run_scan([str(b)], False)
            self.assertEqual(rc, 1)
            self.assertIn("[NG]", out)

            rc, out = self.run_scan([str(b)], True)
            self.assertEqual(rc, 0, out)
            left = audit_trust.load_pem_certs(b.read_bytes())
            self.assertEqual([c.subject for c in left], [self.strong.subject])
            self.assertTrue(Path(str(b) + ".pre-emudhra-fix").exists())

            rc, out = self.run_scan([str(b)], False)
            self.assertEqual(rc, 0)
            self.assertIn("[OK]", out)

    def test_constants_match_shipped_pems(self):
        for data in (self.emsign, self.aaa):
            cert = x509.load_pem_x509_certificate(data)
            self.assertIn(audit_trust.fp(cert), audit_trust.BLOCKED_ROOTS)
            self.assertIn(audit_trust.spki_fp(cert), audit_trust.BLOCKED_SPKI)


if __name__ == "__main__":
    unittest.main()
