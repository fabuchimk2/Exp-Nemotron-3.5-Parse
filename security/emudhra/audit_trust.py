#!/usr/bin/env python3
"""eMudhra intermediate CA key compromise (2026-10) trust audit.

Background: the private keys of eight eMudhra intermediate CAs
(chaining to "emSign ECC Root CA - G3", with Sectigo cross-signs under
"AAA Certificate Services") were P-384 scalars smaller than 256, so anyone
can recover them from the public certificate and forge TLS / code-signing
certificates.

This tool:
  scan    : finds CA bundles (system, certifi, vendored copies, $SSL_CERT_FILE ...)
            and reports blocked roots and EC certificates whose private key
            is a tiny scalar (k <= --weak-max).  --fix rewrites the bundles
            without those certificates.
  hosts   : fetches the certificate chain each host actually presents and
            checks every certificate in it the same way.

Exit code: 0 = clean, 1 = findings, 2 = usage / runtime error.
Requires: python3 + cryptography (present in the vLLM image).
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Some legacy roots have non-positive serials; irrelevant for this audit.
warnings.filterwarnings("ignore", message="Parsed a serial number")

HERE = Path(__file__).resolve().parent

# SHA-256 of the DER certificate.  Extracted from Ubuntu's ca-certificates
# package (the PEM copies live in ./blocked-roots/ and are re-hashed at start).
BLOCKED_ROOTS = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b":
        "emSign ECC Root CA - G3 (issuer of the compromised eMudhra intermediates)",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4":
        "AAA Certificate Services (Sectigo cross-signs of the compromised intermediates)",
}
# SHA-256 of the DER SubjectPublicKeyInfo (catches re-issued copies of the same key).
BLOCKED_SPKI = {
    "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782":
        "emSign ECC Root CA - G3 key",
    "bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3":
        "AAA Certificate Services key",
}

PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----", re.S
)

CURVES = (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1())


@dataclass
class Finding:
    where: str
    subject: str
    reason: str


def _weak_point_table(weak_max: int) -> dict[bytes, int]:
    """Public points k*G for k in 1..weak_max on the NIST curves -> k."""
    table: dict[bytes, int] = {}
    for curve in CURVES:
        for k in range(1, weak_max + 1):
            pub = ec.derive_private_key(k, curve).public_key()
            table[pub.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )] = k
    return table


class Checker:
    def __init__(self, weak_max: int):
        self.weak = _weak_point_table(weak_max) if weak_max > 0 else {}
        self.blocked_fp = dict(BLOCKED_ROOTS)
        self.blocked_spki = dict(BLOCKED_SPKI)
        # Also trust the shipped PEMs (in case someone adds one there).
        for pem in sorted((HERE / "blocked-roots").glob("*.crt")):
            for cert in load_pem_certs(pem.read_bytes()):
                self.blocked_fp.setdefault(fp(cert), f"{pem.name}")
                self.blocked_spki.setdefault(spki_fp(cert), f"{pem.name} key")

    def check(self, cert: x509.Certificate) -> str | None:
        if (r := self.blocked_fp.get(fp(cert))):
            return f"blocked root: {r}"
        if (r := self.blocked_spki.get(spki_fp(cert))):
            return f"blocked public key: {r}"
        pub = cert.public_key()
        if self.weak and isinstance(pub, ec.EllipticCurvePublicKey):
            pt = pub.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            if (k := self.weak.get(pt)) is not None:
                return f"WEAK EC KEY: private key recovered (k={k}, {pub.curve.name})"
        return None


def fp(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def spki_fp(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest()


def load_pem_certs(data: bytes) -> list[x509.Certificate]:
    out = []
    for m in PEM_RE.finditer(data):
        try:
            out.append(x509.load_pem_x509_certificate(m.group(0)))
        except ValueError:
            pass
    return out


def subject(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def default_bundles() -> list[Path]:
    cands: list[str] = [
        "/etc/ssl/certs/ca-certificates.crt",      # Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",         # RHEL/Fedora
        "/etc/ssl/cert.pem",                        # Alpine/macOS
    ]
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
                "NODE_EXTRA_CA_CERTS"):
        if os.environ.get(var):
            cands.append(os.environ[var])
    try:
        import certifi  # noqa: PLC0415
        cands.append(certifi.where())
    except ImportError:
        pass
    # Vendored copies (pip/_vendor/certifi, botocore, httplib2, ...).
    for root in sys.path + ["/usr/lib/python3/dist-packages", "/usr/local/lib"]:
        if os.path.isdir(root):
            cands += glob.glob(os.path.join(root, "**", "cacert.pem"), recursive=True)
            cands += glob.glob(os.path.join(root, "**", "cacerts.pem"), recursive=True)
    seen, out = set(), []
    for c in cands:
        p = Path(c)
        if p.is_file():
            real = p.resolve()
            if real not in seen:
                seen.add(real)
                out.append(real)
    return out


def scan_bundle(path: Path, checker: Checker, fix: bool) -> list[Finding]:
    data = path.read_bytes()
    findings: list[Finding] = []
    bad_blocks: list[bytes] = []
    for m in PEM_RE.finditer(data):
        try:
            cert = x509.load_pem_x509_certificate(m.group(0))
        except ValueError:
            continue
        if (reason := checker.check(cert)):
            findings.append(Finding(str(path), subject(cert), reason))
            bad_blocks.append(m.group(0))
    if fix and bad_blocks:
        new = data
        for blk in bad_blocks:
            new = new.replace(blk, b"")
        new = re.sub(rb"\n{3,}", b"\n\n", new)
        shutil.copy2(path, str(path) + ".pre-emudhra-fix")
        path.write_bytes(new)
    return findings


def fetch_chain(host: str, port: int, timeout: int) -> list[x509.Certificate]:
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}",
           "-servername", host, "-showcerts"]
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        m = re.match(r"^(?:https?://)?(?:[^@/]*@)?([^/:]+):(\d+)", proxy)
        if m:
            cmd += ["-proxy", f"{m.group(1)}:{m.group(2)}"]
    res = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
    return load_pem_certs(res.stdout)


def cmd_scan(args: argparse.Namespace, checker: Checker) -> int:
    bundles = [Path(b) for b in args.bundle] or default_bundles()
    if not bundles:
        print("no CA bundle found", file=sys.stderr)
        return 2
    total = 0
    for b in bundles:
        n = len(load_pem_certs(b.read_bytes()))
        findings = scan_bundle(b, checker, args.fix)
        total += len(findings)
        state = "FIXED" if (args.fix and findings) else ("NG" if findings else "OK")
        print(f"[{state}] {b} ({n} certs)")
        for f in findings:
            print(f"    - {f.subject}: {f.reason}")
    if args.fix:
        # Findings were removed; re-scan to make sure nothing is left.
        left = sum(len(scan_bundle(b, checker, False)) for b in bundles)
        print(f"removed {total} certificate(s); remaining findings: {left}")
        return 1 if left else 0
    return 1 if total else 0


def cmd_hosts(args: argparse.Namespace, checker: Checker) -> int:
    if not shutil.which("openssl"):
        print("openssl CLI not found", file=sys.stderr)
        return 2
    bad = 0
    for spec in args.host:
        host, _, port = spec.partition(":")
        try:
            chain = fetch_chain(host, int(port or 443), args.timeout)
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"[ERR] {spec}: {e}")
            bad += 1
            continue
        if not chain:
            print(f"[ERR] {spec}: could not obtain a certificate chain")
            bad += 1
            continue
        hits = [(c, r) for c in chain if (r := checker.check(c))]
        print(f"[{'NG' if hits else 'OK'}] {spec} (chain length {len(chain)})")
        for c in chain:
            print(f"    {subject(c)}")
        for c, r in hits:
            print(f"    !! {subject(c)}: {r}")
        bad += bool(hits)
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--weak-max", type=int, default=4096,
                    help="flag EC keys whose private scalar is <= this (default 4096; "
                         "the eMudhra keys were < 256). 0 disables.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan CA bundles")
    s.add_argument("--bundle", action="append", default=[],
                   help="bundle file to scan (repeatable). Default: auto-discover")
    s.add_argument("--fix", action="store_true",
                   help="remove offending certificates in place (keeps *.pre-emudhra-fix)")
    h = sub.add_parser("hosts", help="check the chains presented by hosts")
    h.add_argument("host", nargs="+", help="host[:port]")
    h.add_argument("--timeout", type=int, default=20)
    args = ap.parse_args(argv)

    checker = Checker(args.weak_max)
    return cmd_scan(args, checker) if args.cmd == "scan" else cmd_hosts(args, checker)


if __name__ == "__main__":
    sys.exit(main())
