#!/usr/bin/env bash
# Response to the eMudhra intermediate CA private-key compromise (2026-10).
# Run as root inside a Debian/Ubuntu-based image (vLLM images are Ubuntu).
#
#  1. Upgrade ca-certificates to the distro fix
#       Ubuntu 22.04: 20260816ubuntu0.22.04.1  / 24.04: 20260816ubuntu0.24.04.1
#       (distrusts "emSign ECC Root CA - G3", LP: #2171507)
#  2. Explicitly distrust emSign ECC Root CA - G3 and AAA Certificate Services
#     in /etc/ca-certificates.conf as well (belt and braces, and survives a
#     downgrade or an older base image).
#  3. Upgrade Python certifi (>= 2026.10.19 dropped the root) and strip the
#     blocked / weak certificates from every bundle Python can see,
#     including vendored copies (pip/_vendor/certifi, ...).
#  4. Gate: audit_trust.py scan must come back clean or the build fails.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
CERTIFI_MIN="${CERTIFI_MIN:-2026.10.19}"

echo "== [eMudhra] 1/4 upgrade ca-certificates"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates openssl
dpkg-query -W -f='ca-certificates ${Version}\n' ca-certificates
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "== [eMudhra] 2/4 distrust roots in /etc/ca-certificates.conf"
for name in emSign_ECC_Root_CA_-_G3.crt Comodo_AAA_Services_root.crt; do
  # Drop any positive entry, then add a '!' (deselect) entry.
  sed -i "\#^mozilla/${name}\$#d" /etc/ca-certificates.conf
  grep -qx "!mozilla/${name}" /etc/ca-certificates.conf \
    || echo "!mozilla/${name}" >> /etc/ca-certificates.conf
done
update-ca-certificates --fresh >/dev/null

echo "== [eMudhra] 3/4 certifi >= ${CERTIFI_MIN} and bundle cleanup"
if "$PY" -c 'import certifi' 2>/dev/null; then
  "$PY" -m pip install --no-cache-dir -q --upgrade "certifi>=${CERTIFI_MIN}"
  "$PY" -c 'import certifi; print("certifi", certifi.__version__)'
fi
"$PY" "$HERE/audit_trust.py" scan --fix

echo "== [eMudhra] 4/4 verify"
"$PY" "$HERE/audit_trust.py" scan
echo "== [eMudhra] trust store is clean"
