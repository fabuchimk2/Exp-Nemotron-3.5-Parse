#!/usr/bin/env bash
# Run on each Docker host (the A2000 machine and the RTX PRO 6000 machine).
# The host's trust store is used by `docker pull`, apt, pip, curl, etc.,
# so it needs the eMudhra fix as well, not just the container.
#
#   sudo security/emudhra/host-check.sh          # report only
#   sudo security/emudhra/host-check.sh --fix    # apply the distro update + distrust
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FIX=0; [[ "${1:-}" == "--fix" ]] && FIX=1
IMAGE="${AUDIT_IMAGE:-nemotron-parse-vllm:0.26.0}"
rc=0

echo "== OS: $(. /etc/os-release; echo "$PRETTY_NAME")"
if command -v dpkg-query >/dev/null; then
  v="$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null || echo none)"
  echo "== ca-certificates: $v"
  if ! zcat /usr/share/doc/ca-certificates/changelog.gz 2>/dev/null | head -20 \
       | grep -q 'emSign ECC Root CA - G3'; then
    echo "   !! the installed package predates the eMudhra fix"
    echo "      (Ubuntu: 20260816ubuntu0.<release>.1 / Debian: DSA-6572-1, DLA-4845-1)"
    if (( FIX )) && apt-get update -qq \
         && apt-get install -y -qq --only-upgrade ca-certificates; then
      echo "   -> upgraded to $(dpkg-query -W -f='${Version}' ca-certificates)"
    else
      rc=1
    fi
  fi
fi

if (( FIX )) && [[ -f /etc/ca-certificates.conf ]]; then
  for name in emSign_ECC_Root_CA_-_G3.crt Comodo_AAA_Services_root.crt; do
    sed -i "\#^mozilla/${name}\$#d" /etc/ca-certificates.conf
    grep -qx "!mozilla/${name}" /etc/ca-certificates.conf \
      || echo "!mozilla/${name}" >> /etc/ca-certificates.conf
  done
  update-ca-certificates --fresh >/dev/null
  echo "== distrust entries applied, bundle regenerated"
fi

echo "== auditing host bundles"
if python3 -c 'import cryptography' 2>/dev/null; then
  extra=(); (( FIX )) && extra=(--fix)
  python3 "$HERE/audit_trust.py" scan "${extra[@]}" || rc=1
elif docker image inspect "$IMAGE" >/dev/null 2>&1; then
  # No python3-cryptography on the host: audit with the built image.
  docker run --rm --entrypoint python3 \
    -v /etc/ssl/certs/ca-certificates.crt:/host/ca-certificates.crt:ro \
    "$IMAGE" /opt/security/emudhra/audit_trust.py scan \
    --bundle /host/ca-certificates.crt || rc=1
else
  echo "   (install python3-cryptography or build $IMAGE first)"; rc=2
fi

# Docker registry CA overrides are another place a blocked root could live.
if [[ -d /etc/docker/certs.d ]] && python3 -c 'import cryptography' 2>/dev/null; then
  mapfile -t pems < <(find /etc/docker/certs.d -name '*.crt')
  if (( ${#pems[@]} )); then
    args=(); for p in "${pems[@]}"; do args+=(--bundle "$p"); done
    python3 "$HERE/audit_trust.py" scan "${args[@]}" || rc=1
  fi
fi

echo "== result: $([[ $rc == 0 ]] && echo OK || echo "ACTION NEEDED (rc=$rc)")"
exit $rc
