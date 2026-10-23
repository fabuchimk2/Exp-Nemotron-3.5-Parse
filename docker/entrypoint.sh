#!/usr/bin/env bash
# Startup: eMudhra trust re-check -> weight integrity check -> vllm serve.
# All knobs are environment variables; see profiles/*.env.
set -euo pipefail

MODEL_DIR="${MODEL_DIR:-/opt/nemotron-parse}"
cd "$MODEL_DIR"

# 1) eMudhra: refuse to start if a blocked/weak CA got back into a bundle
#    (e.g. a mounted bundle or a package installed at runtime).
if [[ "${EMUDHRA_AUDIT:-1}" == "1" ]]; then
  python3 /opt/security/emudhra/audit_trust.py scan \
    || { echo "[eMudhra] trust store audit FAILED - refusing to start" >&2; exit 1; }
fi
# Optional: check the chains that the hosts you talk to actually present
# (e.g. EMUDHRA_CHECK_HOSTS="huggingface.co cdn-lfs.huggingface.co").
if [[ -n "${EMUDHRA_CHECK_HOSTS:-}" ]]; then
  # shellcheck disable=SC2086
  python3 /opt/security/emudhra/audit_trust.py hosts ${EMUDHRA_CHECK_HOSTS}
fi

# 2) Weights must match the hashes recorded at build time.
if [[ -s .weights.sha256 ]]; then
  sha256sum --quiet -c .weights.sha256 \
    || { echo "weight checksum mismatch - refusing to start" >&2; exit 1; }
fi
echo "model revision: $(cat .revision 2>/dev/null || echo unknown)"

# Pass any arguments through for debugging (e.g. `docker run ... bash`).
if [[ $# -gt 0 ]]; then
  exec "$@"
fi

# 3) Serve.  Defaults follow the model card's vLLM recipe; the GPU-specific
#    values come from profiles/<gpu>.env.
args=(
  serve "$MODEL_DIR"
  --served-model-name "${SERVED_MODEL_NAME:-nemotron-parse}"
  --host 0.0.0.0 --port "${PORT:-8000}"
  --dtype bfloat16
  --trust-remote-code
  --max-model-len "${MAX_MODEL_LEN:-16384}"
  --max-num-seqs "${MAX_NUM_SEQS:-64}"
  --max-num-batched-tokens "${MAX_NUM_BATCHED_TOKENS:-16384}"
  --gpu-memory-utilization "${GPU_MEMORY_UTILIZATION:-0.90}"
  --limit-mm-per-prompt '{"image":1}'
  --no-enable-prefix-caching
)
[[ -f chat_template.jinja ]] && args+=(--chat-template chat_template.jinja)
[[ -n "${VLLM_API_KEY:-}" ]] && args+=(--api-key "$VLLM_API_KEY")
# GPU-specific extras, e.g. "--attention-backend TRITON_ATTN" on Ampere.
if [[ -n "${EXTRA_VLLM_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  args+=(${EXTRA_VLLM_ARGS})
fi

echo "+ vllm ${args[*]}"
exec vllm "${args[@]}"
