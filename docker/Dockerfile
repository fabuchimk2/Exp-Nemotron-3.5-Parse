# Nemotron-3.5-Parse on vLLM (one image for RTX A2000 and RTX PRO 6000)
#
# Why vLLM and not llama.cpp: as of 2026-10-22 llama.cpp (master 970b51c)
# has no support for this architecture (no GGUF conversion, no mtmd
# projector). The model card supports vLLM via NVIDIA's plugin.
#
# The default base is the model card's reference version, vLLM 0.26.0
# (CUDA 13.0, torch arch list includes 8.6 = A2000 and 12.0 = RTX PRO 6000).
# The plugin accepts vLLM 0.25.x to 0.32.x. To change it, override VLLM_IMAGE
# and VLLM_VERSION together.
ARG VLLM_IMAGE=vllm/vllm-openai:v0.26.0@sha256:ffb2d59b1c059a5bd8d781320c9f5189de8293693b7d95da54befddaa54abf52
FROM ${VLLM_IMAGE}

ARG VLLM_VERSION=0.26.0
# Pin a commit hash in production (resolves "main" at build time otherwise;
# the resolved commit is recorded in /opt/nemotron-parse/.revision).
ARG MODEL_REPO=nvidia/Nemotron-3.5-Parse
ARG MODEL_REVISION=main

# ---- eMudhra intermediate CA key compromise response (before any download) ----
COPY security/emudhra /opt/security/emudhra
RUN bash /opt/security/emudhra/harden-trust-store.sh

# Make every TLS client use the cleaned system bundle.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt

# ---- model + NVIDIA vLLM plugin (bundled in the model repository) ----
WORKDIR /opt/nemotron-parse
# HF_TOKEN is optional (the repo is public); passed as a BuildKit secret so it
# does not end up in an image layer.
RUN --mount=type=secret,id=hf_token,required=false \
    set -eu; \
    if [ -s /run/secrets/hf_token ]; then export HF_TOKEN="$(cat /run/secrets/hf_token)"; fi; \
    python3 -m pip install --no-cache-dir -q "huggingface-hub>=1.24.0,<2"; \
    hf download "${MODEL_REPO}" --revision "${MODEL_REVISION}" --local-dir . ; \
    python3 - <<'EOF'
import os
from huggingface_hub import HfApi
info = HfApi().model_info(os.environ.get("MODEL_REPO", "nvidia/Nemotron-3.5-Parse"),
                          revision=os.environ.get("MODEL_REVISION", "main"))
open(".revision", "w").write(info.sha + "\n")
print("model revision:", info.sha)
EOF

# Pinning vllm to the base image's version prevents pip from swapping it out.
# Newly installed packages may bring their own CA bundle, so re-run the gate.
RUN set -eu; \
    python3 -m pip install --no-cache-dir ".[vllm,client]" "vllm==${VLLM_VERSION}"; \
    python3 -c "import vllm, sys; v = vllm.__version__; print('vllm', v); sys.exit(0 if v.startswith('${VLLM_VERSION}') else 1)"; \
    python3 /opt/security/emudhra/audit_trust.py scan --fix; \
    python3 /opt/security/emudhra/audit_trust.py scan; \
    sha256sum $(find . -type f -name '*.safetensors' | sort) > .weights.sha256; \
    cat .weights.sha256

COPY docker/entrypoint.sh /usr/local/bin/nemotron-entrypoint
RUN chmod +x /usr/local/bin/nemotron-entrypoint

# Runtime is offline: weights are baked in, nothing is fetched at startup.
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    MODEL_DIR=/opt/nemotron-parse

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=300s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)" || exit 1
ENTRYPOINT ["/usr/local/bin/nemotron-entrypoint"]
