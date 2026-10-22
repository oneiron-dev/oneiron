#!/usr/bin/env bash
# The house model's second server: llama.cpp `llama-server` on the same 27B as
# Q4_K_M, on the other GPU. It is the generation fallback rung and the
# local_reasoner the decision read reaches on llama.cpp's native API
# (/tokenize, /completion). See README.md.
#
# Each launch names itself (FIX 7895): llama_identity.py hashes what this
# launch loads, writes its identity manifest into the manifests-only
# ONEIRON_HOUSE_LLAMA_IDENTITY_DIR, and hands back `--alias
# oneiron-llama/<epoch>/<digest> --path <dir> --ui`, so every answer names the
# launch that gave it. If that fails for any reason, llama-server starts as
# it would without it: no alias, no manifest, and a warning on stderr.
#
# The weights, at the commits the model artifact catalog pins
# (crates/oneiron-server/src/model_artifacts/catalog.rs):
#   target unsloth/Qwen3.8-27B-GGUF@4ca720788d1e01f1bff70c033e0d0028fd02e502
#          Qwen3.8-27B-UD-Q4_K_M.gguf
#   draft  unsloth/Qwen3.5-0.8B-GGUF@6ab461498e2023f6e3c1baea90a8f0fe38ab64d0
#          Qwen3.5-0.8B-Q8_0.gguf
set -euo pipefail

: "${ONEIRON_HOUSE_LLAMA_SERVER:=/opt/oneiron-house/llama.cpp/build/bin/llama-server}"
: "${ONEIRON_HOUSE_LLAMA_TARGET:=/var/lib/oneiron-house/models/Qwen3.8-27B-UD-Q4_K_M.gguf}"
: "${ONEIRON_HOUSE_LLAMA_DRAFT:=/var/lib/oneiron-house/models/Qwen3.5-0.8B-Q8_0.gguf}"
: "${ONEIRON_HOUSE_LLAMA_DRAFT_MAX:=8}"
: "${ONEIRON_HOUSE_CONTEXT:=32768}"
: "${ONEIRON_HOUSE_LLAMA_SLOTS:=2}"
: "${ONEIRON_HOUSE_LLAMA_GPU:=1}"
: "${ONEIRON_HOUSE_LLAMA_PORT:=18134}"
# The configured wire id of the provider this server answers as (models.toml);
# a launch's manifest is bound to it.
: "${ONEIRON_HOUSE_LLAMA_MODEL_ID:=qwen3.8-27b}"
: "${ONEIRON_HOUSE_LLAMA_IDENTITY_DIR:=/var/cache/oneiron-house/llama-identity}"
: "${ONEIRON_HOUSE_PYTHON:=/opt/oneiron-house/.venv/bin/python}"

export CUDA_VISIBLE_DEVICES="$ONEIRON_HOUSE_LLAMA_GPU"
# Each slot gets the full context: llama-server splits --ctx-size across slots.
args=(
  --model "$ONEIRON_HOUSE_LLAMA_TARGET"
  --model-draft "$ONEIRON_HOUSE_LLAMA_DRAFT"
  --spec-type draft-simple --spec-draft-n-max "$ONEIRON_HOUSE_LLAMA_DRAFT_MAX"
  --ctx-size "$((ONEIRON_HOUSE_CONTEXT * ONEIRON_HOUSE_LLAMA_SLOTS))"
  --parallel "$ONEIRON_HOUSE_LLAMA_SLOTS"
  --n-gpu-layers 999 --gpu-layers-draft 999
  --flash-attn on
  --jinja --reasoning-format deepseek
  --host 127.0.0.1 --port "$ONEIRON_HOUSE_LLAMA_PORT"
)

identity=()
if prepared=$("$ONEIRON_HOUSE_PYTHON" "$(dirname "$0")/llama_identity.py" prepare \
      --server "$ONEIRON_HOUSE_LLAMA_SERVER" \
      --manifest-dir "$ONEIRON_HOUSE_LLAMA_IDENTITY_DIR" \
      --configured-wire-id "$ONEIRON_HOUSE_LLAMA_MODEL_ID" \
      -- "${args[@]}") && [ -n "$prepared" ]; then
  mapfile -t identity <<<"$prepared"
  # The launch alias is the server's one alias.
  unset LLAMA_ARG_ALIAS
else
  echo "serve-llama.sh: WARN no launch identity; llama-server starts without an alias or manifest" >&2
fi

exec "$ONEIRON_HOUSE_LLAMA_SERVER" "${args[@]}" ${identity[@]+"${identity[@]}"}
