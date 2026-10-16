#!/usr/bin/env bash
# The house model's second server: llama.cpp `llama-server` on the same 27B as
# Q4_K_M, on the other GPU. It is the generation fallback rung and the
# local_reasoner the decision read reaches on llama.cpp's native API
# (/tokenize, /completion). See README.md.
set -euo pipefail

: "${ONEIRON_HOUSE_LLAMA_SERVER:=/opt/oneiron-house/llama.cpp/build/bin/llama-server}"
: "${ONEIRON_HOUSE_LLAMA_TARGET:=/var/lib/oneiron-house/models/Qwen3.8-27B-UD-Q4_K_M.gguf}"
: "${ONEIRON_HOUSE_LLAMA_DRAFT:=/var/lib/oneiron-house/models/Qwen3.5-0.8B-Q8_0.gguf}"
: "${ONEIRON_HOUSE_LLAMA_DRAFT_MAX:=8}"
: "${ONEIRON_HOUSE_CONTEXT:=32768}"
: "${ONEIRON_HOUSE_LLAMA_SLOTS:=2}"
: "${ONEIRON_HOUSE_LLAMA_GPU:=1}"
: "${ONEIRON_HOUSE_LLAMA_PORT:=18134}"

export CUDA_VISIBLE_DEVICES="$ONEIRON_HOUSE_LLAMA_GPU"
# Each slot gets the full context: llama-server splits --ctx-size across slots.
exec "$ONEIRON_HOUSE_LLAMA_SERVER" \
  --model "$ONEIRON_HOUSE_LLAMA_TARGET" \
  --model-draft "$ONEIRON_HOUSE_LLAMA_DRAFT" \
  --spec-type draft-simple --spec-draft-n-max "$ONEIRON_HOUSE_LLAMA_DRAFT_MAX" \
  --ctx-size "$((ONEIRON_HOUSE_CONTEXT * ONEIRON_HOUSE_LLAMA_SLOTS))" \
  --parallel "$ONEIRON_HOUSE_LLAMA_SLOTS" \
  --n-gpu-layers 999 --gpu-layers-draft 999 \
  --flash-attn on \
  --jinja --reasoning-format deepseek \
  --host 127.0.0.1 --port "$ONEIRON_HOUSE_LLAMA_PORT"
