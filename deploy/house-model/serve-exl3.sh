#!/usr/bin/env bash
# The house model's generation server: Qwen3.8-27B EXL3 4 bpw with the DFlash2
# draft at depth 7 (owner ruling 2026-10-16), on one GPU. See README.md.
set -euo pipefail

: "${ONEIRON_HOUSE_EXL3_TARGET:=/var/lib/oneiron-house/models/qwen3.8-27b-exl3-4bpw}"
: "${ONEIRON_HOUSE_EXL3_DRAFT:=/var/lib/oneiron-house/models/qwen3.8-27b-dflash2-exl3-5bpw}"
: "${ONEIRON_HOUSE_DRAFT_DEPTH:=7}"
: "${ONEIRON_HOUSE_CONTEXT:=32768}"
# Requests in flight at once (1 to 4): 1, one at a time, until E5 and E1 pass
# on INFER-BENCH. The KV pool they share: unset, the server sizes it to one
# full request (the context plus draft and close room, page-rounded).
: "${ONEIRON_HOUSE_EXL3_IN_FLIGHT:=1}"
: "${ONEIRON_HOUSE_EXL3_CACHE_TOKENS:=}"
: "${ONEIRON_HOUSE_EXL3_GPU:=0}"
: "${ONEIRON_HOUSE_EXL3_PORT:=18091}"
: "${ONEIRON_HOUSE_PYTHON:=/opt/oneiron-house/.venv/bin/python}"

export CUDA_VISIBLE_DEVICES="$ONEIRON_HOUSE_EXL3_GPU"
exec "$ONEIRON_HOUSE_PYTHON" "$(dirname "$0")/exl3_server.py" \
  --target-dir "$ONEIRON_HOUSE_EXL3_TARGET" \
  --draft-dir "$ONEIRON_HOUSE_EXL3_DRAFT" \
  --draft-tokens "$ONEIRON_HOUSE_DRAFT_DEPTH" \
  --context "$ONEIRON_HOUSE_CONTEXT" \
  --max-in-flight "$ONEIRON_HOUSE_EXL3_IN_FLIGHT" \
  ${ONEIRON_HOUSE_EXL3_CACHE_TOKENS:+--cache-tokens "$ONEIRON_HOUSE_EXL3_CACHE_TOKENS"} \
  --model-id qwen3.8-27b \
  --host 127.0.0.1 --port "$ONEIRON_HOUSE_EXL3_PORT"
