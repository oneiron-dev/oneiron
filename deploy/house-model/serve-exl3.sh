#!/usr/bin/env bash
# The house model's generation server: Qwen3.8-27B EXL3 4 bpw with the DFlash2
# draft at depth 7 (owner ruling 2026-10-16), on one GPU. See README.md.
#
# The weights, at the commits the model artifact catalog pins
# (crates/oneiron-server/src/model_artifacts/catalog.rs):
#   target turboderp/Qwen3.8-27B-exl3@113cf7ab958054860e43fb7f3063b1af19171095
#          (the 4.00bpw branch's commit)
#   draft  Mia-AiLab/Qwen3.8-27B-DFlash2-EXL3-5.0bpw@4f0436269bca761b071f05319e8e04a87cc633f9
set -euo pipefail

: "${ONEIRON_HOUSE_EXL3_TARGET:=/var/lib/oneiron-house/models/qwen3.8-27b-exl3-4bpw}"
: "${ONEIRON_HOUSE_EXL3_DRAFT:=/var/lib/oneiron-house/models/qwen3.8-27b-dflash2-exl3-5bpw}"
# The target's weights manifest, written when the weights are deployed
# (weights_manifest.py prepare). The server checks the installed shards
# against it before they load, and its digest is the cache identity's model;
# missing or mismatched, the server serves with no model digest (FIX 7895).
: "${ONEIRON_HOUSE_EXL3_WEIGHTS_MANIFEST:=/var/lib/oneiron-house/models/qwen3.8-27b-exl3-4bpw.weights.json}"
: "${ONEIRON_HOUSE_DRAFT_DEPTH:=7}"
: "${ONEIRON_HOUSE_CONTEXT:=32768}"
# Requests in flight at once (1 to 4): 4; a request that sets `oneiron_solo`
# runs alone. The KV pool they share: unset, the server's own default,
# DEFAULT_CACHE_TOKENS in exl3_server.py, never under one full request.
: "${ONEIRON_HOUSE_EXL3_IN_FLIGHT:=4}"
: "${ONEIRON_HOUSE_EXL3_CACHE_TOKENS:=}"
: "${ONEIRON_HOUSE_EXL3_GPU:=0}"
: "${ONEIRON_HOUSE_EXL3_PORT:=18091}"
: "${ONEIRON_HOUSE_PYTHON:=/opt/oneiron-house/.venv/bin/python}"
# A Unix socket the host's native calls come in on (exl3_ipc.py), beside
# the HTTP routes; unset, none. The supervisor's managed launch passes its
# own; set it here only to reach a hand-started server natively.
: "${ONEIRON_HOUSE_EXL3_NATIVE_SOCKET:=}"

export CUDA_VISIBLE_DEVICES="$ONEIRON_HOUSE_EXL3_GPU"
exec "$ONEIRON_HOUSE_PYTHON" "$(dirname "$0")/exl3_server.py" \
  --target-dir "$ONEIRON_HOUSE_EXL3_TARGET" \
  --weights-manifest "$ONEIRON_HOUSE_EXL3_WEIGHTS_MANIFEST" \
  --draft-dir "$ONEIRON_HOUSE_EXL3_DRAFT" \
  --draft-tokens "$ONEIRON_HOUSE_DRAFT_DEPTH" \
  --context "$ONEIRON_HOUSE_CONTEXT" \
  --max-in-flight "$ONEIRON_HOUSE_EXL3_IN_FLIGHT" \
  ${ONEIRON_HOUSE_EXL3_CACHE_TOKENS:+--cache-tokens "$ONEIRON_HOUSE_EXL3_CACHE_TOKENS"} \
  ${ONEIRON_HOUSE_EXL3_NATIVE_SOCKET:+--native-socket "$ONEIRON_HOUSE_EXL3_NATIVE_SOCKET"} \
  --model-id qwen3.8-27b \
  --host 127.0.0.1 --port "$ONEIRON_HOUSE_EXL3_PORT"
