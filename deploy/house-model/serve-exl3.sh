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
# runs alone. The KV pool they share: unset, the server's own default
# (DEFAULT_CACHE_TOKENS beside the draft KV ring, DEFAULT_CACHE_TOKENS_WITHOUT_RING
# without one, in exl3_server.py), never under one full request.
: "${ONEIRON_HOUSE_EXL3_IN_FLIGHT:=4}"
: "${ONEIRON_HOUSE_EXL3_CACHE_TOKENS:=}"
# The DFlash2 draft's KV as a ring of this many pages per in-flight slot, in
# place of a full-pool copy (README, "The draft KV ring"): unset, the server's
# DEFAULT_DRAFT_RING_PAGES; 0 turns it off (with the pool unset, stock).
: "${ONEIRON_HOUSE_EXL3_DRAFT_RING_PAGES:=}"
# The speed parts (README, "Speed parts"): 1 turns a part on, 0 off; unset,
# the server's SPEED_PART_DEFAULTS.
speed_parts=()
for part in FUSE_PROJECTIONS FP16_PREFILL PROMPT_LOOKUP DRAFT_WINDOW_TABLES; do
  var="ONEIRON_HOUSE_EXL3_$part"
  flag=$(printf '%s' "$part" | tr 'A-Z_' 'a-z-')
  case "${!var:-}" in
    "") ;;
    1) speed_parts+=("--$flag") ;;
    0) speed_parts+=("--no-$flag") ;;
    *) echo "serve-exl3.sh: $var must be 0, 1 or unset, not '${!var}'" >&2; exit 2 ;;
  esac
done
# A rebuilt exllamav3 extension (README, "GEMM FP16 accumulators"): the
# directory build-exl3-ext.sh wrote; unset, the extension installed with
# exllamav3. It is resolved here, before anything imports it, and the
# resolved directory goes first on PYTHONPATH and to the server, which
# checks that the extension it loaded came from it and digests that file:
# a link switched after the launch changes neither.
: "${ONEIRON_HOUSE_EXL3_EXT_DIR:=}"
if [ -n "$ONEIRON_HOUSE_EXL3_EXT_DIR" ]; then
  if ! resolved=$(CDPATH= cd -P -- "$ONEIRON_HOUSE_EXL3_EXT_DIR" 2>/dev/null && pwd -P); then
    echo "serve-exl3.sh: $ONEIRON_HOUSE_EXL3_EXT_DIR is no directory (build-exl3-ext.sh writes one)" >&2
    exit 2
  fi
  ONEIRON_HOUSE_EXL3_EXT_DIR=$resolved
  if ! compgen -G "$ONEIRON_HOUSE_EXL3_EXT_DIR/exllamav3_ext*.so" >/dev/null; then
    echo "serve-exl3.sh: $ONEIRON_HOUSE_EXL3_EXT_DIR holds no exllamav3_ext module (build-exl3-ext.sh writes one)" >&2
    exit 2
  fi
  export PYTHONPATH="$ONEIRON_HOUSE_EXL3_EXT_DIR${PYTHONPATH:+:$PYTHONPATH}"
fi
# The key of the digest of the inherited EXL3_* variables (README,
# "exllamav3's own variables"): a file of at least 32 random bytes that the
# workers exchanging session snapshots share; unset, a key of the process's
# own.
: "${ONEIRON_HOUSE_EXL3_ENV_KEY_FILE:=}"
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
  ${ONEIRON_HOUSE_EXL3_DRAFT_RING_PAGES:+--draft-ring-pages "$ONEIRON_HOUSE_EXL3_DRAFT_RING_PAGES"} \
  ${speed_parts[@]+"${speed_parts[@]}"} \
  ${ONEIRON_HOUSE_EXL3_EXT_DIR:+--exllamav3-ext-dir "$ONEIRON_HOUSE_EXL3_EXT_DIR"} \
  ${ONEIRON_HOUSE_EXL3_ENV_KEY_FILE:+--exllamav3-env-key-file "$ONEIRON_HOUSE_EXL3_ENV_KEY_FILE"} \
  ${ONEIRON_HOUSE_EXL3_NATIVE_SOCKET:+--native-socket "$ONEIRON_HOUSE_EXL3_NATIVE_SOCKET"} \
  --model-id qwen3.8-27b \
  --host 127.0.0.1 --port "$ONEIRON_HOUSE_EXL3_PORT"
