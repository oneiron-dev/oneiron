#!/usr/bin/env bash
#
# ONE-1441 WIRE-P1 — the shared local-server fixture.
#
# Builds `oneiron-server`, stands it up against a throwaway vault, and prints
# two deterministic machine-readable lines:
#
#     ONEIRON_WIRE_URL=<base url>
#     ONEIRON_WIRE_KEY=<v2.cred.<slip hex>.<seed hex> credential>
#
# The key is a paired credential: the owner creates a link with
# `oneiron-server token pair`, and the SDK's `pair` redeems it with a fresh
# connection key. The client sends the slip after `Authorization: Bearer ` and
# signs every request with that key; it never reads the slip's claims. Nothing
# here prints a production credential: the auth secret is generated per run
# and dies with the temporary directory.
#
# ONE-1543 stage 6 consumes the same two lines in this same grammar, which is
# why the format is pinned rather than convenient.
#
# Ordering is load-bearing. The owner actor is provisioned on a PRE-SERVER
# vault by a one-shot embedded open, and that process must EXIT before the
# server starts: one process owns a vault directory's write side at a time, and
# the fixture gets no exemption from its own single-writer rule.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/oneiron-wire-XXXXXX")"
VAULT_DIR="$WORK_DIR/vault"
SERVER_LOG="$WORK_DIR/server.log"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

log() { printf '[wire-test-server] %s\n' "$*" >&2; }

# A per-run secret. It is the host root every paired slip is verified against,
# so the owner command that creates links must present the one the server was
# started with, and it must not outlive the fixture.
AUTH_SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# An ephemeral port chosen by the kernel, so parallel fixtures do not collide.
PORT="${ONEIRON_WIRE_PORT:-$(python3 -c '
import socket
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
')}"
BASE_URL="http://127.0.0.1:${PORT}"

log "building oneiron-server and the fixture provisioner"
cargo build --locked --quiet -p oneiron-server --bin oneiron-server
cargo build --locked --quiet -p oneiron-remote --example provision-fixture-actor

SERVER_BIN="$(cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/oneiron-server"
PROVISION_BIN="$(dirname "$SERVER_BIN")/examples/provision-fixture-actor"

mkdir -p "$VAULT_DIR"

# Construction-time ownership binds the first human actor with no verifier
# chain (OF-452 D10). The one-shot exits, releasing the writer lease, before
# the server is allowed anywhere near the directory.
log "provisioning the owner actor on the pre-server vault"
PRINCIPAL_REF="$("$PROVISION_BIN" "$VAULT_DIR")"
if [[ ! "$PRINCIPAL_REF" =~ ^[0-9a-f]{32}$ ]]; then
  log "provisioner did not print a 32-hex actor id: ${PRINCIPAL_REF}"
  exit 1
fi

# Match the explicit OpenOptions dimensions in provision-fixture-actor.rs.
# HNSW dimensions are persisted at creation; the server default is different.
log "starting oneiron-server on ${BASE_URL}"
"$SERVER_BIN" serve \
  --vault-path "$VAULT_DIR" \
  --dimensions 1024 \
  --host 127.0.0.1 \
  --port "$PORT" \
  --auth-secret "$AUTH_SECRET" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Readiness is "the facade router answers", not "the port accepts". An
# unauthenticated POST must reach the auth extractor and be refused, which
# proves the nest is mounted — a plain TCP probe would succeed while the router
# was still assembling.
log "waiting for the facade projection"
READY=0
for _ in $(seq 1 300); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    log "server exited during startup; log follows"
    cat "$SERVER_LOG" >&2
    exit 1
  fi
  STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -d '{}' \
    "${BASE_URL}/v1/core/facade/receipts" 2>/dev/null || true)"
  if [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
    READY=1
    break
  fi
  sleep 0.2
done
if [[ "$READY" != "1" ]]; then
  log "server never became ready; log follows"
  cat "$SERVER_LOG" >&2
  exit 1
fi

# Paired through the server's OWN owner command and the SDK's OWN pair, so the
# fixture proves the path a real owner and developer take rather than
# hand-building a credential the server might not accept. `token pair` opens no
# vault; it asks the running server for the link.
link() {
  ONEIRON_SECRET="$AUTH_SECRET" "$SERVER_BIN" token pair --url "$BASE_URL" "$@"
}
pair() {
  "$PROVISION_BIN" pair "$1"
}

log "pairing the test credential"
KEY="$(pair "$(link --scope core:read,core:write \
  --principal-ref "$PRINCIPAL_REF" --actor-class human)" | tr -d '\r\n')"

if [[ "$KEY" != v2.cred.* ]]; then
  log "pairing did not produce a v2 credential"
  exit 1
fi

printf 'ONEIRON_WIRE_URL=%s\n' "$BASE_URL"
printf 'ONEIRON_WIRE_KEY=%s\n' "$KEY"

# The caller drives the tests; this process stays alive so the server does,
# and the EXIT trap tears both down together.
if [[ -n "${ONEIRON_WIRE_EXEC:-}" ]]; then
  # Negative-authority fixtures use the same real pairing path. They are only
  # passed to the child; the two public stdout lines above stay unchanged.
  # The links are unredeemed: the child's SDKs pair them, and a stranger link
  # names a principal that is no vault entity, so its pair is refused.
  NO_CLASS_KEY="$(pair "$(link --scope core:read,core:write \
    --principal-ref "$PRINCIPAL_REF")")"
  READ_KEY="$(pair "$(link --scope core:read \
    --principal-ref "$PRINCIPAL_REF" --actor-class human)")"
  owner_link() {
    link --scope core:read,core:write --principal-ref "$PRINCIPAL_REF" --actor-class human
  }
  PAIR_LINK="$(owner_link)"
  NODE_PAIR_LINK="$(owner_link)"
  README_NODE_LINK="$(owner_link)"
  README_PYTHON_LINK="$(owner_link)"
  STRANGER_REF="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  STRANGER_LINK="$(link --scope core:read,core:write \
    --principal-ref "$STRANGER_REF" --actor-class human)"
  log "running: ${ONEIRON_WIRE_EXEC}"
  ONEIRON_WIRE_URL="$BASE_URL" ONEIRON_WIRE_KEY="$KEY" \
    ONEIRON_WIRE_NO_CLASS_KEY="$NO_CLASS_KEY" \
    ONEIRON_WIRE_READ_KEY="$READ_KEY" \
    ONEIRON_WIRE_PAIR_LINK="$PAIR_LINK" \
    ONEIRON_WIRE_NODE_PAIR_LINK="$NODE_PAIR_LINK" \
    ONEIRON_WIRE_STRANGER_LINK="$STRANGER_LINK" \
    ONEIRON_WIRE_README_NODE_LINK="$README_NODE_LINK" \
    ONEIRON_WIRE_README_PYTHON_LINK="$README_PYTHON_LINK" \
    bash -c "$ONEIRON_WIRE_EXEC"
else
  wait "$SERVER_PID"
fi
