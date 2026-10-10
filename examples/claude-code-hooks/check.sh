#!/usr/bin/env bash
# The Claude Code hooks, end to end, on invented data (docs/ops/claude-code-hooks.md):
# Claude Code-shaped events on stdin against a throwaway served vault.
#
#   examples/claude-code-hooks/check.sh /path/to/oneiron
#
# 1. A Stop hook fires while the vault is down: the session waits in the queue.
# 2. serve starts and imports it.
# 3. A SessionStart hook in the same project recalls what the session said.
set -euo pipefail

ONEIRON=${1:?usage: check.sh /path/to/oneiron}
HOOK="$(cd "$(dirname "$0")" && pwd)/oneiron_hook.py"
T=$(mktemp -d)
SERVE=
cleanup() {
  [ -n "$SERVE" ] && kill "$SERVE" 2>/dev/null && wait "$SERVE" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT
export ONEIRON_AUTH_SECRET=claude-code-hooks-check-secret-0001
unset ONEIRON_VAULT_PATH ONEIRON_URL ONEIRON_SECRET ONEIRON_BINDING_KEY
CONFIG=$T/oneiron.toml
PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')

"$ONEIRON" init "$T/vault" --config "$CONFIG" --embedder none >/dev/null
cat >>"$CONFIG" <<EOF
[import]
queue = true
queue_dir = "$T/queue"
claude_code_root = "$T/projects"
EOF
"$ONEIRON" token agent --name claude-code-hooks --tier read-only \
  --out "$T/claude-code-hooks.cred" --config "$CONFIG" >/dev/null

# An invented session in Claude Code's own log layout.
SESSION=0b5e55e0-1111-4222-8333-944455556666
LOG=$T/projects/-tmp-heron-lantern/$SESSION.jsonl
mkdir -p "$(dirname "$LOG")"
python3 -I - "$LOG" "$SESSION" <<'EOF'
import json, sys

log, session = sys.argv[1], sys.argv[2]


def line(role, uuid, parent, at, text):
    if role == "user":
        message = {"role": "user", "content": text}
    else:
        message = {"id": "msg_" + uuid[-4:], "type": "message", "role": "assistant",
                   "model": "claude-test", "content": [{"type": "text", "text": text}]}
    return {"parentUuid": parent, "isSidechain": False, "userType": "external",
            "cwd": "/tmp/heron-lantern", "sessionId": session, "version": "2.1.0",
            "type": role, "uuid": uuid, "timestamp": at, "message": message}


first, second = "d1000000-0000-4000-8000-000000000001", "d1000000-0000-4000-8000-000000000002"
rows = [
    line("user", first, None, "2026-10-10T01:00:00.000Z",
         "For the heron lantern project, keep the ferry timetable in pier nine order."),
    line("assistant", second, first, "2026-10-10T01:00:05.000Z",
         "Noted: the heron lantern timetable stays in pier nine order."),
]
with open(log, "w") as out:
    out.writelines(json.dumps(row) + "\n" for row in rows)
EOF

event() { python3 -I -c 'import json, sys; print(json.dumps(dict(zip(sys.argv[1::2], sys.argv[2::2]))))' "$@"; }

echo "1. Stop while the vault is down"
event hook_event_name Stop session_id "$SESSION" transcript_path "$LOG" cwd /tmp/heron-lantern \
  stop_hook_active false |
  python3 -I "$HOOK" hand-over --oneiron "$ONEIRON" --config "$CONFIG"
ls "$T/queue"
[ "$(ls "$T/queue" | wc -l)" -eq 1 ] || { echo "FAIL: nothing queued"; exit 1; }

echo "2. serve starts and imports the queued session"
"$ONEIRON" serve --config "$CONFIG" --host 127.0.0.1 --port "$PORT" 2>"$T/serve.log" &
SERVE=$!
for _ in $(seq 1 240); do
  [ -z "$(ls -A "$T/queue")" ] && break
  sleep 0.5
done
[ -z "$(ls -A "$T/queue")" ] || { echo "FAIL: the queue was not drained"; tail -20 "$T/serve.log"; exit 1; }
grep -o 'queued import landed.*' "$T/serve.log" | head -1 || true

echo "3. A new session in the same project starts"
OUT=$(event hook_event_name SessionStart session_id 0b5e55e0-2222-4333-8444-a55566667777 \
  source startup cwd /tmp/heron-lantern transcript_path /dev/null |
  python3 -I "$HOOK" session-start --oneiron "$ONEIRON" --url "http://127.0.0.1:$PORT" \
    --credential-file "$T/claude-code-hooks.cred")
echo "$OUT"
grep -q 'pier nine order' <<<"$OUT" || { echo "FAIL: the session was not recalled"; exit 1; }
echo "CHECK OK"
