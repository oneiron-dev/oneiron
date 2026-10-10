# Claude Code hooks: your vault in every session

Four Claude Code hooks connect a session to your running vault. You make no
calls by hand:

| Claude Code event | Hook | What happens |
|---|---|---|
| `SessionStart` (start, resume, `/clear`, after a compaction) | `session-start` | A short recall for the project. Claude Code adds it to the session's context. |
| `PreCompact` | `hand-over` | The session's log is queued for import before compaction drops it from context. |
| `Stop` (each time Claude finishes a reply) | `hand-over` | The log is queued again; the import lands only what is new. |
| `SessionEnd` | `hand-over` | A last queue, for a session that ended mid-reply. |

The hooks sit beside the MCP tools ([Connect an agent](connect-an-agent.md)). The
tools are for what Claude decides to look up or save. The hooks run every time,
without Claude asking.

The scripts are in [`examples/claude-code-hooks/`](../../examples/claude-code-hooks/):
`oneiron_hook.py` (Python 3.9+, standard library only), `settings.json` (the
snippet to merge) and `check.sh` (the end-to-end check).

## How it works

```
Claude Code ──SessionStart──▶ oneiron_hook.py session-start ──▶ oneiron mcp ──▶ serve: recall
            ◀── stdout: the recalled lines, added to context

Claude Code ──Stop/PreCompact/SessionEnd──▶ oneiron_hook.py hand-over
            ──▶ oneiron import claude-code <log> --queue   (writes one small file)
                                   serve, every 5 s ──▶ imports the queued log
```

- **Recall** goes through `oneiron mcp` with the hooks' own read-only
  credential. It calls `recall` at the `light` effort: no model call and no
  embedding, so it is fast and costs nothing. A server that does not list
  `recall` gets the lexical `memory.query` instead. The query is the project's
  name: the git repository's folder name, or the working directory's.
- **Write-back** needs no credential. `--queue` leaves one file that names the
  session's log in the vault's import queue. A running `serve` imports it
  within seconds. It is the same import as `oneiron import claude-code` with the
  vault stopped: the import ledger lands each message once, so the next
  `Stop` adds only the new messages. A Claude Code session brings its subagent
  logs (`<session>/subagents/`) with it.
- **Nothing blocks.** Each hook prints nothing and exits 0 when the vault is
  down, slow or refuses. A session queued while `serve` is down waits in the
  queue and lands when `serve` starts. A mistyped hook command exits 1, which
  Claude Code shows as a hook error and then goes on. No hook ever exits 2, so
  none can block a compaction or keep a reply from ending.
- **No hook reads or prints a credential.** `oneiron mcp` reads the credential
  file itself.

## 1. Turn on the import queue

In the config `serve` reads, then restart `serve`:

```toml
[import]
queue = true
# The defaults:
# queue_dir = "<vault path>.import-queue"      beside the vault
# claude_code_root = "~/.claude/projects"     queued Claude Code logs must sit under it
# codex_root = "~/.codex/sessions"            queued Codex rollouts must sit under it
```

`queue = true` is your standing approval: `serve` imports every log queued
under `claude_code_root` as if you had run `oneiron import claude-code` on
it. It reads nothing outside that folder. Every folder below the root is
opened without following a link, so a link under it leads nowhere. The queue
folder is created readable and writable by you alone. `serve` opens it
without following a link and does not read it when another user owns it or
can write it. With the queue on, `queue_dir` and both roots must be absolute
paths (`~/` is expanded). The queue is off by default, and a hosted node never
runs it.

Each pass takes every waiting log and lands them together, earliest first: a
session lands before a resumed copy of it, as in a folder import. A pass holds
up to a million messages; past that, the earliest logs land and the rest wait
for the next pass. A log whose last line was still being written, the
session's or a subagent's, is read again on the next pass, up to three times.
When the vault cannot land a pass (a full disk, say), the logs stay queued and
`serve` tries again, waiting longer each time, up to about five minutes.

You can queue a log by hand too:

```bash
oneiron import claude-code ~/.claude/projects/<project>/<session>.jsonl --queue
```

## 2. Mint the hooks' credential

With `serve` stopped (minting holds the vault's writer lease), using the same
config as `serve`:

```bash
oneiron token agent --name claude-code-hooks --tier read-only \
  --out ~/.config/oneiron/claude-code-hooks.cred
```

The hooks only read, so their credential is read-only and never owner-grade.
It is separate from the `claude-code` credential your MCP server entry uses,
so you can revoke either one alone. Keep the `slip_id` the command prints.
Start `serve` again.

## 3. Merge the settings

Add the four entries in `examples/claude-code-hooks/settings.json` to the
`"hooks"` object of `~/.claude/settings.json` (every project) or of one
project's `.claude/settings.json`. Keep your existing entries. Then replace the
placeholders with full paths. Claude Code does not expand `~` there.

- `/path/to/oneiron_hook.py`: where you keep the script.
- `/path/to/oneiron`: the `oneiron` binary. Hooks run with Claude Code's
  `PATH`, which may not include it.
- `http://127.0.0.1:9090`: the server's origin. Use the `host` and `port` that
  `serve` listens on.
- `/path/to/claude-code-hooks.cred`: the file from step 2.
- `/path/to/oneiron.toml`: the config `serve` reads. The queue's place comes
  from it.

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "timeout": 15,
        "command": "python3 /path/to/oneiron_hook.py session-start --oneiron /path/to/oneiron --url http://127.0.0.1:9090 --credential-file /path/to/claude-code-hooks.cred" } ] }
    ],
    "PreCompact": [
      { "hooks": [ { "type": "command", "timeout": 10,
        "command": "python3 /path/to/oneiron_hook.py hand-over --oneiron /path/to/oneiron --config /path/to/oneiron.toml" } ] }
    ],
    "Stop": [
      { "hooks": [ { "type": "command", "timeout": 10,
        "command": "python3 /path/to/oneiron_hook.py hand-over --oneiron /path/to/oneiron --config /path/to/oneiron.toml" } ] }
    ],
    "SessionEnd": [
      { "hooks": [ { "type": "command", "timeout": 5,
        "command": "python3 /path/to/oneiron_hook.py hand-over --oneiron /path/to/oneiron --timeout 4 --config /path/to/oneiron.toml" } ] }
    ]
  }
}
```

Start a new Claude Code session in a project the vault knows. The recalled
lines appear in its context under "From your Oneiron vault".

### Next to your other hooks

These entries use four events: `SessionStart`, `PreCompact`, `Stop` and
`SessionEnd`. Claude Code merges hook entries across the user, project and
local settings files and runs every matching hook in parallel. So a hook you
already have on another event, for example a `PreToolUse` hook on `Agent` or
`Workflow`, runs exactly as before. If you already have a hook on one of these
four events, add ours as one more entry in that event's list.

## Remove it

1. Delete the four entries from the settings file.
2. Revoke the credential, with `serve` stopped:
   `oneiron token revoke --jti <slip_id>`. Then delete the `.cred` file.
3. Set `queue = false` under `[import]` and restart `serve`. Queued files
   still waiting stay in the queue folder; delete the folder if you like.

What the hooks already imported stays in your vault, like any import.

## What lands, and what waits for you

- Each session lands as an imported conversation, exactly as
  `oneiron import claude-code` lands it ([Import your history](import-history.md)).
  Your words and Claude's replies land. Tool calls, tool results, thinking and
  injected context are counted, not landed. The write door's secret scan
  applies: a turn holding a secret-shaped value is refused, and the next queue
  of that session tries it again.
- Messages are searchable at once, so the next `SessionStart` in that project
  can recall them.
- Claims drawn from imported material never approve themselves (ARCH-0027,
  ARCH-0040). Reviewing them in bulk is the import's open follow-up; until it
  ships, no claim waits on these hooks. Queue entries waiting for a stopped
  `serve` are the only pending items, and `serve` takes them up when it starts.

## Limits and timings

- `session-start` gives up after 8 seconds (`--timeout`) and prints at most 8
  hits (`--limit`), each up to 400 characters, about 6,000 characters in all.
  Claude Code caps a hook's added context at 10,000 characters.
- `hand-over` takes well under a second: it writes one small file. Claude
  Code gives `SessionEnd` hooks 1.5 seconds unless a hook sets its own
  `timeout`; the `timeout` of 5 above raises that budget to 5 seconds.
- `serve` looks at the queue every 5 seconds and imports what waits there.
  One session log is read up to 1 GiB, the same limit as `oneiron import`.
  A larger one, the session's or a subagent's, is left out with a
  `log_too_large` warning in `serve`'s log, and the rest of the session
  lands.
- `--query "<words>"` on `session-start` recalls those words instead of the
  project's name.

Hook events, their input fields, stdout handling and timeouts:
[Claude Code hooks reference](https://code.claude.com/docs/en/hooks).

## Check it

`examples/claude-code-hooks/check.sh /path/to/oneiron` runs the whole loop on
invented data in a temporary folder. A `Stop` event arrives while the vault is
down, and the session waits in the queue. Then `serve` starts and imports it.
Last, a `SessionStart` event in the same project prints a line from that
session. It never touches your own sessions or vault.
