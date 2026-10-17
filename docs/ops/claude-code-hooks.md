# Claude Code hooks: your vault in every session

Four Claude Code hooks connect a session to your vault, and a fifth is there
if you want it. You make no calls by hand:

| Claude Code event | Hook | What happens |
|---|---|---|
| `SessionStart` (start, resume, `/clear`, after a compaction) | `session-start` | The session binds a vault and is told which in one line; then a short recall for the project. Claude Code adds both to the session's context. |
| `UserPromptSubmit` (only if you add it) | `prompt` | A short recall for what you just asked, from the bound vault. |
| `PreCompact` | `hand-over` | The session's log is queued for import before compaction drops it from context. |
| `Stop` (each time Claude finishes a reply) | `hand-over` | The log is queued again; the import lands only what is new. |
| `SessionEnd` | `hand-over` | A last queue, for a session that ended mid-reply. |

The hooks sit beside the MCP tools ([Connect an agent](connect-an-agent.md)). The
tools are for what Claude decides to look up or save. The hooks run every time,
without Claude asking.

The hooks are part of the `oneiron` binary: `oneiron hook --host claude-code
<event>`. [`examples/claude-code-hooks/`](../../examples/claude-code-hooks/)
holds `settings.json` (the snippet to merge) and `check.sh` (the end-to-end
check).

## How it works

```
Claude Code ──SessionStart──▶ oneiron hook session-start ──▶ bind a vault (below)
                                                       ──▶ oneiron mcp ──▶ serve: vault.recall
            ◀── stdout: the vault's line and the recalled lines, added to context

Claude Code ──Stop/PreCompact/SessionEnd──▶ oneiron hook hand-over
            ──▶ oneiron import claude-code <log> --queue   (writes one small file)
                                   serve, every 5 s ──▶ imports the queued log
```

- **Recall** goes through `oneiron mcp` with the hooks' own read-only
  credential. By default it calls `vault.recall` at the `light` effort: no model
  call and no embedding, so it is fast and costs nothing. `--effort medium`
  embeds the query on the server's embedder, so a session finds what it
  worked on in other words; `high`, `xhigh` and `max` also rerank on the
  reranker the server's `[models]` routes, under the server's own budget
  (see [run-with-models.md](run-with-models.md#8-the-reranker)). A server that
  does not list `vault.recall` gets the lexical `memory.query` instead (on the
  one-space preset it also embeds the query through the text slot's declared
  space, as `POST /v1/core/query` does). The query is
  the project's name: the git repository's folder name, or the working
  directory's.
- **Write-back** needs no credential. `--queue` leaves one file that names the
  session's log in the vault's import queue. A running `serve` imports it
  within seconds. It is the same import as `oneiron import claude-code` with the
  vault stopped: the import ledger lands each message once, so the next
  `Stop` adds only the new messages. A Claude Code session brings its subagent
  logs (`<session>/subagents/`) with it.
- **Nothing blocks.** Each hook exits 0 when the vault is down, slow or
  refuses. `session-start` still prints its one line, which then says no
  vault answered; nothing else is printed. A session queued while `serve` is
  down waits in the queue and lands when `serve` starts. A mistyped hook command exits 1, which
  Claude Code shows as a hook error and then goes on. No hook ever exits 2, so
  none can block a compaction or keep a reply from ending.
- **No hook reads or prints a credential.** `oneiron mcp` reads the credential
  file itself.

## Which vault a session uses

`session-start` binds the first of these, then prints one line naming it
(ARCH-0028 `#plugin-first-run`):

1. **A pin.** The hook's `--url`, else `ONEIRON_URL`, else `url` in
   `hook.toml` in your oneiron config folder (`$XDG_CONFIG_HOME/oneiron/`,
   else `~/.config/oneiron/`, the folder of the default `oneiron.toml`):

   ```toml
   url = "http://127.0.0.1:9090"
   ```

   A pinned vault that does not answer is not swapped for another; the line
   says so.
2. **A running local vault.** Every `serve` registers itself (below). The
   hook asks each with `GET /.well-known/oneiron`, which needs no credential,
   and binds the one that answers. When several answer it binds the newest,
   says so, and prints the one command that pins it.
3. **The hosted vault, when you are logged into the cloud.** Not built yet:
   `oneiron connect` brings the login. The hook passes over this step.
4. **A local server it starts.** The hook runs `oneiron serve --host
   127.0.0.1` with the config every command reads when none is named
   (`ONEIRON_CONFIG`, else the default `oneiron.toml`), in a process of its
   own that keeps running after the session. It logs to `serve.log` in the
   run folder. If that server answers within the hook's `--timeout`, the
   session binds it; if not, the next session finds it. When another
   session's server, still starting, already holds the vault, this one's
   `serve` cannot open it and exits; the session then looks again for a
   running vault and binds the newest that answers, within the same
   `--timeout`. With no config there is no
   vault to start: the line says to set one up with `oneiron init`.

`prompt` binds the same way but never starts a server and prints no line of
its own. A pinned vault that does not answer one probe gets no recall, so a
vault that is down costs a prompt at most 2 seconds. `hand-over` queues into the queue of `--config` if you give it;
else, with a pin, of the running local vault at the pin; with no pin, of the
newest running local vault; else of the default config. A pin is never
swapped for another vault.

A pin in `hook.toml` counts only when no one but you can write it: your own
regular file, not a link, with no write bit for others and, on macOS, no ACL
entry. A runtime file counts only on the same terms. The session sends its
credential where they point.

Starting a server never creates a vault: the hook starts one only when the
config's `vault_path` holds an initialized vault.

`oneiron hook --host hermes bind [--url <origin>]` binds in the same order and
prints the result as one JSON line, `{"url": <origin or null>, "lines": [...]}`.
Hermes's memory provider (`packages/oneiron-hermes`) runs inside Hermes's own
process and asks there, so the order has one home.

### Runtime files

Each `serve` writes one file once its listener is bound and it is ready, and
removes it when it stops cleanly. The file is JSON: the vault id (`null`
until the vault is rooted), the `url` a client on this host reaches it at,
its `pid`, its vault folder (`state_dir`), the config it read and when it
started. The folder is:

- `$XDG_RUNTIME_DIR/oneiron/` where the platform has a runtime folder
  (Linux);
- else `run/` in your oneiron config folder, for example
  `~/.config/oneiron/run/` on macOS.

Never the repository, never a vault folder. The folder is created readable
and writable by you alone (0700) and each file by you alone (0600). A hook
reads neither a folder another user owns or can write, nor a file that is a
link or another user's. A file whose process is gone (a `serve` that was
killed), or whose pid is now another user's process, is stale: the next hook
removes it. A file whose process lives but
whose server does not answer is passed over and kept, since that server may
still be starting.

A `serve` from before runtime files registers nothing; restart it once.

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

- `/path/to/oneiron`: the `oneiron` binary. Hooks run with Claude Code's
  `PATH`, which may not include it.
- `/path/to/claude-code-hooks.cred`: the file from step 2.

The hooks find the vault themselves ([above](#which-vault-a-session-uses)).
Add `--url <origin>` to `session-start` to pin one there instead, and
`--config /path/to/oneiron.toml` to `hand-over` when `serve` reads a config
other than the default and may be stopped when a session ends.

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "timeout": 15,
        "command": "/path/to/oneiron hook --host claude-code session-start --credential-file /path/to/claude-code-hooks.cred" } ] }
    ],
    "PreCompact": [
      { "hooks": [ { "type": "command", "timeout": 10,
        "command": "/path/to/oneiron hook --host claude-code hand-over" } ] }
    ],
    "Stop": [
      { "hooks": [ { "type": "command", "timeout": 10,
        "command": "/path/to/oneiron hook --host claude-code hand-over" } ] }
    ],
    "SessionEnd": [
      { "hooks": [ { "type": "command", "timeout": 5,
        "command": "/path/to/oneiron hook --host claude-code hand-over --timeout 4" } ] }
    ]
  }
}
```

Start a new Claude Code session in a project the vault knows. Its context
opens with the line naming the vault, then the recalled lines under "From
your Oneiron vault".

To recall for each prompt as well, add a `UserPromptSubmit` entry running
`/path/to/oneiron hook --host claude-code prompt --credential-file
/path/to/claude-code-hooks.cred`. It recalls at the `light` effort unless
you set `--effort`, and prints nothing when it finds nothing.

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
  ARCH-0040). Each queue pass that lands something is one import: `serve`
  queues the Dreamer over it and logs its review id
  (`import:claude-code:<time>`). `oneiron runs pending` lists the reviews, and
  `oneiron runs show|approve|decline` resolves each whole
  ([Import your history](import-history.md#claims)). Queue entries waiting for
  a stopped `serve` land when it starts.

## Limits and timings

- `session-start` gives up after 8 seconds (`--timeout`), binding included,
  and prints at most 8 hits (`--limit`), each up to 400 characters, about
  6,000 characters in all, after its one line. Each probe of a vault waits
  at most 2 seconds. `prompt` has the same limits. Claude Code caps a hook's
  added context at 10,000 characters.
- `hand-over` takes well under a second: it writes one small file. Claude
  Code gives `SessionEnd` hooks 1.5 seconds unless a hook sets its own
  `timeout`; the `timeout` of 5 above raises that budget to 5 seconds.
- `serve` looks at the queue every 5 seconds and imports what waits there.
  One session log is read up to 1 GiB, the same limit as `oneiron import`.
  A larger one, the session's or a subagent's, is left out with a
  `log_too_large` warning in `serve`'s log, and the rest of the session
  lands.
- `--query "<words>"` on `session-start` recalls those words instead of the
  project's name (on `prompt`, instead of the prompt).
- `--effort <light|medium|high|xhigh|max>` on `session-start` picks recall's
  effort; it stays `light` unless you set it. Above light the server embeds
  the query first, and a model that is still loading leaves recall on its
  lexical signals (the result says `sparse: true`). Give such a hook a
  `--timeout` its server's embedder and reranker can meet; a hook that runs
  out of time prints nothing and the session goes on.

Hook events, their input fields, stdout handling and timeouts:
[Claude Code hooks reference](https://code.claude.com/docs/en/hooks).

## Check it

`examples/claude-code-hooks/check.sh /path/to/oneiron` runs the whole loop on
invented data in a temporary folder. A `Stop` event arrives while the vault is
down, and the session waits in the queue. Then `serve` starts and imports it.
Last, a `SessionStart` event in the same project binds that `serve` by its
runtime file and prints a line from that session. It never touches your own
sessions, vault, runtime files or pin.
