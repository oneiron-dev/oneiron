# Claude Code hooks: your vault in every session

Six Claude Code hooks connect a session to your vault, and another is there
if you want it. You make no calls by hand:

| Claude Code event | Hook | What happens |
|---|---|---|
| `SessionStart` (start, resume, `/clear`, after a compaction) | `session-start` | The session binds a vault and is told which in one line. Claude Code adds it to the session's context. Given the task's words (`--query "<words>"`), it is also given the lines that clear your relevance bar, at most 3; keyed on nothing but the folder, it recalls nothing. The plugin and the snippet below pass `--query " "` ([How it works](#how-it-works)). |
| `UserPromptSubmit` (only if you add it) | `prompt` | The lines for what you just asked that clear your relevance bar, at most 3, from the bound vault. |
| `PostToolUse` | `tool-result` | After a non-Oneiron tool result, Claude Code gets at most one new line from the vault. To a vault that is not on this machine, the recall's query holds only the tool's name and, for Claude Code's own file tools (`Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`), the file's base name: never the command, another tool's path, other input text or the tool's output. The request also carries the session id and digests of the session folder's path (no raw path or label), as every hook recall does. On this machine the full query goes only after the vault answers the credential's own vault id. |
| `SessionStart` (after a compaction) | `focus-refresh` | If this session already had a board, Claude Code gets it back. It asks only the origin a running Oneiron MCP server recorded for the same credential file after the vault first admitted it, with that credential, and only when that vault answers the credential's own vault id; with no such record, running servers that recorded different origins, or a `--url` naming another origin, it asks nothing. A board longer than Claude Code lets a hook add is not cut: the hook says to call `self.focus.refresh` instead. |
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

The Oneiron plugin for Claude Code
([`plugins/claude-code/`](../../plugins/claude-code/)) carries these six
hooks, the MCP server entry and a skill that tells Claude when to recall and
save. Install it in Claude Code with `/plugin marketplace add
oneiron-dev/oneiron`, then `/plugin install oneiron@oneiron`. The plugin mints
nothing and runs `oneiron` from Claude Code's `PATH`: do steps 1 and 2 below,
minting the hooks' credential to `~/.config/oneiron/claude-code-hooks.cred`,
the path the plugin reads, and skip step 3. Remove it with `/plugin uninstall
oneiron@oneiron` in place of step 1 of [Remove it](#remove-it).

## How it works

The plugin's `--carrier-in-content` bridge flag lets board updates ride
Oneiron's own tool results. For every other tool result, `PostToolUse` can
add one line from your vault, up to 12 per session. It only gives lines
above your carrier bar and never gives the same line twice. After compaction,
the board comes back only if that session already had one.

```
Claude Code ──SessionStart──▶ oneiron hook session-start ──▶ bind a vault (below)
                                                       ──▶ oneiron mcp ──▶ serve: vault.recall
                                                           (only with --query "<words>")
            ◀── stdout: the vault's line and any recalled lines, added to context

Claude Code ──Stop/PreCompact/SessionEnd──▶ oneiron hook hand-over
            ──▶ oneiron import claude-code <log> --queue   (writes one small file)
                                   serve, every 5 s ──▶ imports the queued log
            or, to a selected hosted vault (below):
            ──▶ oneiron mcp ──▶ the hosted vault: vault.imports.hook_transcript
```

As with a local import, a session handed over to a hosted vault lands in the project its
folder is bound to there; an agent needs a credential that covers that project or the
hand-over is refused.

- **Recall** goes through `oneiron mcp` with the hooks' own read-only
  credential. It calls `vault.recall` at the `light` effort (no model call)
  unless you set `--effort`; `medium` also searches by the query's vector, so
  a session finds what it worked on in other words; `high`, `xhigh` and `max`
  also rerank on the reranker the server's `[models]` routes, under the
  server's own budget (see [run-with-models.md](run-with-models.md#8-the-reranker)).
  A server that does not list `vault.recall` is asked nothing.
- **Only lines above your relevance bar.** Lines that miss the session's work
  are worse than none, so every hook line is judged by your bar before the
  result is cut: a line under it takes no slot, at most 3 lines are given, only
  from the session's project, and nothing when none clears it. The score is the
  raw cosine of the line's vector and the query's in your vault's embedding
  space (the server embeds the query once for it, at any effort), never a rank.
  Set the bar per hook with the settings `recall.bar.start` (session start) and
  `recall.bar.carrier` (each prompt or tool result), per harness (the item, `claude-code`) and
  per project (a project's row overrides the vault's). The default, `measured`,
  is a cosine of 0.52 in pplx-embed-v1-0.6b's space, where it was measured;
  in any other space it gives nothing until you set a floor
  (`{"cosine": {"floor": 0.6, "model": "<org/name@revision>"}}`), and on a
  vault with no embedder it gives a line holding a rare word of the query, or
  every word of it. `open` skips the relevance cut, `quiet` gives no lines.
  When the bar compares cosines, the recall reports each line's `similarity`.
  To be told in one line when nothing cleared the bar, set
  `recall.bar.empty_receipt` to true for the harness; by default the hook says
  nothing.
- **Read the whole record.** Each pushed line ends with its record id (and
  revision if pinned), source, claim standing when present, readable source
  conversation when known, and the learned time in UTC. Pass the id to
  `vault.hydrate` to read the whole record. The session's own imported
  conversation is never pushed. As owner, use `vault.settings.set` with
  `{"key":"recall.bar.excluded_predicates","scope":{"kind":"vault"},"value":[]}`
  to push all predicates that otherwise pass. The default list is
  `skill.hub_provenance`, `skill.scan_verdict` and `machine.capacity`; each
  entry also excludes predicates below it. A project can set its own list.
- **No recall at start, unless you give the task's words.** A start keyed on
  nothing but the folder's name recalls nothing: on a folder's name no bar
  separates the lines you need from the ones that mislead. The plugin and the
  snippet below pass `--query " "`: a blank query binds the vault, records the
  session and calls no tool. Claude recalls through the MCP tools when the work
  needs it. To be given lines at start, give `--query "<words>"`.
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
  file itself: `--credential-file` for a pinned or local vault, and the one
  the hosted selection names for the hosted vault it selected (below).

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
3. **The hosted vault your sign-in selected**, as `oneiron hosted` recorded it
   ([below](#the-hosted-selection)), when its origin answers the same one
   probe. Its recalls run as the credential the selection names for that
   vault, in its own mode (a paired slip, or your owner sign-in's upgrade
   headers); that credential goes to no other vault, and `--credential-file`
   does not go to it. When this step binds nothing and the hook then binds a
   local vault at step 4, the session prints one more line saying why: no
   hosted vault is signed in to here, none is selected, the selection could
   not be read, or the selected vault is not answering. None of these signs
   you out or changes the selection; the next session looks again.
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
   When `oneiron user-service install` wrote your user service
   ([below](#the-user-service)), the hook asks your own supervisor to start
   it instead, and binds it once it answers; the line says its user service
   started it. If the supervisor refuses the start, the hook starts the
   vault itself and says why.

`prompt` binds the same way, by the same choice of steps 1 to 3, but never
starts a server and prints no line of its own. A pinned or selected vault that does not answer one probe gets no recall, so a
vault that is down costs a prompt at most 2 seconds. `hand-over` queues into the queue of `--config` if you give it;
else, with a pin, of the running local vault at the pin; with no pin, of the
newest running local vault; else of the default config. A pin is never
swapped for another vault. A Claude Code session's `hand-over` goes by what
every `session-start` of that session bound (its first start, and each
resume or compaction). Each start records its binding in
`hook-sessions/<session id>/` in the run folder: `local` for a pin, a local
vault or no vault, `hosted-<16 hex digits>` for a hosted vault (its origin
and id, never a credential), and `unknown` when a resumed or compacted
session had no record yet. Files are owner-only and only ever added. A
session whose records are all `local` loses them 30 days after its last
start, and queues locally as it did with them; every other record is kept,
so a session that bound a hosted vault hands over by it however long it
waited.

- Every start bound your selected hosted vault, and it is still the one
  selected: the `hand-over` sends the session's log and its subagents' logs
  (every `agent-*.jsonl` under `<session>/subagents/`, a workflow run's
  folder included) to that vault through `vault.imports.hook_transcript`, as
  the credential the selection names, in its own mode, and queues nothing
  here. It sends only the log of the event's own session
  (`<session id>.jsonl`). An OAuth selection sends as its hand-over sign-in
  (`hosted login --hand-over`, above). While none stands, the log waits on
  this machine: one small file per session in
  `hosted-hand-over-queue-<origin hash>/` beside `hosted.json`, naming the
  session and its log's path, never a copy of the log. The first session end
  that finds no hand-over sign-in also files the request for one itself: it
  starts `oneiron hosted login --hand-over --unattended` in the background,
  and your inbox asks to "land this machine's coding sessions in your hosted
  vault as each ends". Allow it within 10 minutes (the vault keeps a request
  that long), and the logs waiting land at the next session end. Session
  ends ask again only once a day after a request lapsed, and never after you
  denied one (run `hosted login --hand-over` then); the record is
  `hosted-hand-over-ask-<origin hash>.json`. The next hand-over that
  lands a log sends the logs waiting after it, each read again as below; a
  log that is gone leaves the queue. At most 256 logs wait for one vault,
  and a further one takes the oldest one's place. `logout` empties the
  queue.
- The starts bound a hosted vault that is no longer the one selected, or
  more than one vault (you selected another vault and resumed, say): the log
  goes nowhere, not to the vault selected now and not to a local queue, since
  it holds turns from a vault the other never served. Move it yourself with
  `oneiron continue --cloud --transcript <log>` or
  `oneiron import claude-code <log>`.
- Every start bound a pin, a local vault or no vault, or no start recorded
  anything (the session started before this record): the log queues locally
  as above.

The logs are read below Claude Code's `projects` folder, every folder and log
there opened through no symbolic link, as `serve` reads a queued log. Each
call fits the carrier of the selection's sign-in: the owner's socket frame
(about 8 MiB encoded), else the 64 MiB line `oneiron mcp` reads, and at most
64 MiB inflated. Subagents' logs that do not fit one call with the session's
log go in further calls, each with the session's log again, which the import
lands once. Over the owner's socket, a session's log too long for one call
goes in parts (`vault.imports.hook_transcript_part`), up to 64 MiB encoded:
the hosted vault holds them in memory, at most two sends at once, each for
at most 10 minutes between parts and 30 minutes in all, and lands the log
with the last part as one `vault.imports.hook_transcript` call: a verb hook
on that verb judges the whole log once, and no hook sees a part. A log too
long even for that, or for a slip's one call,
is not sent at all; import it on the machine it ran on with `oneiron import
claude-code <log>`. A send
the hosted vault does not take (it does not answer, or the credential has no
Grant naming the verb) is dropped without a word; the session's next
hand-over sends the whole log again, and the import lands only what is new.
Codex, Cursor and GitHub Copilot sessions go the same way, each by its own
log ([Session hooks for Codex, Cursor and GitHub Copilot](client-session-hooks.md#a-hosted-vault)).

A pin in `hook.toml` counts only when no one but you can write it: your own
regular file, not a link, with no write bit for others and, on macOS, no ACL
entry. A runtime file counts only on the same terms. The session sends its
credential where they point.

Starting a server never creates a vault: the hook starts one only when the
config's `vault_path` holds an initialized vault.

### The user service

Optional. A user service keeps the local vault running between sessions and
after login, under your own supervisor, so step 2 finds it running in every
session. The engine has one writer per vault, and the service is it.

```bash
oneiron user-service install [--config <file>] [--settings-file <file>]
oneiron user-service remove
oneiron user-service status
```

- `install` writes the unit and starts it. On Linux that is the systemd user
  unit `oneiron.service` in `$XDG_CONFIG_HOME/systemd/user/` (else
  `~/.config/systemd/user/`), made from the shipped
  `deploy/systemd/oneiron.service` without its `PrivateTmp=` line (a user
  manager makes a private `/tmp` only inside a user namespace, which some
  distributions refuse) and with `Type=exec` for its `Type=notify` (the
  server reports ready only on a socket systemd passed it, and this service
  binds its address itself); then `systemctl --user daemon-reload`, `enable`
  and `restart`. On macOS it is the launchd agent `com.oneiron.server` in
  `~/Library/LaunchAgents/`, with the shipped agent's label, `RunAtLoad`,
  `KeepAlive` and logs in `~/Library/Logs/`, but no `Sockets`: the server
  binds its configured address itself; then `launchctl bootout` and
  `bootstrap` in your `gui/<uid>` domain. The service runs the `serve` step 4
  runs: this binary (or `--oneiron <file>`), `serve --config <config>
  [--settings-file <file>] --vault-path <vault> --host 127.0.0.1`, with the
  config every command reads when none is named unless you give `--config`,
  and the vault folder `install` found initialized, made absolute: a relative
  `vault_path` is read from the folder you run `install` in, and the service
  starts in another. Run again, it writes the unit anew and restarts the
  service.
- `install` refuses when there is no initialized vault to run; when a unit
  it did not write is at that path (it never overwrites one: each unit it
  writes carries the line `Written by oneiron user-service install.`); and,
  the first time, when a `serve` it did not start already runs that vault.
  Stop that server first.
- `remove` stops the service (`systemctl --user disable --now`, or
  `launchctl bootout`) and deletes the unit `install` wrote, never another.
- Each prints one JSON line, `{"installed", "path", "supervisor"}`.

### The hosted selection

`oneiron hosted` records the hosted vaults you signed in to on this machine
and the one selected, in `hosted.json` in your oneiron config folder, beside
`hook.toml`. The surface you signed in on (the cloud console, the app) runs
these commands to export its selection; you can run them too. With a terminal
alone, `login` signs you in itself. Each prints where the selection stands as
one JSON line.

```bash
# Sign in here: the vault's own sign-in, in a browser; you allow it in your inbox.
oneiron hosted login --origin https://<vault-origin>
# Then let session ends land their logs there (a second sign-in, below).
oneiron hosted login --origin https://<vault-origin> --hand-over
# A paired slip: its own vault id is read from the slip.
oneiron hosted login --origin https://<vault-origin> --credential-file <file>
# Your owner sign-in: the surface that wrote the headers file names the vault.
oneiron hosted login --origin https://<vault-origin> --auth-mode owner \
  --owner-upgrade-headers-file <file> --vault-id <vault-id>
oneiron hosted select <vault-id>     # or: --none
oneiron hosted logout [--vault-id <vault-id>]
oneiron hosted status
```

- `login` records the vault only once its origin admits the credential over
  `oneiron mcp`, the transport a recall uses (`--timeout-secs`, 30 by
  default), and then selects it. A slip names its own vault, which must match
  `--vault-id` when you give one. Nothing is recorded when the origin refuses
  or does not answer; the bridge's own refusal is printed on stderr.
- `login` with no credential file signs in through the hosted vault's own
  OAuth sign-in, as a native app. It prints a link and opens it in your
  browser; the page shows a match code, and you allow the request in your
  Oneiron inbox when the code there is the same. The browser then comes back
  to a one-time listener on this machine's loopback (`--sign-in-timeout-secs`,
  600 by default; other traffic to the listener does not extend it), and
  `login` keeps the sign-in in
  `hosted-oauth-<origin hash>.json` beside `hosted.json`, readable by you
  alone. It asks for the `read` tier, and the vault lists it in your consent
  registry, where one tap revokes it. Its access token lasts an hour and
  refreshes on use; the refresh token lasts 30 days from its last use.
  `oneiron mcp --auth-mode oauth --oauth-token-file <file>` reaches the vault
  with it, over HTTP. The browser must run on the machine that runs `login`.
  An origin has one spelling (scheme and host in lower case, no default
  port), so `HTTPS://Vault.example/` is `https://vault.example`. Run again for
  the same origin, `login` keeps the new sign-in apart until the vault admits
  it for the vault named; only then does it take the old one's place, and the
  old one is revoked. A recorded login also revokes and removes an OAuth
  sign-in the vault's earlier record kept in another file, and drops the
  record of another vault that named the origin's file (the origin answers
  for that vault no more). A login that is not recorded leaves the old
  sign-in as it was.
  A vault that serves no OAuth sign-in (no https `oauth_resource_indicator`
  in its server config) answers 404, and `login` says so.
- `login --hand-over` lets this machine's session ends land their logs in
  the vault recorded at `--origin` in OAuth mode. The `read` sign-in recalls
  and writes nothing, and landing a log writes, so this is a second sign-in
  through the same flow, as the same client: `full` at the vault's `/mcp`
  alone, never its git door. Your inbox ask says it asks to "land this
  machine's coding sessions in your hosted vault as each ends". It is kept
  in `hosted-oauth-hand-over-<origin hash>.json` beside the first, and only
  the `hand-over` hook reads it; recall stays on the `read` sign-in. The
  import still needs your Grant naming `vault.imports.hook_transcript` for
  that agent. `logout` signs it out with the first. You need not run it
  yourself: the first session end that finds no hand-over sign-in files the
  same request on its own (below). `--unattended` is that form: it opens no
  browser, files the ask in your inbox, and waits for your answer for up to
  `--sign-in-timeout-secs`.
- `select` takes a recorded vault id, or its first characters when no other
  recorded id begins with them; `--none` selects none. `logout` forgets one
  recorded vault, or every one. Neither deletes a credential file another
  surface wrote: that surface keeps it. `logout` revokes an OAuth sign-in
  `login` made at its vault, and removes its file, after any refresh in
  flight has written its tokens; the `.lock` file beside it stays.
- `status` prints `state` (`not_logged_in`, `no_selection`, `selected` or
  `unavailable`), the selected vault id and every recorded vault: its
  `origin`, `vault_id`, `auth_mode` (`slip`, `owner` or `oauth`), `credential_file` and
  `verified_at_ms`, when its origin last admitted the credential (a record,
  never an expiry). It names credential files, never what is in them.

The file is written whole, readable and writable by you alone (0600), in one
rename, and only these commands write it. A hook only reads it, and counts it
only on the pin's terms above: the session sends the credential it names to
the origin it names.

`oneiron hook --host hermes bind [--url <origin>]` binds in the same order and
prints the result as one JSON line, `{"url": <origin or null>, "lines": [...],
"hosted": <the selected hosted vault it bound, as `oneiron hosted status` shows
one, or null>}`.
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

## Which project a session reads

You bind a folder to one of your projects, once, in that folder:

```bash
oneiron project bind <project-ref>   # the PROJECT's id, 32 hex
oneiron project unbind               # remove this folder's binding
oneiron project bindings             # list every folder's binding
```

These send your credential as `oneiron api` does (`ONEIRON_SECRET`), and
binding is your act alone: an agent may tell you the command, and its own
attempt waits for your answer. The command sends a BLAKE3 digest of the
checkout's real path (`blake3:` and hex) and the folder's name, never the path;
the vault keys the digest with its own id before it stores it, so one folder's
ids differ from vault to vault. Someone who reads the vault and knows its id can still test a
guessed path against a stored id: the digest hides the path, it is not a
secret. A binding belongs to the machine that holds the vault you bound it
on: another machine of the vault never receives it, and a restore drops it,
so on a replica, and after a restore, the folder reads as unbound until you
bind it again. The folder is the git checkout it sits in, so every subfolder
of a repository shares one binding; a linked worktree with no binding of its
own reads its main checkout's (a bare repository, or one with a separate git
directory, has none). The filesystem root and your home folder are never a
workspace.

The plugin starts `oneiron mcp --workspace .`, so every tool call names the
folder Claude Code runs in. Then:

- A read that names no project (`vault.claims.list`, `vault.recall`, the
  searches, `vault.hydrate` and the rest) reads only claims of the folder's
  project and the projects below it. Its read receipt names the axis
  `session_project`.
- In a folder with no project bound, such a read reads no claim, and its
  receipt names `no_project_bound`: bind one to read the folder's memory. The
  session-start hook says so in its vault line, with the bind command (which
  names that vault by `--base-url`), and recalls nothing for it: it asks the vault once, through a bridge started for
  the session's folder, whether a project is bound there (`initialize` answers
  `project_bound` under `_meta["oneiron/workspace"]`, naming no project).
- The hook's own recalls (at start when it has a query, and on each prompt)
  pass `--workspace` with the session's folder, so they read its project too,
  and your bar is read at that project. In a folder with no project bound
  they give nothing.
- A read that names its projects (`project_refs` on `vault.recall`,
  `vault.claims.list_filtered`, `vault.claims.read_filtered`) reads those,
  within what the credential reads anyway.
- Claims, notes, messages and turns carry a project. The notes and turns a
  session writes, including turns imported from its session log, carry the
  folder's bound project. Rows written with no folder, or before session
  placement, carry the root project, which a bound session does not read.
  Room speech is the exception: a room's history shows its members' messages
  and turns whatever project they carry, since they were posted to every
  member; claims in a room still follow the folder. Conversations and other
  rows read as before.

The binding selects; it grants nothing. The folder a tool call names comes from
the client, so a client that names another folder only changes which of the
rows its credential reads anyway come first by default.

A claim the session writes (`vault.claims.upsert`, `vault.remember`) that names
no project lands in the folder's project, so the session reads it back. One
that names its project (`scope_project_id`) lands there, within what the
credential may write. In a folder with no project bound, writes keep the root's
default project, as before. Notes and turns the session writes land in the
folder's project the same way.

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
paths (`~/` is expanded). The queue is off by default. With it on, an ordinary
`serve` runs it whatever its privacy posture; a vault our cloud hosts (managed
serve) starts no import yet.

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

Add the hook entries in `examples/claude-code-hooks/settings.json` to the
`"hooks"` object of `~/.claude/settings.json` (every project) or of one
project's `.claude/settings.json`. Keep your existing entries. Then replace the
placeholders with full paths. Claude Code does not expand `~` there.

- `/path/to/oneiron`: the `oneiron` binary. Hooks run with Claude Code's
  `PATH`, which may not include it.
- `/path/to/claude-code-hooks.cred`: the file from step 2.
- `/path/to/claude-code.cred`: the same agent credential you use for your
  MCP server. Add `--carrier-in-content` to that server's `oneiron mcp` args.

The hooks find the vault themselves ([above](#which-vault-a-session-uses)).
Add `--url <origin>` to `session-start` to pin one there instead, and
`--config /path/to/oneiron.toml` to `hand-over` when `serve` reads a config
other than the default and may be stopped when a session ends.

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "timeout": 15,
        "command": "/path/to/oneiron hook --host claude-code session-start --credential-file /path/to/claude-code-hooks.cred --query \" \"" } ] },
      { "matcher": "compact", "hooks": [ { "type": "command", "timeout": 15,
        "command": "/path/to/oneiron hook --host claude-code focus-refresh --credential-file /path/to/claude-code.cred" } ] }
    ],
    "PostToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "timeout": 10,
        "command": "/path/to/oneiron hook --host claude-code tool-result --credential-file /path/to/claude-code-hooks.cred" } ] }
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

Start a new Claude Code session. Its context opens with the line naming the
vault, and no recalled lines ([No recall at start](#how-it-works)).

To recall for each prompt as well, add a `UserPromptSubmit` entry running
`/path/to/oneiron hook --host claude-code prompt --credential-file
/path/to/claude-code-hooks.cred`. It recalls at the `light` effort unless
you set `--effort`, gives only the lines that clear `recall.bar.carrier`, and
prints nothing when none does.

### Next to your other hooks

These entries use five events: `SessionStart`, `PostToolUse`, `PreCompact`,
`Stop` and `SessionEnd`. Claude Code merges hook entries across the user, project and
local settings files and runs every matching hook in parallel. So a hook you
already have on another event, for example a `PreToolUse` hook on `Agent` or
`Workflow`, runs exactly as before. If you already have a hook for any of
these events, add ours to that event's list.

## Remove it

1. Delete these hook entries from the settings file.
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
- Messages are searchable at once, so the next session in that project can
  recall them.
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
- `tool-result` has 1.5 seconds for binding, recall and picking a line.
  A smaller `--timeout` takes precedence.
- `focus-refresh` adds the whole board, its two header lines included, only
  when that fits in Claude Code's 10,000 characters; otherwise one line says
  to call `self.focus.refresh` for it.
- `hand-over` takes well under a second: it writes one small file. To a
  hosted vault it sends the whole log, gzip-compressed, in as few calls as
  the sign-in's carrier takes (above), all ending by the same `--timeout`,
  writing the calls included; over the owner's socket a log too long for
  one call goes in parts, up to 64 MiB encoded. A log past that is not
  sent, and lands only through `oneiron import claude-code <log>`. Claude
  Code gives `SessionEnd` hooks 1.5 seconds unless a hook sets its own
  `timeout`; the `timeout` of 5 above raises that budget to 5 seconds.
- `serve` looks at the queue every 5 seconds and imports what waits there.
  One session log is read up to 1 GiB, the same limit as `oneiron import`.
  A larger one, the session's or a subagent's, is left out with a
  `log_too_large` warning in `serve`'s log, and the rest of the session
  lands.
- `--query "<words>"` on `session-start` gives the lines for those words that
  clear your start bar (on `prompt`, the words instead of the prompt). With no
  `--query`, or a blank one (`--query " "`, as the plugin passes), the start
  recalls nothing.
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
