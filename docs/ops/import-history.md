# Import your ChatGPT, Claude, Claude Code, Codex, Copilot and Cursor history

`oneiron import <source> <path>` brings your own history into your vault. Stop
`oneiron serve` first: the import holds the vault's writer lease, the same as
every local owner command. `--dry-run` never opens the vault (it reads the
import ledger with LMDB read-only), so it also works while `serve` runs. Both
read the same config as `serve` (`--config`, `--vault-path`, `ONEIRON_*`).

| Source | `<path>` |
|---|---|
| `chatgpt` | The export zip, its `conversations.json`, or the unzipped folder. |
| `claude` | The Claude.ai export zip, its `conversations.json`, or the unzipped folder. |
| `claude-code` | `~/.claude/projects`, one project's folder in it, or one session `.jsonl`. Given `~/.claude`, only `projects/` is read. |
| `codex` | `~/.codex/sessions`, any year, month or day folder in it, or one rollout `.jsonl`. Given `~/.codex`, only `sessions/` is read. |
| `hook-transcript` | One GitHub Copilot or Cursor session `.jsonl` a hook handed over, under a folder in `hook_transcript_roots` (below). Never a folder. |

```bash
oneiron import claude-code ~/.claude/projects --dry-run   # counts only; writes nothing
oneiron import claude-code ~/.claude/projects
oneiron import codex ~/.codex/sessions/2026/10
oneiron import chatgpt ~/Downloads/chatgpt-export.zip
```

Only the path you give is read. Symbolic links under it are not followed, and
a file or folder that changes into something else while it is read is refused.

## While `serve` runs: the import queue

With `queue = true` under `[import]` in the serve config, `serve` imports
session logs handed to it, so you need not stop it:

```bash
oneiron import claude-code ~/.claude/projects/<project>/<session>.jsonl --queue
```

`--queue` writes one small file naming the log and returns. `serve` imports
it within seconds, the same way as above, with the session's subagent logs.
Only logs under `claude_code_root` (default `~/.claude/projects`) or
`codex_root` (default `~/.codex/sessions`) are imported, and no link under
them is followed. The [Claude Code hooks](claude-code-hooks.md) queue each
session this way at every stop.

Each pass lands what is queued, earliest session first, up to the size
limit of one import below. What is past it waits for the next pass, which
comes 5 seconds later; a waiting log is not read again until it lands.

## A coding agent's hook transcript: GitHub Copilot and Cursor

GitHub Copilot (in VS Code, and the Copilot CLI) and Cursor give their hooks
the path of the session's log (`transcript_path`). Hand that one file over:

```bash
oneiron import hook-transcript <transcript_path> --queue   # serve imports it
oneiron import hook-transcript <transcript_path>           # serve stopped
```

The log must sit under a folder you list in the serve config; none is listed
by default, so no hook transcript is read until you list one. Each folder
must be absolute (`~` is expanded), and everything below it counts. Listing a
folder is your standing approval for every transcript under it, queued or
imported directly:

```toml
[import]
queue = true
hook_transcript_roots = [
  "~/.copilot/session-state",          # Copilot CLI: <session>/events.jsonl
  "~/.cursor/projects",                # Cursor: <folder>/agent-transcripts/<id>/<id>.jsonl
  "<VS Code workspace storage>",       # VS Code Copilot: <workspace>/<extension>/transcripts/<session>.jsonl
]
```

What the file holds picks the reader, never its name or folder:

- **GitHub Copilot.** VS Code's transcript and the CLI's `events.jsonl` are
  one event per line (`type`, `data`, `id`, `timestamp`). The words of
  `user.message` and `assistant.message` land, each known by its event id
  (`copilot:<id>`), in the conversation `copilot:<session>`: the id in the
  log's `session.start`, or else the file's name (for an `events.jsonl`, its
  session folder's). A subagent's events (`agentId`) land as its own
  conversation, `copilot:<session>/agent/<agent>`, whose prompts are the
  delegating agent's. A prompt a skill or autopilot wrote is counted as
  injected; one another agent sent is that agent's, never yours. Reasoning,
  tool calls and their results, system messages and session events are
  counted.
- **Cursor.** Cursor publishes no format for this file, so the reader takes
  only what a dated public sample (July 2026) shows: one line per message,
  `role` and `message.content` blocks of `text` and `tool_use`, and the older
  `turn_ended` line. Other fields are ignored. Your words are those inside
  the `<user_query>` wrapper Cursor adds. The log keeps no ids or times, so
  each message's id chains from the one before it, and the conversation
  (`cursor:<id>`, from the file's name) occurs when it was imported. A
  message added at the end of a grown log is new; one inserted or removed in
  the middle gives every message after it a new id, so those land again.

Every line the reader cannot read (not JSON, or not a record it knows) is
counted in `not_kept.unreadable`, per conversation and in the totals; a
queued import logs the pass's count as `unreadable` on `queued import
landed`. A file with no Copilot or Cursor record at all is refused, with its
line count, and nothing lands. Re-reading a grown log lands only what is new,
as for every source; hand it over again at each stop.

## What lands

- Each source conversation becomes a conversation in the vault; each message a
  message, grouped into turns of one speaker. A ChatGPT edit or regeneration
  (with what was said after it), a Claude Code sidechain or subagent, and a
  Codex spawned or forked thread each become their own conversation, linked to
  the one they belong to. The conversation itself is the path as first
  written, whichever branch the app showed when you exported, so switching
  branches and exporting again never moves a message.
- Messages are searchable at once through your recall (lexical search;
  vectors follow when `serve` has an embedder).
- The speaker is the source's: the import is not recorded as their author.
  Messages occurred when the source says and were learned at the import.
- Tool calls and results, reasoning, system prompts, injected context (hook
  reminders, command output, environment blocks, the Codex IDE wrapper around
  your request) and attachments are not landed. Each is counted in the report
  under `not_kept`. Tool names are kept on the assistant message that called
  them. A slash command you typed with arguments (`/review explain this`) and
  a prompt you queued while the assistant was busy are your words and land.
- The write door's secret scan applies. A turn holding a secret-shaped value is
  refused and counted under `refused`, and the rest of the import lands. With
  the scan on (the default), the next import tries that turn again.

## Re-importing

An import ledger records every imported message by its source id and a hash of
its text, its role, and whether the source left the speaker unknown, in the same
transaction as the message. Running the same import again
writes nothing. A session that grew, or a later export, adds only the new
messages. A message whose text changed is landed as a revision beside the
original, never as a duplicate. Copies of earlier messages land once: Claude
Code copies a resumed session's lines into the new session's log, and Codex
copies a parent thread's items into a forked or spawned thread's rollout.

A Claude Code or Codex conversation keeps the folder its session ran in (the
`import_cwd` field) and occurs when the session started (`occurred` in
`GET /v1/core/conversations?view=full`).

## Size limits

No session log and no export is passed over or refused for its size. Every
log, the session's own and each subagent's, is read whole, and so is an
export's `conversations.json`. Only the decoders keep bounds of their own: a
zipped export unzips its `conversations.json` up to 2 GiB, and one
conversation of an export, or one line of a log, is parsed up to 128 MiB.

An import that holds more than `[limits] import_decoded_messages` (a million
messages) or `import_decoded_bytes` (1 GiB of them) decoded lands whole all
the same. The row asks whether everything is okay, and the report names it in
`warnings` (`"warning": "limit_crossed"`, its `row`, `limit` and `observed`).
`serve`'s queue lands queued sessions in passes of about that much; a session
past it lands alone, and its rows ask in `serve`'s log.

## The report

stdout is one JSON document of counts: per conversation (its source id, kind,
`new`, `skipped`, `changed`, `refused`, `not_kept`), totals, `files` (`read`;
`passed`: other `.jsonl` files under the path, such as a workflow journal;
`hard_linked`: session logs with another name, a hard link that may point
outside the folder, never read), and `warnings`: one per `[limits]` row the
import crossed (`"warning": "limit_crossed"`), plus one `"warning":
"hard_linked"` with the count of hard-linked logs, which it does not name, and
`review`, where the claims drawn from this import wait (below; `null` for a
dry run and for an import that landed nothing). It never holds message text
or titles. `--dry-run` prints the same counts and
predicts the secret scan's refusals; a refusal from a policy gate shows only
in a real import.

## Claims

Imported turns carry an import stamp. Each import queues the Dreamer over what
it landed, since no session ends for an import, and `serve` with a model runs
it. Every claim the Dreamer draws from imported words is `imported` and waits
for you, Proposed: imported material never approves itself, whatever the
policy's source-trust rows grant (ARCH-0027, ARCH-0040). The prompts a
delegating agent gave its subagents are not your words and are not read for
claims; what the subagents answered is. Neither are words whose speaker the
log does not say, such as a Codex thread's copy of history whose own thread
the copy left out: they land with `said_by: unknown`, and once you import the
rollout that says they were yours, they land again as yours and are read.

Each import is one review, named in the report's `review` (`run_id`
`import:<source>:<time>`, its `run_ref`, and the Dreamer attempts it queued).
Approve or decline it whole, with one receipt, as any run
([Approve or decline an agent run in one act](owner-actions.md#approve-or-decline-an-agent-run-in-one-act)):

```bash
oneiron runs pending
oneiron runs show import:claude-code:1791234567
oneiron runs approve import:claude-code:1791234567 --bundle <bundle id from show>
```

The review fills as the Dreamer runs; `show` lists what waits so far and its
bundle id binds exactly that. A claim citing words a later import added to the
same turn waits in the later import's review; a claim you declined is not
proposed again from the same words. A large import drains over several Dreamer
passes, each reading about one round of turns. Each import takes a second of
its own on the vault's clock: if that clock is ahead of the machine's (the
system clock moved back), the import is refused until the machine catches up.

## Keep a folder of notes attached

`oneiron import notes` reads a folder once. To keep a folder of markdown
notes and PDFs (an Obsidian vault, an agent's memory folder) attached instead:

```sh
oneiron import folder attach ~/notes [--include 'journal/**/*.md'] [--kind observation]
oneiron import folder rescan [~/notes]     # one folder now, or every attached one
oneiron import folder list
oneiron import folder detach ~/notes       # rescans stop; the notes stay
```

`attach` records the folder and lands its notes the way `import notes` lands
them. From then on `oneiron serve` rescans every attached folder when it starts
and every five minutes (a local vault only). Each rescan:

- lands a new file as a new note, with its title and links;
- supersedes what a changed file landed: when the note still holds that text,
  the file's text replaces it through the note edit door, which keeps its
  history; when you edited the note since, the file's text waits as a fork for
  review and your edits stay;
- retracts the note of a file that left the folder. The note is archived, a
  local marker that keeps its text, and comes back when the file does. Nothing
  is erased, and a note you deleted or archived yourself is left alone.

A folder's notes come in as imported, never as your own writing (ARCH-0027).
Each folder has its own import machine: it is the author of the notes the
folder brings, and its rescans make the edits that follow the files. The notes
stay yours to read, title and edit, and your edits are yours. Note titles are
per author, so a folder note may share a title with a note you wrote.

A PDF lands as the text of its pages, titled by its file name, whatever its
size or page count. Only the text layer is read: a scanned PDF reads as blank,
and an encrypted or unreadable one is passed over and counted
(`unreadable_pdf`). A page whose content decodes past 8 MiB (the decoder's
bound) is left out and the rest lands (`partly_read_pdf`). A PDF whose bytes
change while its text does not keeps its note as it is.

No file is passed over for its size. Text past the 1 MiB a note holds lands in
parts, cut at a line break where one is near: the file's own note holds the
first, and each next part is a note of its own (`<path>#part2`, titled
`<title> (part 2)`, and so on), of the same kind, linked to the first. A
markdown file's frontmatter stays in its first part, and each part's
`[[links]]` are those in its own text. When the file shrinks, the parts its
text no longer reaches are retracted. A folder whose notes hold more text than
`[limits] import_folder_text_bytes` (256 MiB), or more notes than
`import_folder_notes` (100,000), is read and imported whole all the same: the
row asks whether everything is okay, and stdout names it in `warnings`
(`"warning": "limit_crossed"`).

Nothing is ever written to the folder: it feeds the vault, it is not the vault.
A folder that is missing retracts nothing. A folder whose last file you
deleted retracts that file's note too; if a mount point reads empty, the notes
come back at the rescan after it is mounted again. The CLI opens the
vault itself, so run `attach`, `rescan` and `detach` with `serve` stopped.
