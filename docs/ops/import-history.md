# Import your ChatGPT, Claude, Claude Code and Codex history

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

```bash
oneiron import claude-code ~/.claude/projects --dry-run   # counts only; writes nothing
oneiron import claude-code ~/.claude/projects
oneiron import codex ~/.codex/sessions/2026/10
oneiron import chatgpt ~/Downloads/chatgpt-export.zip
```

Only the path you give is read. Symbolic links under it are not followed, and
a file or folder that changes into something else while it is read is refused.

## What lands

- Each source conversation becomes a conversation in the vault; each message a
  message, grouped into turns of one speaker. A ChatGPT edit or regeneration,
  a Claude Code sidechain or subagent, and a Codex spawned or forked thread
  each become their own conversation, linked to the one they belong to.
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
its text, in the same transaction as the message. Running the same import again
writes nothing. A session that grew, or a later export, adds only the new
messages. A message whose text changed is landed as a revision beside the
original, never as a duplicate. Copies of earlier messages land once: Claude
Code copies a resumed session's lines into the new session's log, and Codex
copies a parent thread's items into a forked or spawned thread's rollout.

## The report

stdout is one JSON document of counts: per conversation (its source id, kind,
`new`, `skipped`, `changed`, `refused`, `not_kept`), totals, and `files`
(`read`, and `passed`: other `.jsonl` files under the path, such as a workflow
journal). It never holds message text or titles. `--dry-run` prints the same
counts and predicts the secret scan's refusals; a refusal from a policy gate
shows only in a real import.

## Claims

Imported turns carry an import stamp. The Dreamer classifies what it extracts
from them as imported evidence, and imported material never approves itself
(ARCH-0027, ARCH-0040). Reviewing those claims in bulk is the next step and
is not wired by this command.
