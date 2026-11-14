---
name: oneiron
description: Use the person's Oneiron vault as long-term memory across Claude Code sessions. Use it when the person refers to earlier work, decisions, people or preferences that this session does not hold; when you learn a lasting fact worth keeping; or when the Oneiron tools or hooks need setting up.
---

# Oneiron: your vault as memory

The Oneiron plugin connects this session to the person's vault in two ways:

- **Hooks run on their own.** When a session starts, a hook binds a vault and
  adds one line naming it, then a short recall for the project under "From
  your Oneiron vault". Before a compaction, after each reply and when the
  session ends, a hook queues the session's log; the running `oneiron serve`
  imports it, and each message lands once.
- **The `oneiron` MCP server gives you the vault's verbs as tools**, one tool
  per verb, under the agent credential the person minted for Claude Code. That
  credential decides what you may read and write. The vault checks it on every
  call; you never name your own identity.

## Recall

Before you ask the person to repeat something, or guess at an earlier
decision, call `vault.recall` with a short `query` in plain words (a project,
a person, a topic). `effort` is one of `light` (no model call, fastest),
`medium` (the default: embeds the query, so other words for the same thing
match), `high`, `xhigh` and `max` (these also rerank). Use `limit` to keep
the answer short. When you act on a recalled memory, say so, so the person
can correct it.

## Save

When you learn a lasting fact the person would want kept (a decision, a
preference, who owns what), save it with `vault.remember`: one claim with a
`subject_ref`, a `predicate`, a `value`, a `confidence` and a `source`. It
goes through the same write gate as the person's own writes. A propose-only
credential's claims wait for the person's review. Do not save secrets,
passwords or keys, and do not save what the session's log already carries:
the hooks hand the whole log to the vault.

`self.actor` tells you the actor your credential binds and the person it acts
for, as refs a claim can take as its `subject_ref`. `vault.people.list` lists
the people you may read, by handle.

## Set up once

The plugin mints no credential: a grant comes only from the person. If the
`oneiron` tools fail to connect, or the session-start line says no vault
answered, walk the person through these steps.

1. Put the `oneiron` binary on the `PATH` Claude Code runs with, and set up a
   vault with `oneiron init <vault folder>` if there is none.
2. Stop `oneiron serve` (minting holds the vault's writer lease), then mint the
   two credentials the plugin reads, one for the tools and a read-only one for
   the hooks:

   ```bash
   oneiron token agent --name claude-code --out ~/.config/oneiron/claude-code.cred
   oneiron token agent --name claude-code-hooks --tier read-only --out ~/.config/oneiron/claude-code-hooks.cred
   ```

   Pass the same `--config` as `serve` uses when it reads a config other than
   the default. Keep each `slip_id` the commands print: it is what you revoke.
3. Turn on the import queue so the hooks' hand-over lands: `queue = true` under
   `[import]` in the config `serve` reads. Then start `oneiron serve` again.
4. Start a new session. Its context opens with the line naming the vault.
5. Optional: keep the vault running between sessions and after login with a
   user service (a systemd user unit on Linux, a launchd agent on macOS). If
   it says the vault is running now, stop that `oneiron serve` first, so the
   service is the vault's one writer. Give it the same `--config` and
   `--settings-file` as the hooks when they use others.

   ```bash
   oneiron user-service install
   ```

   `oneiron user-service remove` stops the service and deletes its unit.

Setup details, the vault each session binds, and what lands:
`docs/ops/claude-code-hooks.md` and `docs/ops/connect-an-agent.md` in the
Oneiron repository.

## Remove

Uninstall the plugin with `/plugin uninstall oneiron@oneiron`. With `serve`
stopped, revoke each credential with `oneiron token revoke --jti` and the
`slip_id` its mint printed, then delete the two `.cred` files. What the hooks
already imported stays in the vault, like any import.
