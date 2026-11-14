---
name: oneiron
description: Use the person's Oneiron vault as long-term memory across coding sessions. Use it when the person refers to earlier work, decisions, people or preferences that this session does not hold; when you learn a lasting fact worth keeping; or when the Oneiron tools need setting up.
---

# Oneiron: your vault as memory

The Oneiron plugin connects this session to the person's vault through MCP.
The `oneiron` MCP server gives you the vault's verbs as tools, one tool per
verb, under the agent credential the person minted for this client. That
credential decides what you may read and write. The vault checks it on every
call; you never name your own identity.

This plugin runs no hooks: nothing recalls on its own when a session starts,
and nothing hands the session's log to the vault. Recall when you need it,
and save what is worth keeping yourself.

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
passwords or keys, and do not copy the conversation into the vault: save the
fact, not the talk around it.

`self.actor` tells you the actor your credential binds and the person it acts
for, as refs a claim can take as its `subject_ref`. `vault.people.list` lists
the people you may read, by handle.

## Set up once

The plugin mints no credential: a grant comes only from the person. If the
`oneiron` tools fail to connect, walk the person through these steps.

1. Put the `oneiron` binary on the `PATH` the client starts MCP servers
   with, and set up a vault with `oneiron init <vault folder>` if there is
   none. The plugin's server reaches `oneiron serve` at its default address,
   `http://127.0.0.1:9090`; if `serve` listens elsewhere, add `--url` and
   that origin to the args in the plugin's `mcp.json`.
2. Find the file the plugin reads. The client gives each installed plugin a
   data folder of its own, and the plugin reads its credential from
   `agent.cred` in that folder. Until that file exists, the `oneiron` server
   fails to start, and its error in the client's MCP server log names the
   full path it looked for.
3. Stop `oneiron serve` (minting holds the vault's writer lease), then mint
   the agent's credential to that path. Give each client its own name, such
   as `codex`, `cursor` or `copilot`, so each can be revoked alone:

   ```bash
   oneiron token agent --name <client> --out <data-folder>/agent.cred
   ```

   Pass the same `--config` as `serve` uses when it reads a config other than
   the default. Keep the `slip_id` the command prints: it is what you revoke.
   Then start `oneiron serve` again and restart the plugin's server, or the
   client.

Setup details and what each tier may do: `docs/ops/connect-an-agent.md` in
the Oneiron repository.

## Remove

Uninstall the plugin in the client. With `serve` stopped, revoke the
credential with `oneiron token revoke --jti` and the `slip_id` its mint
printed, then delete `agent.cred` if the client kept the data folder. What
you saved stays in the vault, like any write.
