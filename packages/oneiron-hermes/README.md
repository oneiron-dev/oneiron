# oneiron-hermes

Oneiron as [Hermes Agent](https://github.com/NousResearch/hermes-agent)'s
memory provider: a `MemoryProvider` in Hermes's memory slot (OF-442,
ARCH-0028 `#plugin-hermes`). Hermes runs one outside memory provider at a time.

It starts on the cohabitation default:

- **Hermes's built-in memory off** (`memory.memory_enabled` and
  `memory.user_profile_enabled` both false): Oneiron is the agent's memory.
- **Built-in memory on** (Hermes's default): Oneiron runs beside it. The
  built-in memory and user profile files stay primary; Oneiron keeps the
  conversation, mirrors each built-in memory write as a claim, and recalls
  related context into each turn.

`mode` pins either one: `memory` or `beside`. `auto` (the default) reads
Hermes's two flags at session start.

Running beside a second *outside* memory provider is not designed yet: Hermes
holds one at a time.

## What it does each turn

- **Prefetch:** a recall for the user's message, read in the background after
  the turn before (`queue_prefetch`), or in call mode under a 1.5 s deadline
  when nothing was queued. A trivial prompt ("ok", "thanks", a slash command)
  recalls nothing.
- **Sync:** the user's message and the reply are witnessed into one Oneiron
  conversation per Hermes session, on a background thread. Subagents, cron
  runs and flushes write nothing.
- **Built-in memory writes** (beside): each add, replace or remove is
  witnessed as a note and kept as one claim (`hermes.memory.note` or
  `hermes.memory.user`), keyed by the entry, so a replace updates it and a
  remove closes it.
- **Tools:** `oneiron_recall` and `oneiron_remember`. Hermes reserves the
  `memory` tool name for its own store.
- **Compression and session switches** wait for the writes in flight first.

## Install

```sh
pip install oneiron oneiron-hermes
```

The package registers the entry point `oneiron` in the
`hermes_agent.memory_providers` group. To install it as a directory instead,
copy `src/oneiron_hermes/` (with its `plugin.yaml`) to
`$HERMES_HOME/plugins/oneiron/`; the `oneiron` Python package must still be
importable.

Mint the agent's credential with the vault's server stopped
(`docs/ops/connect-an-agent.md`):

```sh
oneiron token agent --name hermes --out /Users/you/.config/oneiron/hermes.cred
```

Then select the provider and set it up:

```sh
hermes memory setup     # pick "oneiron"; set credential_file to the file above
```

or in `config.yaml`:

```yaml
memory:
  provider: oneiron
```

## Config

`hermes memory setup` writes these to `$HERMES_HOME/oneiron.json`:

| Key | Default | Meaning |
|---|---|---|
| `url` | empty | The vault's origin. Empty: the first of a pin (`ONEIRON_URL`, `hook.toml`), a running local vault, else a local server started from the default config. |
| `credential_file` | empty | The file `oneiron token agent --out` wrote. `ONEIRON_KEY` holds the credential itself instead. |
| `mode` | `auto` | `auto`, `memory` or `beside`. |
| `effort` | `light` | Recall effort; `medium` and up embed the query. |
| `limit` | `8` | Most memories one recall returns. |
| `oneiron` | `oneiron` | The binary that binds the vault. |

`ONEIRON_URL`, `ONEIRON_CREDENTIAL_FILE` and `ONEIRON_HERMES_MODE` override the
file.

## Which vault

The plugin asks `oneiron hook --host hermes bind`, which binds in the order
every Oneiron plugin uses (PLUGIN-FIRSTRUN = D) and prints
`{"url", "lines"}`. The first line, naming the vault, opens the provider's
system-prompt block. Without the `oneiron` binary on `PATH` the plugin uses
`url` as given.

## Status

Built in the current build; installed and tested against a live Hermes in
Phase 2.
