# Connect Claude Code or Codex to your vault

An agent that runs MCP servers as commands (Claude Code, Codex) reaches a
running `oneiron serve` through `oneiron mcp`. That command speaks MCP on stdio
to the agent and forwards each message to the server's MCP endpoint, signing a
fresh holder proof for every request. The agent holds no secret and never
types its own identity; the server checks both on every call.

Each agent gets its own credential: a slip paired to that agent's principal
(actor class `agent`), carrying only the verbs its tier needs. It is never
owner-grade, and you can revoke it on its own.

## 1. Mint the agent's credential

Stop `oneiron serve` first: minting holds the vault's writer lease, like every
local owner command. Use the same config as `serve` (`--config`,
`ONEIRON_AUTH_SECRET`).

```bash
mkdir -p ~/.config/oneiron
oneiron token agent --name claude-code --out ~/.config/oneiron/claude-code.cred
oneiron token agent --name codex --out ~/.config/oneiron/codex.cred
```

- `--out` writes a new file that only you can read, and prints the agent's
  `principal_ref` and `slip_id`. Keep the `slip_id`: it is what you revoke.
  Without `--out` the credential is printed instead.
- One name is one agent principal, and its latest mint is its one
  credential. Minting `claude-code` again gives the same agent a new slip and
  revokes its earlier ones in the same act; the output lists them under
  `revoked_slip_ids`. Give each seat that must stay connected its own name
  (`claude-code-laptop`, `claude-code-desktop`). A slip lasts 30 days by
  default (`--lifetime-secs` to change, capped by the vault's policy).
- `--tier` sets what the agent may do (ARCH-0028's tiers). The latest mint
  for a name sets that agent's tier.
  - `full-access` (the default): what it writes lands at once, through the
    same write gate as yours (ceiling `auto`).
  - `propose-only`: it can write through MCP, but at ceiling `proposed`, so
    its claims wait for your review and the gate refuses what cannot wait,
    such as witnessed conversation. Its slip carries `core:propose`, not
    `core:write`, so no route that commits a write directly (such as
    `/v1/core/batch`) accepts it.
  - `read-only`: it only reads.
- Nothing else can be minted for an agent: no `core:auth`, no organization
  power, never your own owner credential.

Start the server again: `oneiron serve --config <config>`.

## 2. Add it to the agent

`oneiron mcp` forwards to `http://127.0.0.1:9090`, where `oneiron serve`
listens by default; pass `--url` (or set `ONEIRON_URL`) only if your server
listens elsewhere. `--surface tool-first` is the endpoint that lists one tool
per exported verb (`/mcp/tool-first`); `--surface primary` is the code-mode
endpoint (`/mcp`). You choose it here; the agent cannot change it.

**Claude Code** (`-s user` makes it available in every project):

```bash
claude mcp add -s user oneiron -- oneiron mcp --surface tool-first \
  --credential-file ~/.config/oneiron/claude-code.cred
```

**Codex**, in `~/.codex/config.toml`:

```toml
[mcp_servers.oneiron]
command = "oneiron"
args = ["mcp", "--surface", "tool-first",
        "--credential-file", "/Users/you/.config/oneiron/codex.cred"]
```

Codex does not expand `~` in `args`; write the full path.

`oneiron mcp` needs the host's `curl` 7.76 or newer on `PATH`, the same as
`oneiron api`. Instead of `--credential-file` it also reads the slip from
`ONEIRON_SECRET` and its seed from `ONEIRON_BINDING_KEY` (the `token` and
`binding_key` fields `token agent` prints without `--out`; `--secret-env` and
`--binding-key-env` name other variables). The curl it runs inherits neither
variable. The file keeps the secret out of the agent's own config.

Each request gets 120 seconds, answer included (`--request-timeout-secs`), and
an answer that starts arriving and then stalls for 30 seconds is given up on
(`--idle-timeout-secs`).

## 3. Revoke an agent

```bash
oneiron token revoke --jti <slip_id>    # with the server stopped
```

The next call that agent makes is refused with JSON-RPC error `-32001`
(`mcp_auth_required`). Mint a new credential to let it back in.

## What the agent sees

- `initialize` answers with the agent's own actor. `tools/list` is the server's
  tool list, with the `actor` block left out of every input schema:
  `oneiron mcp` adds that block to each call from the `initialize` answer.
- A request the server refuses before MCP because of the credential (HTTP 401
  or 403: a revoked or expired slip, a bad holder proof) comes back as
  JSON-RPC error `-32001` (`mcp_auth_required`), with the server's error body
  in `error.data.server_error`. Any other HTTP error, or an answer that is not
  a JSON-RPC response to that request, comes back as `-32000`
  (`server_error`) with the status in the message. A server that cannot be
  reached, or gives no whole answer within the request's time, comes back as
  `-32000` (`server_unreachable`).
- A message over 2 MiB (the server's own request limit) is refused unsent
  with `-32600` (`frame_too_large`), and an answer over 16 MiB is dropped with
  `-32000` (`reply_too_large`); either way the session goes on.
- `oneiron mcp` prints nothing on stdout but MCP messages, and never prints the
  slip or seed anywhere.
