# Connect Claude Code or Codex to your vault

An agent that runs MCP servers as commands (Claude Code, Codex) reaches a
running `oneiron serve` through `oneiron mcp`. That command speaks MCP on stdio
to the agent and forwards each message to the server's MCP endpoint, signing a
fresh holder proof for every request. The agent holds no secret and never
types its own identity; the server checks both on every call.

Each agent gets its own credential: a slip paired to that agent's principal
(actor class `agent`), carrying only the verbs you name. It is never
owner-grade, and you can revoke it on its own.

## 1. Mint the agent's credential

Stop `oneiron serve` first: minting holds the vault's writer lease, like every
local owner command. Use the same config as `serve` (`--config`,
`ONEIRON_AUTH_SECRET`).

```bash
mkdir -p ~/.config/oneiron
oneiron token agent --name claude-code --scope core:read,core:write \
  --out ~/.config/oneiron/claude-code.cred
oneiron token agent --name codex --scope core:read,core:write \
  --out ~/.config/oneiron/codex.cred
```

- `--out` writes a new file that only you can read, and prints the agent's
  `principal_ref` and `slip_id`. Keep the `slip_id`: it is what you revoke.
  Without `--out` the credential is printed instead.
- `--scope` takes `core:read` (required), `core:propose` and `core:write`.
  Nothing else can be minted for an agent.
- One name is one agent principal. Minting `claude-code` again gives the same
  agent a new slip; the old slip stays valid until you revoke it or it expires
  (30 days by default, `--lifetime-secs` to change, capped by the vault's
  policy).
- The scope sets the agent's tier. With `core:write` it has full access: what
  it writes lands at once, through the same write gate as yours (ceiling
  `auto`). With `core:read,core:propose` its claims wait for your review
  (ceiling `proposed`), and it cannot witness conversation. With `core:read`
  alone it only reads. The latest mint for a name sets that agent's tier.

Start the server again: `oneiron serve --config <config>`.

## 2. Add it to the agent

`--url` is the server's origin. `--surface tool-first` is the endpoint that
lists one tool per exported verb (`/mcp/tool-first`); `--surface primary` is
the code-mode endpoint (`/mcp`). You choose it here; the agent cannot change it.

**Claude Code** (`-s user` makes it available in every project):

```bash
claude mcp add -s user oneiron -- oneiron mcp --url http://127.0.0.1:3000 \
  --surface tool-first --credential-file ~/.config/oneiron/claude-code.cred
```

**Codex**, in `~/.codex/config.toml`:

```toml
[mcp_servers.oneiron]
command = "oneiron"
args = ["mcp", "--url", "http://127.0.0.1:3000", "--surface", "tool-first",
        "--credential-file", "/Users/you/.config/oneiron/codex.cred"]
```

Codex does not expand `~` in `args`; write the full path.

`oneiron mcp` needs the host's `curl` 7.76 or newer on `PATH`, the same as
`oneiron api`. Instead of `--credential-file` it also reads the slip from
`ONEIRON_SECRET` and its seed from `ONEIRON_BINDING_KEY` (the `token` and
`binding_key` fields `token agent` prints without `--out`). The file keeps the
secret out of the agent's own config.

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
- A request the server refuses before MCP (a revoked or expired slip, a bad
  holder proof) comes back as JSON-RPC error `-32001`, with the server's error
  body in `error.data.server_error`. A server that cannot be reached comes back
  as `-32000` (`server_unreachable`).
- `oneiron mcp` prints nothing on stdout but MCP messages, and never prints the
  slip or seed anywhere.
