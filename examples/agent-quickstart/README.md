# Agent quickstart

From the repository root, on a development/build host:

```sh
python3 examples/agent-quickstart/quickstart.py --keep-running
```

The script installs this checkout, initializes a fresh authenticated vault,
mints a scoped agent credential, starts the daemon, saves an agent-private
diary memory through HTTP, recalls that exact entry, and connects MCP stdio.
It needs no account, API key, model service, dashboard, or interactive pairing.

Prerequisites: Python 3.11+, curl 7.76+, and (unless `--binary` is supplied)
rustup plus the native compiler tools. See
[the setup guide](../../docs/agent-setup.md) for unattended prerequisite commands,
client configuration for Claude Code/Codex/OpenCode, and error recovery.
Repository build-host rules still apply; do not build on the owner's Mac.

Options:

- `--binary /absolute/path/to/oneiron`: skip installation and use a binary from
  this checkout. No compiler is needed in this mode.
- `--directory /absolute/new/directory`: choose a durable setup directory.
  Without it, an owner-only directory under the OS temp directory is used.
  Existing directories are refused, not overwritten.
- `--keep-running`: leave the server available after the round trip. Without
  this option it is stopped before the script exits. A failure stops it too.

The script prints the actual URL and paths, and writes `connection.json` and
`mcp.json` in its setup directory. The latter contains ready `mcpServers`
configuration with absolute paths. Keep `agent.cred` and `oneiron.toml` private.
The printed `kill <pid>` command stops the server without deleting the memory.

The demo disables device keystore access in its fresh config to avoid OS
keychain prompts. It does not disable HTTP auth or loosen claim policy.
Private-world keys and device-signing doors are not part of this example.

## Credential names

The private `agent.cred` file holds the paired `v2.cred.<slip hex>.<seed hex>`
credential. For HTTP, the script splits that value into the CLI's real defaults:
`ONEIRON_SECRET` is the `v2.slip.*` bearer and `ONEIRON_BINDING_KEY` is its
64-hex holder seed. `ONEIRON_URL` is the server origin, not a credential.
The SDK/client docs use those same names. `ONEIRON_LINK` is only the one-use
pairing link in the SDK pairing example. No request uses the host issuer secret.
The script ignores inherited `ONEIRON_*` values and makes its own connection.
