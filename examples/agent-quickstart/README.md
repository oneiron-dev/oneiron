# Agent quickstart

From the repository root on Linux (on macOS, see the [signed binary requirement](../../docs/agent-setup.md#prerequisites)):

```sh
python3 examples/agent-quickstart/quickstart.py --binary /absolute/path/to/oneiron --keep-running
```

The script starts a fresh authenticated loopback vault and mints its agent
credential. Over HTTP it saves an entry and reads it back from its private diary.
It then saves and recalls a vault-readable research note.
It checks the memory round trip and runs MCP `initialize` over stdio. No
account, external API key, model service, dashboard, or interactive pairing
is needed.

Default `vault.recall` does not include diary entries.

Use a compatible Linux binary from this revision, Python 3.11+, and curl
7.76+. The tested binary was Linux x86-64. The script does not download a
binary. See [the setup guide](../../docs/agent-setup.md) for build dependencies,
client configuration for Claude Code/Codex/OpenCode, and error recovery.

The `--binary` option skips compilation. Without it, Linux builds this checkout
with Cargo's release profile. In one Linux x86-64 test, a one-job install with
partly cached build artifacts took about 2 h 7 min and peaked at about 37.2 GiB.
A cold parallel attempt was killed at a 40 GiB cap. A successful cold build and
a 16 GiB source install were not demonstrated.

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

The demo uses the platform keystore to mint its agent credential. On Linux,
keys are in an owner-only directory beside the vault; no keychain login is
needed. HTTP auth and claim policy are unchanged.

## Credential names

The private `agent.cred` file holds the paired `v2.cred.<slip hex>.<seed hex>`
credential. For HTTP, the script splits that value into the CLI's real defaults:
`ONEIRON_SECRET` is the `v2.slip.*` bearer and `ONEIRON_BINDING_KEY` is its
64-hex holder seed. `ONEIRON_URL` is the server origin, not a credential.
The SDK/client docs use those same names. `ONEIRON_LINK` is only the one-use
pairing link in the SDK pairing example. No request uses the host issuer secret.
The script ignores inherited `ONEIRON_*` values and makes its own connection.
