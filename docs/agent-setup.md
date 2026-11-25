# Unattended agent setup

From a checkout, on Linux:

```sh
python3 examples/agent-quickstart/quickstart.py --binary /absolute/path/to/oneiron --keep-running
```

Use a compatible Linux binary from this revision. The tested binary was
Linux x86-64. The script starts an authenticated loopback vault.
It saves an entry and reads it back from its private diary. It then saves and
recalls a vault-readable research note and checks MCP `initialize`.
It needs no account, dashboard, external API key, model, embedding service,
or interactive pairing. It does not download a binary.

The `--binary` option skips compilation. Without it, Linux builds this checkout
with Cargo's release profile. In one Linux x86-64 test, a one-job install with
partly cached build artifacts took about 2 h 7 min and peaked at about 37.2 GiB.
A cold parallel attempt was killed at a 40 GiB cap. A successful cold build and
a 16 GiB source install were not demonstrated.

## Prerequisites

- Python 3.11 or newer.
- `curl` 7.76 or newer on `PATH` (used by `oneiron api`).
- For source installation: Git, Rust through rustup, a native C/C++ compiler,
  CMake, and pkg-config. `rust-toolchain.toml` pins the Rust toolchain; rustup
  selects/downloads it when Cargo runs in the checkout.

On macOS, pass `--binary` with a build from this checkout signed with a keychain
access group. With the default `backend = "platform"`, a plain `cargo install`
binary cannot mint the agent credential: macOS uses the data-protection
keychain, with no automatic file fallback. Such a build can opt into
`[keystore] backend = "file"` in its own config, which keeps the key slots as
0600 files in `dir`, guarded by file modes only (see the `[keystore]` section of
`crates/oneiron-server/README.md`). The demo does not choose that for you.

On Debian/Ubuntu, the source-build dependencies include `build-essential`,
`clang`, `cmake`, `pkg-config`, `git`, `curl`, and `python3`. The example never
requests sudo or installs OS packages.

If rustup is missing, its documented noninteractive installer is:

```sh
curl --proto '=https' --tlsv1.2 -fsSLo /tmp/oneiron-rustup-init.sh https://sh.rustup.rs
sh /tmp/oneiron-rustup-init.sh -y --profile minimal --default-toolchain none
```

On Linux, omit `--binary` to build this checkout. The example finds Cargo's
default bin directory without needing a new login shell.

Contributors to this repository: the build rules are in [AGENTS.md](../AGENTS.md).

## What the script does

1. Creates a new owner-only directory, printed as `Setup directory`. Pass
   `--directory /absolute/new/directory` to choose it. An existing directory is
   refused, never overwritten. Without the option it uses the OS temp directory,
   so choose a durable directory for memory you want to keep.
2. Installs `oneiron` under that directory's `install/bin` unless `--binary` is
   supplied. It runs `cargo install --locked --path crates/oneiron-server --bin
   oneiron --root <directory>/install` from the repository root.
3. Chooses an unused loopback port and writes a private `oneiron.toml` with a
   random host authentication secret. It ignores inherited `ONEIRON_*`
   variables and uses only the new vault and its config.
4. Runs `oneiron init <directory>/vault --config <directory>/oneiron.toml
   --embedder none --oneironer none`. Both choices are explicit; init cannot
   prompt or download a model.
5. On the stopped vault, runs `oneiron token agent --name agent-quickstart
   --tier full-access --out <directory>/agent.cred --config
   <directory>/oneiron.toml`. This creates an agent-bound slip, binding seed,
   and the agent's grant. It does not require an owner pairing-link click.
6. Starts `oneiron serve --config <directory>/oneiron.toml`, with logs in
   `server.log`, and waits up to 60 seconds for `/api/health`.
7. Saves a private diary NOTE with `POST /v1/core/facade/self.memory.diary`
   and reads it back from its private diary with
   `POST /v1/core/facade/self.memory.diary.query`. The script passes the minted
   agent's ID and a one-line reason, then checks the returned Markdown and
   entry ID. Ordinary `vault.recall` does not return diary entries.
8. Writes a vault-readable research NOTE with
   `POST /v1/core/facade/vault.notes.create`, then calls
   `POST /v1/core/facade/vault.recall` with `effort: "light"`. It checks the
   matching text and the saved NOTE's ID in the result's provenance. This is
   lexical recall, not semantic/vector recall. It does not promote a claim
   or change the vault's claim policy.
9. Connects through `oneiron mcp --surface tool-first --credential-file
   <directory>/agent.cred --url <origin>` and checks its MCP `initialize` reply.
   This surface needs no code executor or model configuration.

The demo sets `[keystore] backend = "platform"` in its fresh config. The issuer
needs this keystore to mint the agent credential. On Linux, `dir` puts key
slots in 0600 files in a 0700 directory beside, not inside, the vault. This is
software protection, not a hardware keystore. It does not ask for a keychain
login; backup tools skip the directory only if they honour `CACHEDIR.TAG`.
On macOS `dir` is ignored. The signed binary uses the data-protection keychain.
HTTP authentication stays on.

Without `--keep-running`, the script stops its server after the round trip.
With it, the server runs in its own session, its PID is printed, and the agent
can use it immediately. Failures after startup stop only the process the
example started; they do not kill any existing server.

Expected output includes these lines (paths, port, ids and text vary):

```text
Read back from its private diary: <32-hex entry id>
Saved and recalled research note: <32-hex note id>
MCP connected. Client config: <directory>/mcp.json
MCP protocol: 2024-11-05
Connection details: <directory>/connection.json
Vault remains running at http://127.0.0.1:<port>. Stop it with: kill <pid>
```

## Connect your coding agent

`connection.json` contains the absolute binary, config and credential paths,
URL, PID, log path, the diary agent and entry IDs, and the research note ID
and recall query.
`mcp.json` contains a `mcpServers.oneiron` entry with absolute paths.
Do not commit these local files: `agent.cred` holds a paired credential and
`oneiron.toml` holds the host authentication secret.

- **Claude Code:** merge the generated `mcpServers.oneiron` entry into the
  project's `.mcp.json`, or use the already-documented
  [Claude Code command](ops/connect-an-agent.md#2-add-it-to-the-agent). Use the
  generated absolute binary path, URL, and credential path, not bare `oneiron`
  if it is not on `PATH`.
- **Codex:** in its `config.toml`, put the generated `command` and `args` under
  `[mcp_servers.oneiron]`. Paths in `args` must be absolute.
- **OpenCode:** in its `opencode.json`, place a local server under
  `mcp.oneiron`: `{"type":"local","command":["<absolute binary>","mcp",
  "--url","<origin>","--surface","tool-first","--credential-file",
  "<absolute credential path>"],"enabled":true}`. These are Oneiron CLI
  arguments, not extra OpenCode CLI flags.

No client-specific configuration is modified automatically. The script has
already connected and performed the memory round trip without any such edit;
these entries tell an ongoing client how to keep using that vault.

The tool-first MCP endpoint lists the memory verbs in `tools/list`. Use the
input schema it returns for each `tools/call`. The MCP schema has an envelope
with `schema_version`, `consent`, and `arguments`; do not send an HTTP body as
MCP tool arguments. The paired credential binds the actor.

For HTTP, send each body directly (no MCP envelope):

For a private entry, use your own 32-hex principal ID (`principal_ref` from
`oneiron token agent --out`) and give a one-line read reason.

```text
POST /v1/core/facade/self.memory.diary
{"content":"Private project note."}

POST /v1/core/facade/self.memory.diary.query
{"agent":"<agent id>","reason":"Read my project note"}
```

For an entry that ordinary recall can find, create a vault-readable research
NOTE and search for words from it.

```text
POST /v1/core/facade/vault.notes.create
{"kind":"research","markdown":"Orchard project note."}

POST /v1/core/facade/vault.recall
{"query":"orchard","effort":"light","limit":5}
```

Use `oneiron api --base-url <origin> raw POST <path> --data -` with the JSON
body on stdin. The example reads `agent.cred` into `ONEIRON_SECRET` (the paired
slip) and `ONEIRON_BINDING_KEY` (its binding seed) in the child environment.
`oneiron api` signs the holder proof and does not put either secret in argv.
A raw curl call with a bearer alone is not equivalent: it lacks the fresh
holder proof. The script is the complete HTTP client example; no crypto SDK
or hand-written signature code is required.

## Remote MCP with OAuth: cloud agents

A cloud agent that runs on its vendor's servers, such as Grok Bot or Muse,
cannot start `oneiron mcp` or hold a paired credential. It connects by URL
instead: it adds `https://<vault-host>/mcp` and signs in at the vault's own
OAuth 2.1 server (protected resource metadata, dynamic client registration,
PKCE S256 and the `/mcp` resource). The vault owner allows each sign-in once,
in the inbox, at a tier and optionally in one world. The app's bearer token
maps to that grant at the vault and never carries a slip or a key, and
`vault.consent.registry` revokes it.

The vault needs a public https origin as its OAuth identity:
`oneiron serve --oauth-resource-indicator https://<vault-host>`. Without it
every OAuth route answers 404.

- [Connect Grok Bot](connect/grok-bot.md)
- [Connect Muse](connect/muse.md)

A local coding agent keeps the paired credential above: it signs every call
with its holder proof.

## Owner mode: MCP as the vault's owner

Everything above connects an agent with its own delegated credential, the
paired slip `token agent` mints for that agent's grant. That remains the way
to connect an agent. `oneiron mcp` also has a separate owner mode, for the
vault's owner himself, when a surface he has signed in on issues his sign-in
for that vault:

```sh
oneiron mcp --url https://<vault-host> --auth-mode owner \
  --owner-upgrade-headers-file /absolute/path/to/owner-upgrade-headers.json
```

- **The file** holds one JSON object of header names to text values, exactly
  as the issuing surface wrote it: `{"<header name>": "<value>", ...}`. For a
  managed vault it is the human sign-in the vault's proxy already honours;
  the proxy then attests the owner to his vault itself. The bridge sends
  these headers on the socket's upgrade in place of a slip and holder proof,
  and its calls carry no holder proof.
- **Owner-only:** only its owner may be able to read the file (mode `0600`,
  no ACL entry). The bridge checks this at spawn and again before every new
  socket, and refuses a group- or world-readable file, saying so.
- **Refresh:** the file is read again for every new socket, so the issuer can
  replace an expired sign-in in place (write a new file, then rename it over
  the old one). An open socket keeps the identity it opened with.
- **Refused headers:** the file may not name `Host`, the upgrade's framing and
  hop-by-hop headers (`Connection`, `Upgrade`, any `Sec-WebSocket-*`,
  `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Keep-Alive`,
  `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization`), a slip's
  holder proof `x-oneiron-binding`, an MCP connector credential
  `x-oneiron-mcp-credential`, or the supervisor attestations
  `x-oneiron-managed-owner-action` and `x-oneiron-managed-widen-action`, which
  only the vault's proxy makes after checking his sign-in. Nor may any value
  carry a slip (`v2.slip.` or `v2.cred.`). Such a file is refused whole, by
  the header's name; no value is ever printed.
- **No slip beside it:** `--credential-file`, or a value in the variables
  `--secret-env` and `--binding-key-env` name (`ONEIRON_SECRET` and
  `ONEIRON_BINDING_KEY` by default), is refused in owner mode. Unset them, or
  set them empty, for the bridge's process.
- **Socket only:** owner mode rides the server's socket alone; `--transport
  http` is refused and nothing falls back to HTTP. A refused or unreadable
  sign-in is `mcp_auth_required`: sign in again on the issuing surface so it
  rewrites the file. A server that offers no MCP socket is
  `mcp_socket_unavailable`.
- **Issuer required:** Oneiron itself does not mint or refresh this file.
  Something the owner signs in on (a console, or the identity tooling in
  front of his vault) must write it and replace it before the sign-in
  expires. Without such an issuer, owner mode has nothing to send; connect
  with an agent credential as above.

## Stop, restart, and repair

- **Stop:** run the printed `kill <pid>` command. Vault data remains in the
  setup directory. A temporary directory can still be removed by the OS.
- **Restart:** use the absolute `binary` from `connection.json` with
  `serve --config <config>`. Remove inherited `ONEIRON_*` overrides first,
  as the example does. Keep the same config and credential.
- **Missing binary:** omit `--binary` to install the checkout, or pass the
  absolute executable path. Adding an unrelated release binary to `PATH`
  does not replace the checkout installation by default.
- **Missing/old curl:** install curl 7.76 or newer and make it the first curl
  on `PATH`. Both the HTTP CLI and MCP bridge require it.
- **Vault not started / `server_unreachable`:** read `server.log`, start
  `serve --config <config>`, and use its exact URL from `connection.json`.
  The MCP bridge connects; it does not start a vault.
- **Port in use:** do not kill an unknown listener. Use a new setup directory
  (a fresh run chooses a free port), or change `port` in this vault's config
  and the URL in your client config together.
- **Writer lease held:** do not run init or token minting against a vault
  while it is served. Stop that vault, mint, then restart it.
- **401, 403, or `mcp_auth_required`:** check the URL and credential refer to
  the same vault. The host `auth_secret` is **not** an agent bearer token.
  For an expired/revoked slip, stop this vault, run `token agent` with the same
  name/tier/config and a new `--out` file, restart, and update the client path.
  The latest mint for a name revokes that name's previous slips. In owner
  mode, minting a slip does not help: sign in again on the surface that
  wrote `--owner-upgrade-headers-file`.
- **`proof_clock_ahead`:** follow the clock-specific recovery instructions in
  [owner actions](ops/owner-actions.md#agents-refused-after-the-host-clock-ran-ahead),
  rather than repeatedly replacing credentials.
- **File permissions:** keep the credential owner-only (mode `0600`, with
  no ACL granting another user access). `token agent --out` writes it that way.
  Use a new `--out` path when replacing a credential; it never overwrites a file.
  On an NFSv4 home the server's list counts too: an entry that grants anyone
  but `OWNER@` read or write refuses the file, and the refusal names it
  (`nfs4_getfacl` lists the entries). A credential on an SMB mount, or on an
  NFSv4 mount that reports no list (a server without list support), is
  refused, because this host does not read the server's list, unless the host
  owner sets `ONEIRON_CREDENTIAL_FILES_TRUST_NETWORK_FS_ACL=1`: every user that
  list admits can then read the credential. On an NFSv3 mount the mode decides,
  as on a local file system, because its server enforces the mode bits.

No running user service, browser, or third-party model is required. This path
creates one isolated vault; production hosting, service managers, private
worlds, and model provisioning are separate choices.
