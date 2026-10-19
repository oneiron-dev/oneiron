# Unattended agent setup

From a checkout, on Linux or macOS:

```sh
python3 examples/agent-quickstart/quickstart.py --keep-running
```

This is the install → start → connect → save → retrieve path for a coding agent.
It needs no account, dashboard, API key, model, embedding service, or interactive
pairing. The script builds **this checkout**, not an assumed published release.
A source build can take several minutes; this is not a five-minute build claim.

## Prerequisites

- Python 3.11 or newer.
- `curl` 7.76 or newer on `PATH` (used by `oneiron api`).
- For source installation: Git, Rust through rustup, a native C/C++ compiler,
  CMake, and pkg-config. `rust-toolchain.toml` pins the Rust toolchain; rustup
  selects/downloads it when Cargo runs in the checkout.

On a Debian/Ubuntu build host, the native tools can be installed without package
prompts with `sudo apt-get install -y build-essential clang cmake pkg-config git
curl python3`. This requires an already-authorized administrator; the example
never requests sudo or installs OS packages. On macOS, Command Line Tools must
already be installed; the example never opens an installer or a browser.

If rustup is missing, its documented noninteractive installer is:

```sh
curl --proto '=https' --tlsv1.2 -fsSLo /tmp/oneiron-rustup-init.sh https://sh.rustup.rs
sh /tmp/oneiron-rustup-init.sh -y --profile minimal --default-toolchain none
```

The example finds the default Cargo install directory without needing a new
login shell. With an existing binary from this checkout, skip the build:

```sh
python3 examples/agent-quickstart/quickstart.py --binary /absolute/path/to/oneiron --keep-running
```

Repository contributors must still follow the build-host rules in
[AGENTS.md](../AGENTS.md): do not run a source build on the owner's Mac.

## What the script does

1. Creates a new owner-only directory, printed as `Setup directory`. Pass
   `--directory /absolute/new/directory` to choose it. An existing directory is
   refused, never overwritten. Without the option it uses the OS temp directory,
   so choose a durable directory for memory you want to keep.
2. Installs `oneiron` under that directory's `install/bin` unless `--binary` is
   supplied. It runs `cargo install --locked --path crates/oneiron-server --bin
   oneiron --root <directory>/install` from the repository root.
3. Chooses an unused loopback port and writes a private `oneiron.toml` with a
   random host issuer secret. It ignores inherited `ONEIRON_*` variables for all
   child commands, so it cannot accidentally use an existing vault or model.
4. Runs `oneiron init <directory>/vault --config <directory>/oneiron.toml
   --embedder none --oneironer none`. Both choices are explicit; init cannot
   prompt or download a model.
5. On the stopped vault, runs `oneiron token agent --name agent-quickstart
   --tier full-access --out <directory>/agent.cred --config
   <directory>/oneiron.toml`. This creates an agent-bound slip, binding seed,
   and the agent's grant. It does not require an owner pairing-link click.
6. Starts `oneiron serve --config <directory>/oneiron.toml`, with logs in
   `server.log`, and waits up to 60 seconds for `/api/health`.
7. Saves a private diary NOTE with `POST /v1/core/facade/self.memory.diary` and
   retrieves it with `POST /v1/core/facade/vault.recall`, using `effort: "light"`.
   It checks both the recalled text and the saved entry's provenance id before
   reporting success. This is lexical recall, not semantic/vector recall. It
   neither promotes a generated claim nor changes the vault's claim policy.
8. Connects through `oneiron mcp --surface tool-first --credential-file
   <directory>/agent.cred --url <origin>` and checks its MCP `initialize` reply.
   This surface needs no code executor or model configuration.

The demo sets `[keystore] backend = "off"` **only in its fresh config**, avoiding
OS keychain prompts. Device signing and private-world key doors are unavailable
in this demo. It does not turn off HTTP authentication. For a real vault that
needs those doors, configure the platform keystore separately.

Without `--keep-running`, the script stops its server after the round trip.
With it, the server runs in its own session, its PID is printed, and the agent
can use it immediately. Failures after startup stop only the process the
example started; they do not kill any existing server.

Expected output includes these lines (paths, port, ids and text vary):

```text
Saved and recalled memory: <32-hex entry id>
MCP connected. Client config: <directory>/mcp.json
Connection details: <directory>/connection.json
Vault remains running at http://127.0.0.1:<port>. Stop it with: kill <pid>
```

## Connect your coding agent

`connection.json` contains the absolute binary, config and credential paths,
URL, PID, log path, memory id and recall query. `mcp.json` contains a ready
`mcpServers.oneiron` entry with absolute paths. Do not commit these local files:
`agent.cred` holds a paired credential and `oneiron.toml` holds the issuer secret.

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

The agent first calls `tools/list`. The tool-first endpoint exports the same
verb names as HTTP. It can save another diary entry with:

```json
{"name":"self.memory.diary","arguments":{"spec":{"content":"Remember this project note."}}}
```

Then call `vault.recall` with
`{"spec":{"query":"project note","effort":"light","limit":5}}` as its
arguments. These are the `params` of an MCP `tools/call`. Do not invent an
`actor` block; the credential binds the actor. Diary entries are private to
that agent principal, so a different agent name does not share this diary.

For HTTP, the exact same inputs have **no `spec` wrapper**:

```json
POST /v1/core/facade/self.memory.diary
{"content":"Remember this project note."}

POST /v1/core/facade/vault.recall
{"query":"project note","effort":"light","limit":5}
```

Use `oneiron api --base-url <origin> raw POST <path> --data -` with the JSON
body on stdin. The example reads `agent.cred` into `ONEIRON_SECRET` (the paired
slip) and `ONEIRON_BINDING_KEY` (its binding seed) in the child environment.
`oneiron api` signs the holder proof and does not put either secret in argv.
A raw curl call with a bearer alone is not equivalent: it lacks the fresh
holder proof. The script is the complete HTTP client example; no crypto SDK
or hand-written signature code is required.

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
  as the example does. Keep the same config/issuer secret and credential.
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
  the same vault. `auth_secret` is an issuer key, **not** a bearer token.
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

No running user service, browser, or third-party model is required. This path
creates one isolated vault; production hosting, service managers, private
worlds, and model provisioning are separate choices.
