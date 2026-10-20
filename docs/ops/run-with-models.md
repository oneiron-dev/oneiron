# Run the server, with or without models

`oneiron serve` needs no model. Capture, search, reopen, export and backup all
work on a fresh vault with nothing configured. Models attach afterwards as
config, in a `[models]` section of the same `oneiron.toml`. One edit swaps
the model behind any seat, and no model or vendor is named in code.

## 1. No model

```bash
export ONEIRON_AUTH_SECRET="$(openssl rand -hex 32)"   # host root; the Dreamer needs it later
oneiron init ~/oneiron/vault --config ~/.config/oneiron/oneiron.toml --embedder none
oneiron serve --config ~/.config/oneiron/oneiron.toml
```

`GET /api/health` reports `"ai": {"dreamer": "idle", "dreamer_reason": "no_model_configured", "compaction": "off", "compaction_reason": "no_model_configured"}`.
Chat answers `503 no_model_configured`, and nothing that needs no model waits on one.

## 2. Point a seat at a model

Each provider is one entry of data. Pick any of the three levels below. HIGH
and MID are shorthands that expand to the DETAILED form, and a role written
out in DETAILED replaces what a shorthand gave it.

```toml
# HIGH: one model for every seat (chat and agents, checks, the Dreamer).
[models]
default = "cpa:olety7/gpt-6.1-sol"     # "<provider>:<the provider's own model id>"
prompt = "Answer briefly."             # optional; or prompt_file = "rung.md"

[models.providers.cpa]
kind = "openai-compat"
base_url = "http://127.0.0.1:8317"     # with or without a trailing /v1
key_env = "CPA_API_KEY"                 # the variable's NAME; never the key itself
```

```toml
# MID: a local stack and a cloud, local first. `local` also fills local_reasoner.
[models]
local = "exl3:qwen3.8-27b"
cloud = "router:anthropic/claude-sonnet-4.5"
prefer_local = true                     # false puts the cloud rung first

[models.providers.exl3]                 # any local OpenAI-compatible server: exllamav3, llama.cpp `llama-server`, vLLM, MLX `mlx_lm.server`
kind = "local-openai-compat"
base_url = "http://127.0.0.1:8080"
response_format = "none"                # JSON calls go out without a schema, as the EXL3 recipe below runs

[models.providers.router]               # OpenRouter, or any OpenAI-compatible endpoint
kind = "openai-compat"
base_url = "https://openrouter.ai/api"
key_env = "OPENROUTER_API_KEY"
```

```toml
# DETAILED: one role's ladder, rung by rung. A rung that fails hands the call
# to the next; each rung may carry its own prompt.
[models.roles.dreamer_current]
rungs = [
  { model = "exl3:qwen3.8-27b", prompt_file = "prompts/dreamer-local.md" },
  { model = "llama:qwen3.8-27b-q4" },   # the fallback recipe, below
  { model = "claude:claude-sonnet-4-5" },
]

[models.providers.llama]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:8081"

[models.providers.claude]               # any Anthropic-compatible /v1/messages server
kind = "anthropic-compat"
base_url = "https://api.anthropic.com"
key_env = "ANTHROPIC_API_KEY"
```

The local Dreamer model the examples name is the measured recipe for the
Dreamer's seat: Qwen3.8-27B as EXL3 4 bpw (`turboderp/Qwen3.8-27B-exl3`) with
the DFlash2 5 bpw draft (`Mia-AiLab/Qwen3.8-27B-DFlash2-EXL3-5.0bpw`, at
depth 7, the owner's ruling of 2026-10-16 for every workload), served by an
exllamav3 OpenAI-compatible server with no schema:
its provider sets `response_format = "none"`, so a JSON call goes out with
no `response_format`. The fallback is llama.cpp `llama-server` on
`Qwen3.8-27B-UD-Q4_K_M.gguf` with the `Qwen3.5-0.8B-Q8_0.gguf` draft
(`--spec-type draft-simple --spec-draft-n-max 8`). `deploy/house-model/`
ships both servers, one per GPU, as systemd units, and the `[models]` block
that binds them (`models.toml`): the generative seats try EXL3 first and fall
back to llama.cpp, and `local_reasoner` is the llama.cpp server alone, so the
decision read (section 9) runs on the house weights. The Dreamer's extraction
call sends no schema on any provider: a grammar built from one can strip the
claim fields, so the engine checks the answer against the extraction
contract itself, and an answer that breaks it is refused. Other JSON calls,
such as the conflict verdict, send their schema unless the provider sets
`response_format = "none"`; the engine checks the answer against it either
way. A ladder sends a schema in `response_format` only when every rung declares
`json_response`. A rung without it, such as the Anthropic-compatible one in
the DETAILED example, makes the engine put the schema in a system message on
every rung instead, so keep a schema-constrained llama.cpp fallback in a
ladder of OpenAI-compatible rungs. Typed decisions go through decide()
(ARCH-0076): the System One slot answers first, and its escalation rung reads
the `local_reasoner` model in decision-read mode (section 9).

Role keys are the model manifest's (ARCH-0036): `generative_reasoner` (chat and
saved workflows), `local_reasoner`, `checker`, `dreamer_current`,
`dreamer_target`, `extraction_encoder` (a tagger, `kind = "oneironer"`), and the
rest of the manifest list. `coach` is the Coach's own seat (agent-health asks,
code-fix drafts, session-end distill); HIGH and MID leave it unset, and with no
`[models.roles.coach]` the Coach rides `generative_reasoner`. The retrieval
embedder stays in `[embedder]`, where
`provider = "endpoint"` takes any OpenAI-compatible `/v1/embeddings` server.

Provider fields: `kind` (`openai-compat`, `anthropic-compat`,
`local-openai-compat`, `oneironer`, and the speech-only `cartesia`,
`elevenlabs` and `voxcpm2`), `base_url`, `key_env` or `key_secret`, `headers`
(non-credential only), `timeout_secs` (120), `context_tokens` (128000),
`max_output_tokens`, `output_limit_field`, `response_format` (`schema`, the
default, or `none`; OpenAI-compatible providers only), `capabilities` (`streaming`,
`json_response`, `tool_calling`, `tool_results`, `image_input`, `audio_input`,
`assistant_prefill`, `reasoning`; `assistant_prefill` lets Continue send the
saved reply as an open trailing assistant message instead of an instruction to
go on, and only counts when every rung of the ladder has it: list it only for a
model whose endpoint and serving template continue a trailing assistant message
(no model has it by default); `audio_input` sends a chat message's audio clips as `input_audio`,
WAV or MP3, on OpenAI-compatible providers only, and no provider has it unless
the list says so; a `local-openai-compat` provider declares `streaming`, `json_response` and
`reasoning` unless the list is written out), `model_capabilities` (one wire
model's own list in place of `capabilities`, keyed by the model's name, so
two models on one provider can differ: `model_capabilities = { "gpt-audio" =
["streaming", "audio_input"] }`; the Big rung hears a clip only on a model
whose list has `audio_input`), `family` (the line of models one developer
trains, for every model on the provider; unset, a model's family is unknown,
never read off the provider's name), `model_families` (one wire model's own
family in place of `family`: `model_families = { "claude-opus-5-5" = "claude",
"gpt-6.1" = "gpt" }`; a judge's tie-breaker is asked only of a model whose
family neither judge has),
`locality` (`own_server` or `third_party`), `revision` (`live`),
`responses_socket` and `request_compression` (both below). Plain
`http://` is accepted only for this machine, or for a `local-openai-compat`
server on the private network.

A `key_secret` names a vault secret instead of a variable: the key stays in
the vault's custody (T0), and only the credential broker sends it. The broker is
a separate process that runs as its own OS user, adds the key to one request,
sends it once over verified TLS (no redirect, no retry, no proxy) and strips the
key from the reply. Each call reads the key at the custody door, so register the
secret with a binding for the effector `broker:model` at T0 (doored). Run
the broker with `oneiron-broker serve --socket <path> --client-uid <the
server's uid>` (add `--extra-roots <pem>` for a private CA), and name it:

```toml
[models.broker]
socket = "/run/oneiron-broker/broker.sock"   # absolute; its directory is the fence
uid = 991                                    # the broker's user, never the server's

[models.providers.paid]
kind = "openai-compat"
base_url = "https://api.example.com"         # https only
key_secret = "provider-key"
```

Where no separate user exists, as on macOS, leave out `socket` and `uid`: the
server then starts the broker as its own child, under its own user, at the first
`key_secret` call. The child makes itself non-dumpable (`PT_DENY_ATTACH` on
macOS), so another process of that user cannot read or trace its memory. It
binds no socket file: it takes calls only over a socket pair the server made when
it started it, so it serves that server alone. Its calls' receipts say
`same_user`, and the provider's entry in the model status carries
`"unproven": true`, the badge: another process of that user can still stop the
child, reach the server's own descriptors, or open the child's memory in the
moment it starts, before it closes itself. A separate user stays the first
choice. The child is the `oneiron-broker` beside the server's binary, or:

```toml
[models.broker]
program = "/opt/oneiron/bin/oneiron-broker"   # absolute
extra_roots = ["/etc/oneiron/private-ca.pem"] # optional, absolute
```

A declared run's paid keys must sit at T0, so its teacher calls go out this way.
A `key_secret` provider answers whole chat replies only for now: a streamed chat
call to it is refused before it starts. Its media calls go through the same
broker (§10).

A self-hosted `serve` takes `--settings-file <path>` too: a TOML file in its
config file's schema, read as one more config file over `--config` and under
the environment and the flags, with none of the managed refusals below.

A managed vault (`serve --managed-by-hypnos`) reads no environment and no
config file of its own. Its supervisor passes the owner's settings as one file,
`--settings-file <path>`: an absolute path to a TOML file in the same schema as
a self-hosted server's config file, `[models]`, `[embedder]` and `[gpu]` (§12)
included. A vault VM finds it at `/config/settings.toml` on its config drive.
The file is read once at start, before anything else reads the configuration,
and it is the vault's one settings layer. Each section the owner sets
(`[limits]`, `[connectors.<name>]`, `[native_mail]`, `[browser]`, `[desktop]`,
`[oneironer]`, `[embedding]`, `[self_heal]`, `[recall]`, `[skills]`,
`[failure_signals]`, `[feedback]`, `[runtime]`, `[linear]` and the rest) works
as it does on a self-hosted server. The `[linear]` mirror starts before the
vault reports ready (settings it cannot use stop the start), admits each pass
like a served write, and reads its API key or bridge token at each pass from
the vault secret `api_key_secret` or `bridge_token_secret` names, bound to
`connector:linear`; a direct mirror keeps its response custody in
`<data_dir>.linear-responses` (`/vault/storage/data.linear-responses` in the vault VM),
made private at start. A value the supervisor also passes on argv
(`--dimensions`, `--fast-dims`, `--map-size`, `--log-level`,
`--dict-search-paths`, `--assistant-display-names`, `--maximum-tier`,
`--failure-signal-export`, `--failure-signal-training`) keeps the supervisor's
value.

Some leaves stop the vault at start, by their presence alone (an empty value,
`false` or the supervisor's own value too), with a typed `SettingsRefused` that
names the field and never its value:

- the supervisor's bindings (`SupervisorOwned`): `vault_path`, `host`, `port`,
  `artifact_port`, `auth_secret`, the `oauth_*` fields,
  `kit_bundle_public_urls`, `allow_unauthenticated`, `allowed_origins`,
  `artifact_domains`, `artifact_vault_name`, `trusted_proxies`,
  `lease_vault_id`, `privacy_posture`, `hosted_kms_key_ref`, `device_class`,
  every `[models.broker]` key, `[models.voice] socket`, `[keystore] dir` and
  `[linear] response_dir`, which the vault derives itself. A managed vault's
  artifact origin answers on its internal authority alone
  (`<vault_id>.artifact.invalid`); the edge checks public labels and composes
  public URLs.
  The supervisor passes the voice loop's socket as `--voice-socket`, the key
  directory as `--keystore-dir`, the host's public https origin as
  `--oauth-resource-indicator <url>` and the URLs a recovery kit dials as
  `--kit-bundle-public-urls <url>,<url>` (comma-separated; without it a kit
  fetch is checked against the origin alone). A vault VM reads those two from
  the one-line files `/config/oauth-resource-indicator` and
  `/config/kit-bundle-public-urls` on its config drive. Neither builds an
  auth layer: `--oauth-issuer` and `--oauth-jwks-uri` stay refused. The
  tables of these leaves and of the `EnvironmentSecret` ones below, and the
  rule that matches a field against them (`*` is any one key), are
  `SUPERVISOR_OWNED`, `ENVIRONMENT_KEYS` and `matches_any` in
  `oneiron_vault_contract::settings_policy`, which the supervisor reads too.
- a key named by an environment variable (`EnvironmentSecret`): a provider's
  or System One's `key_env`, both embedder `api_key_env` keys, `[gpu]
  api_key_env`, `[runtime] byo_key_env`, and a `byo_cloud_key` runtime mode,
  which reads one. A provider names its key with `key_secret`, a secret held in
  the vault that the credential broker sends.
- a key the schema does not have (`UnknownField`).
- an owner path outside the vault (`OutsideVault`): every path in the file
  (prompt files, the decision recipe, the code-mode prompt package and `tsc`,
  tagger and embedder model directories, publisher candidate files, dictionary
  roots, import and backup folders, the device-sync credential file, the guest
  runtimes) must be absolute, hold no `~` or `..`, exist, and lie under the
  vault's data directory or the settings file's own directory once its links
  are resolved. A tagger model directory (`[oneironer] model_dir` and each
  tier's) may instead be its bundle's own directory in the node's read-only
  shared model root, `<root>/oneironer/<stack_sha16>/` (managed only, below),
  named by the `stack_sha16` the settings pin beside it and by its manifest.
  The refusal names the finer cause after the reason (`shared_model_layout`,
  `shared_model_stack`, `shared_model_unsafe`, `bundle_stack_mismatch` and
  the like). An import queue with no `claude_code_root` and `codex_root` of
  its own would read the defaults under HOME, so it stops the vault too.

The supervisor binds eight more settings on argv alone; a settings file that
names `browser_runtime`, `desktop_runtime`, `organ_dir`, `mesh_bind`,
`mesh_relays`, `shared_model_root`, `container_home` or
`container_runtime_dir` is refused `SupervisorOwned`:

- `--browser-runtime <path>` and `--desktop-runtime <path>`: the browser and
  desktop guests' container CLI, an absolute path on the vault's own host or
  root filesystem. Each stands as the `runtime` of the owner's `[browser]` or
  `[desktop]` section, which may then leave `runtime` out. The owner's section
  still turns the guest on and picks its image and bounds; the flag alone turns
  on no guest, and the guest still needs an isolating host. An owner's own
  `runtime` inside the vault's storage works as before without the flag.
- `--organ-dir <path>`: where pack organ builds, the seal's among them, are
  written, on the tenant's own storage; without it, `<data_dir>/organs`. It is
  made private at start. A managed vault never reads `ONEIRON_ORGAN_DIR` and
  never writes them to the OS temp directory.
- `--mesh-bind <ip:port>` and `--mesh-relays <url>,<url>`: the paired-machine
  mesh listener's bind and private relays (device-sync.md); without a bind the
  mesh is off. A managed vault never reads `ONEIRON_MESH_*`.
- `--shared-model-root <path>` (managed only, never a vault VM): the node's
  read-only shared model root, where the supervisor installs each model
  bundle once for every vault at `<root>/oneironer/<stack_sha16>/`. The root
  and every directory above it must be owned by root and writable by no group
  or other. A root that fails its check is ignored, logged
  `shared_model_root_ignored` with its cause (and named in a settings refusal
  that ends the start before logging begins), never a refused start; a model
  directory only it would admit is then refused `OutsideVault`.
- `--container-home <path>` and `--container-runtime-dir <path>` (managed
  only, never a vault VM): the `HOME` and `XDG_RUNTIME_DIR` the guests'
  container CLI runs with, so a rootless CLI under the vault's UID finds its
  per-UID storage and runtime directory. Each must be an absolute path with
  no `..` part and an existing directory owned by the vault's UID; the
  supervisor makes both, the vault makes neither. One that fails its check
  is ignored, logged `container_dir_ignored` with its `flag` and `cause`
  (`not_absolute`, `parent_component`, `missing`, `not_directory`,
  `not_owned`, `unreadable` or `unsupported`), never a refused start. An
  engine from before these flags refuses them, so a supervisor passes them
  only to engines at or after the merge that added them.

The container CLI gets `HOME` and `XDG_RUNTIME_DIR` from these two flags
alone. Every call the engine makes to it for a guest (run, inspect and
removal) otherwise runs with `PATH=/usr/bin:/bin` and nothing else, as on a
self-hosted server, and a flag that is absent or ignored leaves its variable
out. The engine itself still reads no HOME or XDG directory.

A vault VM reads the guest runtimes and the mesh settings from the one-line
files `/config/browser-runtime`, `/config/desktop-runtime`, `/config/mesh-bind`
and `/config/mesh-relays` on its config drive.

A `local` embedder names its files with `model_dir` or `models_dir`, because
the XDG data root is never read. A keystore lives in the supervisor's
`--keystore-dir` alone, since one without it would be looked for under HOME:
without the flag none is opened, and unless the file sets `[keystore] backend
= "off"` the vault serves degraded (below). Every embedding, tagging and other
background pass runs under the vault's write admission, so a vault frozen for
reap fills nothing until it thaws. Without the file a managed vault runs on the
defaults: no model seats (its ladder is the rule table and the owner's asks),
no embedder (lexical and graph recall only) and no tagger. Its log starts
before the file is settled, at the level it settles to (`--log-level` over the
file's `log_level`). A file with `[models.voice]` and no `--voice-socket` runs
no voice loop, logged once with the reason `voice_socket_missing`; live voice
sessions still run.

A managed vault reports how it came up on every ctl `Ping`, as `readiness`
(contract v3): `{"state":"ready"}`, or `{"state":"degraded","missing":[...]}`
naming each signing facility it serves without, as `{"facility","reason"}`:
`keystore_directory` with `missing_binding` (no `--keystore-dir`, and the owner
did not turn the keystore off), `device_keystore` with `open_failed`,
`install_signing_keys` with `prepare_failed`, or `host_node_profile` with
`profile_failed`. It is a snapshot taken at start, also logged once before the
vault reports ready, with the reason `managed_facility_missing`. A degraded
vault still serves and sends the same ready byte: reads and sync go on, and
the signing and world-key doors refuse as they do without a keystore. An owner
who set `backend = "off"` gets `ready`.

The supervisor gives a vault its publisher training outbox (OF-420, "Learn from
my conversations") as `--publisher-training-outbox-dir <vault>/training-outbox`,
an absolute path, on argv only: a settings file that names
`publisher_training_outbox_dir` is refused `SupervisorOwned`. The vault keeps
three subdirectories there, `offers/`, `controls/` and `receipts/`
(`oneiron_vault_contract::conversation_training`), and reads the intake's keys
from `intake-recipient.v1` (every offer chunk is sealed to it) and
`intake-receipt-key.v1` (every receipt is checked against it). Without the
recipient key it writes no offer, logs offers as unavailable naming the missing
file, and still writes withdrawals; without the receipt key it applies no
receipt. Offers wait for the vault's admission like every background pass;
withdrawals the vault already recorded are written even while it is frozen for
reap, and stay shippable from a cold vault. The supervisor binds the registry
vault id and the node's bearer when it ships: the files name no vault, only each
month's scope and codes, with the install's signature for the intake to check
and discard. The vault also keeps `scopes/training-scopes.v2.json`, every scope it
used with its receipt cursor, rewritten whole when either changes, for the node
to pull receipts by scope. `scopes/` is the vault user's own directory: a managed
node makes it ahead of time and keeps the outbox root, which holds the intake's
keys, unwritable by the vault. Before an erase the supervisor sends `training_purge`
on the ctl socket: the vault records one purge per scope and answers
`not_needed`, `pending` (with `purge_unsent`, `receipt_pending` or
`purge_rejected`) or `done`, and the erase waits for `done`.

A self-hosted vault (plain `oneiron-server serve`) shares through the anonymous
training window instead, and only with two argv flags together:
`--publisher-training-outbox-dir <absolute path>` and
`--publisher-training-self-host-shipper` (off by default; managed serve reads it
but never runs it, and the shipper flag alone warns once and does nothing). The
vault then fetches the intake's public keys from
`https://oneiron.dev/feedback/training/v1/keys`
(`--publisher-training-intake-origin` names another HTTPS origin) at start and
hourly, and writes `intake-recipient.v1` and `intake-receipt-key.v1` from them.
Every 30 s it sends the uploads and withdrawals that are due over HTTPS, and at
most every 15 minutes it asks for receipts; a pass with nothing due sends
nothing. Uploads carry each released offer's sealed text, its chunk files as
written (only the intake's key opens them), in byte ranges, with its code-only
facts: the month's scope, the month's codes for the conversation, the people and
the worlds, the filter, the sizes and the digests. Each offer goes under its own
code, a 64-hex handle the vault made once and keeps, which is the only way to
withdraw it. Withdrawals carry those codes alone: every offer a deleted
conversation or message, a world turned private, a person's erasure, a newer
offer of the same conversation or the vault's erase withdraws, sent until the
intake signs it `removal_pending`. Receipt asks carry the codes whose next state
is owed, those pending removal among them, until they read `removed`. No request
carries an account, a bearer, a cookie, a user agent, an install key, a vault id
or an IP address of the vault's; the intake sees the connection, as any HTTPS
server does. Every receipt is checked against the intake's receipt keys (the
current one or the one before it) and kept in the vault: `uploading`, `accepted`
(held whole in quarantine, not yet trainable), `eligible` or `refused` after the
intake's own filter, `rejected`, `conflict` or `invalid_submission` (sent again
later), `removal_pending`, then `removed`. The offer's files go once it reads
`eligible`, `refused` or `removed`, or once the vault withholds or withdraws it;
its code stays in the vault after them, and the vault's training key is
destroyed only after every offer of an erase reads `removed`. Requests start at
19 MiB; a `413` or a request that runs out of time (30 s, plus a second for each
64 KiB) makes them smaller for the rest of the process, a `429` or `503` waits
what the intake names, and no reply waits 30 s doubling to 15 minutes, without
end. Nothing is dropped or cut short, and a restart starts the waits afresh.
Stopping the server cuts a request in flight at once; the next start sends the
same window again. Turning "Learn from my conversations" off pauses uploads;
withdrawals and receipts go on. A released offer whose files are missing or no
longer match their manifest ships nothing and is read again every pass; until
its files ship, the owner's training receipts show it as `files_problem`
(`missing` or `mismatched`, with `files_problem_since`).

The broker holds `<socket>.lock` while it serves, so a second broker on the same
path refuses to start. `scripts/ci/broker-fixture.sh` runs the paid-leg fixture with
the broker as a second OS user. It needs an `/etc/subuid` and `/etc/subgid` range
for the user that runs it, and `newuidmap`. A Linux host that is meant to prove the
broker runs it; there, a missing prerequisite fails the run instead of skipping it.
`SCOPE_FULL=true scripts/ci/run_scoped.sh test` runs it after the workspace
tests, so a host that runs that command needs the range and `newuidmap`.

`max_output_tokens` is a ceiling on every call to that provider: it is sent
when a call names no limit, and a larger limit is cut down to it. An
OpenAI-compatible endpoint reads it from `max_tokens` unless
`output_limit_field = "max_completion_tokens"` says otherwise (some hosted
reasoning models accept only that one). An Anthropic-compatible call always
carries `max_tokens`, 4096 when nothing else names it.

An `openai-compat` provider at `https://api.openai.com` or `https://api.x.ai`
runs each call as one Responses turn on a held WebSocket at its
`/v1/responses`. A call whose conversation extends the last response that
socket finished sends only the new items, with `previous_response_id`; any
other call sends the whole conversation. Each turn goes with `store = false`,
so the provider keeps nothing and a replaced or reconnected socket starts the
conversation again in full. The owner can turn storing on with
`POST /v1/owner/settings/models` and `{"responses_store": true}` (`GET` reads
it): each turn then goes with `store = true`, the provider keeps the response,
and a new socket resumes a conversation from its last stored response, sending
only the new items. The server keeps each conversation's last stored response
in the vault, as this deployment's own state (never synced, and left out of a
checkpoint), so a resume also survives a restart; a turn whose response the
provider has since dropped goes whole. A socket is
replaced 5 minutes before its age limit (60 minutes at OpenAI, 59 at xAI).
Idle sockets wait 10 minutes for a next turn, at most 8 per provider. A
call whose socket will not open, or that carries audio, goes out over
`/v1/chat/completions` as before. An upgrade refused with a 4xx (other than
408 or 429) keeps that provider on HTTP until restart. Set
`responses_socket = false` to keep a provider on HTTP. Any other origin, a CPA
route say, holds a socket when its entry sets `responses_socket = true` (a
59-minute limit) or `responses_socket = { max_age_secs = 3600 }`. A
`key_secret` provider stays on HTTP: the credential broker runs no socket yet.

An `anthropic-compat` provider at `https://api.anthropic.com` sends a
`/v1/messages` request body of 16 KiB or more gzip-encoded (level 1), when that
makes it smaller, except on a cloud node (a managed or host-readable
deployment), where gzip costs more on the link than it saves; zstd still
compresses there. Replies do not change. Any other provider sends plain bodies
unless its entry names the codec its route decodes: `request_compression =
"zstd"` (level 3) for our CPA agents route, say, or `"gzip"`. Set
`request_compression = false` to send plain. If a compressed body is answered
400 or 415, it is sent once more, plain; when that answer differs, the
provider sends plain until restart. For a `key_secret` provider the credential
broker compresses instead, after its checks and just before its one send: gzip
level 1 on `/v1/messages` at `https://api.anthropic.com`, under the same
16 KiB and smaller rules, with no plain resend. A `key_secret` entry takes no
`request_compression`.

Our own model servers decode compressed bodies once built or started for it
(OF-604): the house model's `exl3_server.py`, a `llama-server` built by
`deploy/house-model/build-llama.sh` (cpp-httplib's zstd and zlib support on),
a vLLM server started with `--middleware body_codec.DecodeContentEncoding`
(deploy/house-model/README.md, "Compressed requests"), and the VoxCPM2 worker.
Each opts in on its own entry with `request_compression = "zstd"`; an entry
whose server does not decode stays plain. A `voxcpm2` entry compresses its
`/render` uploads, and an opted-in provider's media JSON bodies compress by
the same rules. A tagger endpoint opts in on its section, `[oneironer]
request_compression = "zstd"`, for its `/v1/extract` posts, with the same
plain resend; a `kind = "oneironer"` provider entry takes none.

A reply may name its model differently from the request (a proxy that strips a
login prefix, say). The answer is kept, and the receipt records both names under
`usage.raw_provider` (`requested_model`, `reported_model`, `rung`,
`failed_rungs`). `rung` is the answering rung's place in the role's ladder as
configured, counted from 0, the same numbering `GET /v1/ai/status` lists;
`failed_rungs` counts the rungs that were tried and failed before it.

## 3. Let the Dreamer work

The Dreamer consolidates witnessed turns into claims in the background. It
starts when all of these hold, and `GET /v1/ai/status` names the one that is
missing:

| Needs | Reason when missing |
|---|---|
| a rung on `dreamer_current` | `no_model_configured` |
| `ONEIRON_AUTH_SECRET` set (host root, machine identity) | `no_host_authority` |
| `extraction_egress = true` under `[models]`, for any model reached over HTTP | `extraction_egress_not_allowed` |
| vault defaults that route each Dreamer role's purpose to where that role's model is served (extraction and narrative under `extraction`, the conflict verdict under `consolidation`): `oneiron dreamer grant --extraction-route own_server` (or `third_party`), or `PUT /v1/llm/defaults` | `extraction_route_not_set` |
| with a model manifest, its extraction teacher served by `[models]` at the vault's route | `extraction_model_not_served` |
| with a model manifest, its `generative_reasoner` (the conflict verdict) and `dreamer_current` (narrative) models served by `[models]` at the vault's route | `role_model_not_served` |
| the Dreamer's three policy rows (a fresh vault ships them) | `needs_owner_grant` |

Each pass calls three roles, each on its own model and run: extraction as
`extraction_teacher`, the conflict verdict as `generative_reasoner`, and
declared summaries as `dreamer_current`. A vault's model manifest pins each;
without one, a role uses its own `[models.roles.*]` seat when it has one,
else the Dreamer's (`default = "provider:model"` fills all three with one
model). Each role's calls go out as the run `dreamer-pass/<role>`, so the
run receipts (`oneiron::run_receipt` at info) name the role that made them.

Every call of the three roles names its reasoning level; none leaves the
level to the server, which a local thinking model reads as its highest. With
no level configured it is `medium` with a 4,096-token thinking budget. A
level the vault authors for a call's purpose (its seat policy or description
policy: extraction and narrative under `extraction`, the verdict under
`consolidation`) replaces that default, and the budget with it. A local
(`own_server`) OpenAI-compatible server is sent the level as
`reasoning_effort` and in `chat_template_kwargs`, and the budget as
`reasoning_budget_tokens` (llama.cpp reads all three per request; an
exllamav3 server that renders `chat_template_kwargs` gets the level; the
house EXL3 server in `deploy/house-model/` reads the budget too, and closes the
thought at it). A hosted provider gets `reasoning_effort` alone. A model whose
provider does not declare `reasoning`, or a ladder with a rung that does not,
takes no reasoning controls, so its calls are pinned to `none`; declare
`reasoning` on a hosted provider whose model accepts `reasoning_effort`.

The extraction input lists the people, organisations and places the turns
name that the vault already holds, each with its newest claims, so a model
can name the claim a later turn corrects. A correction the Dreamer stages (a
new value for a claim it already holds) takes its grant in the same pass when
the vault's policy allows it: the replacement lands Auto, the prior closes
with a `Supersedes` edge, and an open `core.conflict.open` that named the
prior closes with a `core.conflict.resolved` claim. One the policy protects (a class a
manifest rule declares critical, or attributed truth such as a user-stated
claim) stays Proposed and is listed in the owner's run review (`GET
/v1/owner/runs`, `oneiron runs pending`). The seeded manifest declares
`health.`, `safety.`, `legal.` and `boundary.` critical, and `decision.settled`
exactly; a predicate no rule names defaults critical for legibility only and
does not hold a correction. A vault whose policy manifest is still the
untouched seeded one takes a newer build's seeded manifest when it opens, and
what waited on the old policy is re-gated, never applied; a manifest the owner
wrote is never touched.

```bash
# once, with the server stopped; ONEIRON_AUTH_SECRET set as for serve
oneiron dreamer grant --config ~/.config/oneiron/oneiron.toml --extraction-route own_server
```

The Dreamer is warm by default (ARCH-0026): a fresh vault's seeded policy
already carries three rows, each keyed to the vault's own Dreamer: a read-only
grant over the vault, an Auto ceiling, and the permit its generated claims
need. No other system actor and no other generated writer gains anything. A
vault created before these rows shipped has none, and the same command adds
them to its live policy; on a vault that has them it changes nothing. The
owner may narrow or remove the rows like any policy row. Extraction leaves the
device only on both opt-ins (the `extraction_egress` key and the routed
defaults), and then only to the model each pass extracts with: the Dreamer's
seat, or the extraction teacher the vault's model manifest pins. Boot reads the
routing and never writes it, so a later tightening by the owner is never
undone by a restart.

A sitting ends, and its turns dream, on `POST /v1/ai/session {"event":"end"}`,
after `models.dreamer.idle_floor_secs` (1200) without activity, or after
`session_ceiling_secs` (43200). Apps send `{"event":"open"}` and
`{"event":"activity"}`; chat turns send them for you. Per-pass spend is
`models.dreamer.pass_budget_units` (400000), metered through the usual budget
guard. If the server is killed mid-pass, the next start requeues the
interrupted attempt and runs it once more; durable steps that already have a
response are not paid for again. A pass that ran out of budget is parked on a
budget trap instead, and a restart leaves it parked: only the trap's resume
signal lets it spend again. Once that signal (or a consent answer, or a
person's response) is sent, here or on a peer that syncs it in, the next pass
resumes the parked attempt as the same try. `SIGTERM` or Ctrl-C stops cleanly:
a pass in flight reaches its attempt boundary first.

Beside sittings, the Dreamer's wake policy (ARCH-0026) wakes its three
recipes from the vault's wake-policy row: Continuous after landed turns,
Weave on accumulation, a quiet window or the longest wait, and Nightly on its
cadence. Continuous reads new turns through the sieve. Nightly queues the
vault cleanup pass, the Coach's nightly jobs, and the Dreamer's curator and
harness audit. Weave's input waits in the policy outbox for its recipe body.

The curator grades the Dreamer's own aged consolidations and files the next
demotion rung for each as a proposal; the harness audit scores the Dreamer's
recorded tuning config (its role models, prompt hash and pass dials, plus the
Coach's retrieval weights) by how often you accepted its reviewed proposals,
and files a retune proposal naming the surfaces a backbone change or a score
drop implicates. Both land in the owner run tray (`/v1/owner/runs`), one
run per night. Approve a curator run and each demotion whose target is
unchanged since grading applies once the approval commits (one that cannot
apply then waits for the next pass); a retune proposal is advice only and
changes nothing.

The vault cleanup pass proposes archives and archives nothing until you
accept (`/v1/owner/cleanup`); automatic archiving stays off until ARCH-0066's
teeth #5 and #9 close. The next regular proactivity digest
(`/v1/owner/proactivity/digest`) carries one `dreamer.cleanup` line: what
cleanup archived since the last digest, and how many records wait in open
proposals, with the cleanup view to restore any of them. Each proposal and
your accept or reject count in the healer oversight receipts
(`/v1/owner/healer/oversight`).

The Coach's nightly room upkeep (`coach.room_upkeep`) needs no grant: the
Coach is born with a read of room refs and turn times only, over the rooms
and turns the Dreamer reads, and never reads a turn's words or a member's
text. Its own read still reads nothing a grant does not name, and narrowing
the Dreamer's policy rows narrows this reach with them. A room whose turns
moved since its last pass gets its summary declared on the scope-summary
path, when the Dreamer reads the room's whole conversation; the Dreamer
writes the summary under its own read and nothing is posted. A thread
with open TASKs that has been quiet for a day gets one Proposed
`coach.room_upkeep.nudge` finding, addressed to the room's host, in the owner
run tray. The Coach never speaks in a room; a nudge is the host's to voice.

The Coach's nightly tripwire sweep (`coach.tripwires`) runs the tier-1
detectors (refused Dreamer consolidations, consent storms and denials,
per-actor write drift) over the last day of Gate receipts, and the read-side
pass runs the retrieval-miss detector. Each run is signed by the scheduled
detector instance, and a run that does not verify stores nothing. A retrieval
miss files a proposed reindex and a refused consolidation a proposed retry,
through the production healer host (`Vault::healer_proposal`); nothing applies
them. Each wake waits for no running chat turn,
no running workflow and `idle_secs` of quiet since the last turn. A peer's sync apply wakes the
Dreamer too, so turns another host wrote are read without waiting for a local
one.

## 4. Chat

`POST /v1/ai/chat` with `{"conversation_ref": "<32-hex>", "text": "…"}` (plus
optional `history`) answers by default with the whole message once it is saved:
`{conversation_ref, turn_id, message_id, text, incomplete, finish_reason}`.
`turn_id` is the assistant turn that Continue and Retry name. A reply cut short
(a crash, a failed stream, a length stop) is still one saved message: it answers
`incomplete: true` with exactly the text that was saved. With `"stream": true`
the answer is NDJSON instead: `accepted`, one `delta` per text chunk, `done`,
then `saved` with the message receipt, and the same deltas reach every owner
socket on `/ws` as transient presence. A whole answer keeps its partials
private. Either way each delta is checkpointed in the message before it is
published, and a client that goes away does not stop the turn. The credential
needs read and write scope, and must be able to read the answering agent's
definition. It is checked for the whole turn. Once it is revoked or expires, a
streamed body sends one `{"type":"error","code":"credential_revoked"}` line
and ends, a whole answer is refused with 403 `credential_revoked`, and the
message is cancelled rather than saved as an answer. The seeded
default agent answers; an owner-grade credential may name another with
`agent_ref`, which must be live, approved and enabled. A turn still running
at shutdown gets a grace to finish, then its message is cancelled, not left
open. A turn spends from `models.chat.turn_budget_units`: the tokens the
reply reports, or the turn's reservation (one call's 8000 units, or the whole
budget if smaller) when it reports none, plus one reservation for each rung
that failed before it. A turn that ends without a reply spends its
reservation.

Chat turns and workflow steps are calls of the `generative_reasoner` role. If
the vault has a model manifest, its binding for that role at the vault's
current route (the pin, narrowed by any resident route) picks the model, and
the server must serve exactly that model there: one of your `[models]` models
with the same engine id and locality. A route the server cannot serve is
refused with `503 model_route_not_served` before anything is sent. Without a
manifest the `[models]` ladder is the role's binding.

## 5. Saved workflows

A dispatched saved workflow runs its steps on the `generative_reasoner` seat
with no further call. Each step's system message is the agent definition's
`instructions`; each step sees its briefing and the earlier steps' outputs.
Memory and chat sections a definition selects are not yet rendered into the
step's prompt. A failed step goes to the engine's failure ladder. A model
call the provider answered with a retryable error is tried again after
`models.workflows.retry_backoff_secs` (30) times the tries so far, up to five
tries. Any other failure, or a fifth retryable one, ends the step for a
person to look at, and its workflow stops. Spend per step:
`models.workflows.step_budget_units` (64000, at least one call's 8000-unit
reservation), one budget for all of a step's tries: an answered try spends
the tokens it reports, or its reservation when it reports none, plus one
reservation for each rung that failed before it; each failed try is
charged its reservation, every budget policy row the step matches (its
agent's cap, its purpose's) counts those charges too, and a try the
remainder cannot admit ends the step. `models.workflows.enabled = false` turns the pump
off.

## 6. Code mode (MCP `execute_code`)

`execute_code` runs a task as generated JavaScript: each step's program comes
from the `generative_reasoner` seat and runs in the checked-in QuickJS
component, calling the vault through each verb at its SDK path
(`vault.recall(...)`, `self.focus.refresh(...)`) under the
connector's own grants. It is listed on `tools/list` only when the seat has a
rung and a prompt package for the executor is named:

```toml
[models.code_mode]
prompt_package = "prompts"   # holds blocks/engine-executor-wire.md; relative to this file
budget_units = 10000000      # optional; process-lifetime meter for its model calls
max_runs = 32                # optional; runs at once, each its own thread (default: from cores and memory)
```

A run holds its place until its worker ends, whether or not its caller is
still waiting. Past `max_runs` a new run waits its turn, round-robin across
credentials, and the row asks whether everything is okay; a run that waits
past `[limits] queue_wait_timeout_ms` ends with `code_run_waited_out` and no
run started. The default is four runs a core, and no more than half a GiB of
memory each. A compaction pass can outlive the call that started it, so
passes have their own `max_runs` places; past them a pass waits its turn, and
one that waits past the deadline leaves the run its raw window.

Each step's call is admitted like a chat turn, against the vault's model
manifest and route, and spends from `budget_units`: the tokens the reply
reports, or one call's 8000-unit reservation when it reports none, plus one
reservation for each rung that failed before it. A call that failed spends one
reservation for each provider call it made: every rung of the seat, or the one
model the vault's manifest pins. A run's clock and config are saved when it
starts, so a run resumed after a restart keeps its clock and refuses another
task. A vault with a model
manifest needs a seat judge this server does not bind yet, so its runs are
refused with `code_run_binding_failed`.

A long run compacts its own window (agent-runtime-v1 §d7). Once a step's
request comes within a margin of the window (the tokens the run adds while
one summary is written, measured as it runs; never more than half the
window), the steps behind the newest `hot_steps` are summarized in the
background while the run keeps working. The summary
replaces them only after the engine's six checks: the reply stopped
naturally, it is the requested JSON, it is smaller than the steps and above
a floor, it keeps every failed step's first line word for word, it does not
loop, and it covers exactly the requested steps. The next request holds one
`<compacted epoch="n" steps="a-b">` frame with the summary and a
`sandbox.fs.read_file` handle to each original output. A failed check is
retried, naming the check, up to `tries` times; after that the run keeps its
raw window. A run that reaches its window with no accepted summary stops
with `"status": "window_full"` and a typed reason, and the next call goes on.
Erasing a record the run was served withdraws the summary's words; the
steps stay covered by their handles.

```toml
[models.code_mode.compaction]   # optional; on by default when code mode is served
enabled = true
role = "checker"        # default: checker when its rungs take a whole window, else generative_reasoner
window_tokens = 96000   # default: the smallest context the code-mode seat's rungs leave for input
hot_steps = 2           # newest steps that never compact
tries = 3
```

The summary prompt is `blocks/engine-executor-compaction.md` in the same
prompt package as the wire prompt. Its user message is one JSON object
(`from`, `through`, `max_summary_tokens`, `pins`, `note`, `retry`, `steps`)
and the reply is `{"from", "through", "summary"}`. `note` is what the agent
asked the summary to keep, as free text, or null; unlike a pin it need not
occur in the steps, and the gate does not check it. The test package's block,
`crates/oneiron/tests/fixtures/prompts/blocks/engine-executor-compaction.md`,
is a working example. Passes are metered on `budget_units`. Without the
block, a seat for the role, or `[models]`, compaction is off and never calls
a model; `GET /api/health` says `"compaction": "off"` with the reason
(`no_model_configured`, `no_compaction_prompt`, `no_compaction_seat`,
`compaction_seat_too_small` when the role's smallest rung leaves less input
room than `window_tokens`, `disabled`, or `code_mode_off`). Each `execute_code` result carries the run's
`compaction` object: `used_tokens`, `compact_at`, `window_tokens`,
`in_flight`, `last_swap`, and `suppressed` (`auth`, `no_credit`,
`turn_scoped` with the failed `check`, or `sticky` with `why`).

A run whose actor is a saved agent definition compacts by that agent's
`memory_profile`: its `window_token_budget` is the run's window, its summary
share sizes the summary, and `compaction = "byoa"` leaves the window to the
agent's own harness (`sticky` with `why: "harness_compacts"`). Its
`compaction_backend` names `code-mode-compaction` (the seat above) or a
reasoning seat by its role's key (`checker`, `local_reasoner`,
`generative_reasoner`); a key this host does not serve compacts on the seat
above. Any other run uses the table above. A long run never outgrows one
summary's sources: each summary stands for the records the calls before it
were served, so the next one names only the records served since.

`compaction_backend = "self"` makes the agent its own compaction writer (FIX
4465). The key sets who writes, not which model: every epoch and fold summary
of its window is written as the agent, under its byline, on the writer its
flight resolves (below), wearing its home. The home is read once per pass,
through the existing doors, under the agent's own Grant at the place its
caller sits: its voice (its PERSON's compiled persona), its lessons (its
admitted, active `actor.lesson` and `actor.failure_mode` claims) and its
diary (read through the diary door as its own reader). There is no self-model
binding yet, so that part is reported absent. A part the agent has none of,
or may not read, is absent; it is never filled from the owner's memory or
another agent's diary. The home takes only the tokens the admitted model's
context leaves once the window, its pins and the reply are counted; what does
not fit is cut and reported as cut.

Which model and context a self-written flight uses is a policy row,
`self_compaction` in the inference defaults (`GET`/`PUT` with the purpose
rows), read once per flight (FIX 6029; the default changed per the owner's
ruling, #2969/#3131):

```json
"self_compaction": {
  "source": "auto",
  "cheap_model": "deepseek/deepseek-flash@1017",
  "locality": "third_party"
}
```

`source` is the flight's strategy. `auto`, the shipped default, decides per
flight: while the live prefix is still warm in its provider's prompt cache,
the agent's live model writes the summary by forking its warm request;
outside that window the cheap writer writes it as the agent, wearing its
home, from the retained steps, since the cache is cold anyway. `live_fork`
always forks the live context, and `retained_turns` always uses the cheap
writer; both stay explicit choices and answer as they always did. Both
writers carry the same as-agent instruction and home.

The cheap writer is the agent's own `compaction_model` when its definition
names one, else the row's `cheap_model`: shipped as DeepSeek V4.1 Flash 1017,
`deepseek/deepseek-flash@1017` (provider key `deepseek`, wire model
`deepseek-flash` at `https://api.deepseek.com`, revision `1017`). A pack, or
the owner, changes it by replacing the table, as with any other row. The
model writes only where this host serves it: a `[models]` provider and a
role's rung must name it, for instance

```toml
[models.providers.deepseek]
kind = "openai-compat"
base_url = "https://api.deepseek.com"
key_env = "DEEPSEEK_API_KEY"
revision = "1017"
locality = "third_party"
# context_tokens, max_output_tokens, capabilities: the provider's own figures
```

with `deepseek:deepseek-flash` on a role's ladder. When the cheap writer's
model is not served here, or the row's `cheap_model` is served wider than
`locality`, the house compaction model (the seat above) writes as the agent
instead, so a flight that compacted before still compacts. An agent's own
`compaction_model` served wider than `locality` is refused, as before.
`locality` is the widest place the call may be served (shipped
`third_party`; a delegated edit cannot widen it). The writer's model is
admitted as exactly that model, on its own one-model ladder. Whether the
agent runs on this device, on a hosted server or in the resident pump does
not matter: the same run is served the same way, and warmth never depends
on where it runs.

With `live_fork`, or `auto` while the prefix is warm, the step that crosses
the threshold (or asks to compact) captures the run's live request as the
rung that admits it sends it: the step's own admission on the chat role,
bound to the rung its walk would send it to now, the rung's prompt first.
That one copy rides the flight; each of its calls sends the prefix unchanged
on that same rung, with no fallback to another rung or model, then the house
compaction's instruction, the agent's home and the span's input after it. The
span is sized on the live model, after the prefix and the reply's reserve,
and the home takes what is left; the prefix is never cut and the home never
goes into it. The prefix's end is marked as a prompt-cache boundary in the
request's own `oneiron` provider options (`cache_boundaries`): an Anthropic
rung sends it as `cache_control` `ephemeral` on that block, on the provider's
own cache lifetime, and any other provider sends a plain call. The receipt
names the live rung's model, and its cached-read and cache-write counters say
whether the provider reused the prefix. The calls file, land and are checked
as any other self-written pass, and the flight lets go of the capture when it
ends.

Under `auto` the host reads warmth from its own memory, never the vault:
each call a rung answers notes the prefixes it marked (a step's or a chat
turn's own end, FIX 4930) from the instant it was dispatched, under its
route, offer, wire model and provider client. A prefix stays warm for the
lifetime its provider keeps it, from one table:

| Route | Lifetime |
| --- | --- |
| The Anthropic API's own (`anthropic-compat` at `https://api.anthropic.com`) | 5 minutes; 1 hour where the request's own `anthropic` options carry a `cache_control` with `ttl: "1h"` |
| Every other route (OpenAI-compatible, Gemini, DeepSeek, any proxy) | unknown, so cold, until a row is added |

The Anthropic wire marks every boundary at the tier the request asks for:
with no such option it sends the bare `ephemeral` marker, as it always did,
so no route newly pays the hour's cache-write price, and tiers that differ
count as the shortest. A restart, a rebuilt provider client, or a matching
prefix more than 20 content blocks before the request's end reads cold too.
The breakpoint checks warmth when it captures the live request, and the
flight checks it again right before its first call goes out, after its
admission. Any stop before that call has gone out (a prefix gone cold, a live
rung that rests, is on probation or is held on the device, a refused
admission, a stale rung) sends nothing on the live rung, settles its permit
unstarted, and the cheap writer writes the flight instead. Once the call has
gone out, a provider's failure stays a failure, never read as cold. The
flight keeps the source its first call ran on for every retry and fold. An `auto` flight's window is
sized on the smaller of the live model's room and the cheap writer's, so a
prefix that goes cold before the first call never leaves a window the cheap
model cannot take. A self agent's chat turn (FIX 4465 D) follows the same
row: under `auto` or `live_fork` its log is read from the retained ledger,
and its flight forks the answer's warm call or, cold, is written by the
cheap writer, its window cut to the whole turns that writer takes.

A pass that cannot be written as the agent keeps its raw window for the turn
and says why; it never falls back to the Dreamer or to the plain house
writer. Under `auto` a live fork that cannot be bound (no rung, a rung wider
than `locality`, no room beside the prefix, a cold prefix) is not such a
failure: the cheap writer writes the flight as the agent. A forced
`live_fork` names every one of them. The run's `compaction` object carries
`self_unavailable`: `live_fork_not_captured` (the row selects `live_fork` and
the flight carries no capture from its breakpoint), `live_rung_unbound` (the
live route refused the step's request, or no rung of its ladder could take it
then), `live_prefix_too_long` (the live request and the reply leave the live
model no room for the span), `live_fork_not_admitted` (the profile's writer
is not `self`, or the capture is not the run's own), `live_fork_stale` (the
live route no longer admits the captured rung), `no_identity` (the actor is
not an agent anchored to a PERSON), `identity_unreadable`,
`policy_unreadable`, `model_not_served` (neither the agent's own model,
`cheap_model` nor the house model is served), or `route_wider_than_policy`. A
run bound to a room is written as the agent too, on the route the run
captured at entry.

Each self-written summary lands only through its packet: a turn digest of
its window, admitted through the packet door's host-log binding against the
run's retained steps, with the snapshot the pass stamped when the gate
accepted it. Its receipt records who wrote it (the agent) and what ran it:
the source its flight ran on (`retained_turns` or `live_fork`, never
`auto`), the admitted model, the provider and the model it reported, the
provider-reported input, cached-read, cache-write and output tokens (`null`
when the provider reported none, never a guessed zero), each try the gate
refused as its own line, the call's step hash and the home parts it wore.
The epoch's receipt rides its coverage row and is named by its SUMMARY's
birth; a fold's rides its fold record. The run's `compaction` object shows
the last pass as `self_writer` (landed or not) and every summary the run
landed, with the receipt its rows keep, as `self_landed`.

Each paid call of a self-written pass, a try the gate refused too, is filed
as one `dreamer.step` claim about and by the agent, its job the run it
compacted, on the run's own route: in the vault for an ordinary run or a
room already on record, in the room's overlay for an off-record room. The
run's meter settled the call once when it ran; filing it settles nothing
again. The receipt names the answering try's step and each refused try's,
and the revision of the retained steps the window was cut from.

A self-written summary depends on each home part it wore whole, as on any
source: erasing a diary entry, a lesson or the voice it wore withdraws the
summary's words. Each self-written epoch or fold that lands in the vault
also queues the Dreamer's check of it, in the same write. The check reads
the summary against the run's retained steps for exactly its span and
records a finding: `supported`, `mismatch`, `stale_evidence` or
`unreadable_evidence`, with the hashes, revisions and the steps a conflict
cites. A mismatch also reaches the agent's inbox. The check never rewrites
the summary, never changes its byline and never writes in the agent's
voice. A summary that stays in an off-record room's overlay is not checked:
nothing of the room reaches the vault, where the Dreamer reads.

A run in an off-record room compacts the same way, inside the room: the pass
reads the room's view, and the summary, its sources and its step coverage
stay in the room's overlay. Nothing reaches the vault, no summary is embedded
or exported, and closing the room drops them with the rest of it. A room
closed or flipped on record while a pass runs refuses its summary, and the
run keeps its raw window. An anonymous room keeps no summary, and a room
already on record when the run started does not compact yet: both report
`sticky` with `why: "off_record_run"`.

The run can also fold spans of its own log (ARCH-0067 §2.2).
`self.fold({from, through, note?})` marks steps `from`–`through` and returns
the fold's handle (`f1`); the log does not change yet. `self.compact({note?})`
asks for a pass at the next step boundary. It is the same seat, backend,
single flight and gate as a crossing, it compacts the settled steps (the hot
steps stay raw), and it folds every pending mark in one batch. A crossing
folds the pending marks too. Each fold leaves one stub where its span was:
`⟨f1 · t5–t8⟩`, the summary, the ids its steps name that the summary does
not, and a read handle to each step's output and each stored result the span
names. The stub is written once and kept byte for byte.
`self.unfold({fold})` appends the fold's raw steps after the step that
called it, labelled `unfolded from t5–t8`, and they stay there.
`self.folds()` lists the folds and the pending marks, and
`describe({fold: "f1"})` returns one fold's span, stub, ids and handles. The
log's tail carries one line naming the folds and pending marks, never a
summary. A mark that fails its pass keeps why and waits for the next
`self.compact`. A run whose compaction is off answers its marks with
`compaction is off for this run`. The ledger is node-local and follows the
run's route, so an off-record room's folds stay in its overlay.

A secret reaches a run as its handle, `[secret sc12]` in text or `sc12` as a
field's value, never as its value. `describe("sc12")` says what it names,
where it was found and whether a reveal would deliver at once, ask the owner
or be refused. `reveal({handle, why})` returns a pending reveal every time,
and `wait(pending)` answers `pending`, `denied`, `expired` or `granted`. The
first `granted` answer carries the value as `value` (or `value_base64`), and
later ones carry only the receipt. The run's record keeps that answer without
the value, so a resumed step must reveal again. The rows are `reveal`,
`reveal.wait` and `reveal.describe` on every other door too.

A run can also hand a secret to a trusted operation without reading it:
`self.use({handle, operation, arguments})`. The operation presents the value
at its own door and the run reads only what came back, with each copy of the
value replaced by the handle. The v1 operations are the read-only provider
checks `slack.auth_test`, `line.bot_info`, `gmail.profile` and
`linkedin.session`, each answering the account the credential belongs to. The
only grant is the secret's binding for the operation's effector (such as
`connector:slack`): there is no ask, and a reveal's grant does not reach it. A
secret the mask on write found has no binding, so `self.use` refuses it and
names the owner door that adds one. Every use, and every refused one, leaves a
Gate record with the handle, generation, effector, operation and send status.

On a server, `self.use` also takes `connector.call`: one connector call with
the secret as the call's credential, in place of the connector's own. Its
`arguments` are what `connector.call` takes: `name`, `tool`, the tool's
`arguments` and `mutation`. The secret needs a binding for
`connector:<connector>`, the connector the name routes to, and the call itself
still runs under the run's own standing grant and gate. The tool's reply comes
back as `result`, marked foreign, with the value replaced. A call the gate
holds parks the run on its `call_ref`, as a held `connector.call` does. The
settler sends it once the hold clears, with the same secret, and the door
checks the binding again at that send. The run then resumes with the call's
settled reply, the `connector.call` reply cleared of the value, bound as
`wait<n>`. An embedded vault refuses `connector.call`.

When the host's model ladder served the turn, each verb call the turn's
program makes carries the provider that answered it, and a reveal's ask names
that provider. An agent no host model drives, such as an external HTTP or MCP
agent, gets an ask that says the host does not know its provider.

A value custody already holds, including one a reveal delivered, does not stay
in what comes back. It may come back in a run's output (its console, answer,
stored results and files, and the model's reply kept as evidence), or in a
later write or side row. Each copy is replaced by its own record's handle, and
no new record is minted. The match is exact and needs at least 12 bytes. It
reads a keyed index that holds each value's length and fingerprint, never the
value. The index's key never leaves this machine. The owner's "not a secret"
ruling for a record wins over the match. The step's program is stored as the
model wrote it, so a resumed step runs the same code. A run in an off-record
session is swept the same way.

A stored file keeps its bytes. A known value in a file, or in a member of a
container file, is marked with its existing record, as a key the scan finds
is marked. A reader without a grant then gets the file with that value
masked, and a granted read gets the real bytes, both through the same mark.

### Reader children, summaries and fold receipts

A run reads a result too big for its window with reader children
(ARCH-0079 #reader-forks). `can({read})` answers what a child may take: the
children's cutoff, the meter they spend on (`scope` with what the run's spend
scope may still spend, or `host`), the active window of the code-mode seat's
model in tokens (from the model's described context; 32768 when none is
described) and the memory one child may hold
(`[limits] code_result_session_memory_bytes` shared by the children one run
may have running, at 32 MiB each). `self.spawn` queues one child over one
range, and `tasks.wait` waits on them. Children run on the vault's reader
runner, never inside a step. A paid or attempt-scoped run's children spend
under its spend scope. An `execute_code` run's children, and those of a
resident run with no spend scope, spend on the host's code-mode meter
(`budget_units`), the one the run's own model calls take, with no per-run
cap: one run's children can exhaust it for every code-mode run. Past
`[limits] code_reader_backlog` queued children (default 256) the row asks
once, on its crossing, and keeps queueing; it never refuses.

`summarize(r, {effort, group, defer})` is one model call over a result and
the results after it, made as a reader job of the run on the same seat and
spend. It is memoised by its members' occurrences and the recipe, so the same
call answers the same summary, and it is a result of the run's children,
read and described as their findings are. A withheld member is refused
before anything is sent. A group whose text passes half the window settles
`group_exceeds_window` with its tokens and the window; the caller splits it.

The bundled `readAll(r, {ask})` helper is code over those verbs: chunks of
half the child window (`chunks(r, {tokens})`), one child each, a wait,
findings deduped by the ranges they cite, staged summaries, and one stored
fold. `diff(a, b)` is the other bundled helper. Neither is an engine verb,
and both state their bounds in their reply.

A fold stored with `store(value, name, {receipt})` keeps a receipt beside its
binding, written in the same checkpoint transaction: the source and range,
each child it names with its state, the ranges read and unread, the children
that stopped short and why, the cutoff, the recipe, the summary tree and every
occurrence whose taint the folded body inherits. The card says what was read,
so a partial fold is never presented as complete. A whole-vault export keeps
each receipt with its run; a withheld folded result exports only the
receipt's refs. An import restores a receipt only when its folded result came
back with it.

### Type check (shadow mode)

Each generated program can be type-checked before it runs, against the same
declarations the executor prompt teaches (`allowJs` + `checkJs`, strict,
ES2022, no DOM or Node globals). It is off by default:

```toml
[models.code_mode.check]
mode = "shadow"              # "off" (default) or "shadow"; "enforce" is reserved and refused
backend = "tsc-rs"           # "tsc-rs" in process (default) or "microsoft"
microsoft_tsc = "/opt/typescript-7.1.0-dev.20261010.1/package/lib/tsc"  # optional
```

Shadow mode blocks nothing and changes no program's result. Once a step's own
state is saved, the check's report is appended to the run's replay record as
`executor/repl/<step>.code-check.json`: backend and pin, latency, every
diagnostic in program coordinates with its whole message, or a failure code. Each check also logs one `oneiron::code_check` line with the
step's outcome (`completed`, `waiting`, `continued` or `failed`) and the
running counts. A step that fails keeps no report, and neither does a run in an
off-record session, whose overlay is quota-bounded; their checks are only in
the log.

`tsc-rs` is the pinned Wasm module in `components/tsc-rs`, compiled once at
startup (a few seconds) and run in a fresh instance per check, two at a time.
`microsoft` runs Microsoft's native `tsc` (`@typescript/typescript-<platform>`,
version `7.1.0-dev.20261010.1` only) as a process per check, in its own
process group and temporary directory but with this host's file system. Since
resolving a module would read or probe the path it names, it leaves unchecked
(`code_check_unsupported`) any program that could name one: one containing
`import`, `export`, `require`, `reference`, `module` or a `\u` escape, in any
case.
With `tsc-rs` selected, a set `microsoft_tsc` is the fallback for any check
tsc-rs cannot finish, a busy one included. A step's report names the checker
whose answer or failure it holds. When no checker loads, code mode runs unchecked and the
server logs why. The checker binary is trusted configuration, like any path
in this file; the programs it checks are not.

### Planned spawns (`[models.planner]`)

An agent run the server leases can ask for help with
`self.agents.spawn({need, ...})` and have the vault's planner pick the shape:
the model, the pattern and the width. Its leader calls
(`self.leader.advice`, `self.leader.pattern`) read the same planner. Each
seat joins a model this host serves to the AGENT_DEF that runs on it:

```toml
[models.planner]
top = 3                      # optional; shapes the leader's advice returns by default

[[models.planner.seats]]
model = "anthropic/claude-sonnet-5-5@1"  # an engine model ID, one seat per model
agent = "sys.team_lead"                  # a seeded definition's logical ID, or an AGENT_DEF hex ID
```

The planned child runs the chosen seat's definition, its type placed on the
need's text. On a host with a model manifest it is born on the chosen seat's
model; its effort follows the seat's own ladder. If the host cannot seat that
model (it is not in the catalog, or its description or route does not fit the
run), the child's birth fails. It is never moved to another model. The pick
and the placement go through the host's decision ladder (section 13), each on
its own 10-second clock. A seat whose definition this vault does not hold is
skipped, with a log line. With no seat, the server lends no planner: a spawn
that names an `agent` runs it directly, and a planned spawn or a leader's
advice or pattern call answers `planner_unbound`.

A leader's `self.leader.split({leader?, slice?})` reads no planner. It splits
the TASK her run realizes into a subproject under that TASK's project (her
lease names both), led by `leader` (herself when unset) over `slice` (the
parent's when unset). The parent still sees one checkbox. The server signs the
spawn with its host key: the managed issuer, or the one `auth_secret` derives;
a host with neither answers `slip_issuer_unbound`. A TASK wraps one child, so a
retry answers the same child.

## 7. Raw calls

With `[models]` set, `/v1/llm/generate` and `/v1/llm/stream` call any
configured model by its engine id (`<provider>/<model>@<revision>`, shown in
`GET /v1/ai/status`), or a seat by its seat id. Their process-lifetime meter is
`models.raw_budget_units`.

## 8. The reranker

Recall at `high`, `xhigh` and `max` reranks its top 30 or 50 candidates on
the `reranker` role (ARCH-0004 #rerank: a cross-encoder refines the fused set
and never replaces the blend). Route the role in `[models]` like any other,
on an OpenAI-compatible provider whose server answers `POST /v1/rerank`
(`{model, query, documents}` in, `{results: [{index, relevance_score}],
usage: {total_tokens}}` out):

```toml
[models.providers.rerank]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:8081"

[models.roles.reranker]
model = "rerank:<the model your server loaded>"

[models.recall]
rerank_budget_units = 32000   # each recall's own line; the default
```

Each paid recall runs on a line of its own under the vault's budget policy,
as a chat turn does. Before a call leaves it is priced on its words, a unit
per byte of each document plus the query once per document, and 16 more
per document for the marks a cross-encoder puts around each pair. A line
that cannot cover that refuses the call unsent with `BUDGET_SPENT`. The
default line covers 50 documents of 500 ASCII characters beside a query of
about 120; longer documents, text outside ASCII (several bytes a
character), or a model whose template wraps each pair in a longer prompt
need a larger `rerank_budget_units`. Each rung of the `reranker` route the
call reaches is admitted on its own permit, reserving that price (at least
one call's 8000 units, or the whole line if smaller), sent through the run's
gate and settled: the tokens the reranker reports, or the reservation when
it reports none. A rung that failed after it went out pays its reservation,
and a fallback rung goes out only while the line still covers the price.
The `Admitted`, `Dispatched` and `Settled` rows go to the server's run
receipts. If the vault has a model manifest, its binding for the `reranker`
role picks the model, as for chat.

The recall scores exactly the block it would rerank: the candidates the
reader may read, with each one's text as the reader's own read serves it.
A row with no revision that holds its words (a message whose words live in
its document: a streamed message, the server's own chat replies among them,
or an edited one; or a turn whose messages show none) is found but not
reranked yet: it follows the reranked rows in its first-stage order. Each
text is judged by the write door as it would leave, a turn's messages
joined as the reranker would read them, and one the door refuses is sent
empty. So is a row a device-only world keeps, at the revision scored: a
`[models]` reranker is reached over HTTP, never on the device. A row sent
empty scores last. A block with no text to send makes no call and says
`skipped` with `no_candidates`. Each rung, a fallback's too, goes out only
while that device-only verdict, run again, keeps none of the rows it sends
with words. Once it keeps one (its world was flagged while a rung was out),
nothing more is sent, and the recall ranks by fusion and says `skipped` with
`device_only` to a caller on this device; a caller off it reads
`no_candidates`, as it reads no hint of a device-local row. The pack repeats
the name the endpoint says
answered as `served_model` only when it is at most 200 printable characters.
The model runs outside every vault transaction, and the scores apply only to
that same block. A block that changed while it was scored (the vault was
written to) is scored once more; if it changes again the recall is refused
with `INVALID_STATE` (409) and nothing stale is used. The pack's
`retrieval_meta.rerank` says what happened: `{"status": "applied", "model",
"served_model", "candidates", "calls"}` or `{"status": "skipped", "reason":
"no_reranker" | "no_candidates" | "deadline" | "device_only"}`.

Without a `reranker` route, `high` and above run their graph expansion
unreranked, and say `skipped` with `no_reranker`. With one, nothing stands in
for it: a spent line is refused with `BUDGET_SPENT` (402; MCP kind
`budget_spent`), and a reranker that refuses, fails or answers out of shape
with `MODEL_UNAVAILABLE` (503; MCP kind `model_unavailable`). A route whose
rungs cannot serve (a key variable unset, or a `key_secret` provider: the
broker has no rerank shape yet) refuses the same way. The request
never names the model, the endpoint or the lease; the server holds them, for
MCP, HTTP and WebSocket recall alike.

## 9. The decision read

decide()'s escalation rung reads the `local_reasoner` model as one pack: the
question's labels, "does this need more thinking?" and, when the host asks
it, "ask a person?", each its own typed question over the same state, sent in
one request and read as probabilities, with no text generated. Each question
is normalized over its own labels: idle-fold test 6b read "ask a person?" as
its own question far better than as part of one joint label table (AUROC
0.990 against 0.908). The model must be a llama.cpp
`llama-server` reached on its native API (`/tokenize`, `/completion`; a
`base_url` ending in `/v1` still reaches them), on the one rung
`local_reasoner` has:

```toml
[models.providers.house]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18134"
revision = "qwen3.8-27b-q4km"     # part of the read's pinned revision

[models.roles.local_reasoner]
model = "house:qwen3.8-27b"

[models.decision_read]
recipe = "prompts/decision-read/recipe.toml"   # your prompt package; relative to this file
max_response_bytes = 67108864                  # one answer body (the default, 64 MiB)
person_threshold = 0.9                         # the PersonThreshold row's start value
think_threshold = 0.8                          # the ThinkThreshold row's start value
```

The recipe is yours, not the server's (`format = 3`): it names the plain
prompt template (`template`, with `{question}`, `{labels}`, `{state}` and
`{state.<key>}` slots), the joint template (`joint_template`, the same slots
and `{paired}`), one label's row wording (`row`, with `{token}` and
`{label}`), one joint label's row wording (`joint_row`, with `{token}`,
`{label}` and `{think}`), the `yes` and `no` words, `no_first` (a plain
yes/no question lists no before yes, as test 6b's side questions did; its
readout still reports yes first), the single-token label verbalizers
(`tokens`, at least four), the end token (`eos`), `n_probs` (how many of the
top probabilities come back), `n_probs_full` (the whole vocabulary, for the
retry below) and, for the owner's probe, `[probe] paired` and `person`. An
optional `[probe] presence` words the presence question every Box or Point
call asks first, over the same images and clock, with the coordinate
question's wording in the `locate` state field ("is that target in the image
at all?"). Only a confident yes, with no person asked, starts the
coordinates; a confident no answers that the target is absent; anything else
abstains. Without it, the coordinates are asked directly.

A question and "does this need more thinking?" stay joint (ARCH-0076
`#ask-a-person`): the question renders the joint template, its text as
`{question}` and the paired question as `{paired}`, over one table of joint
labels, one row per option and paired answer: row `2i` is option `i` with
`{think}` the `no` word, row `2i + 1` with the `yes` word, each its own token.
The read normalizes once over all of them; the option's share is the sum of
its two rows, and P(more thinking) is the sum of the `yes` rows. A yes/no
question's options keep yes first here, whatever `no_first` says. "Ask a
person?" is read separately on the plain template, over its own yes and no.
A question of `n` options takes the first `2n` tokens, so `tokens` bounds a
choice question at half its count. Each label must be one distinct token on
the served tokenizer, or every read is refused. The read's revision is the
provider's `revision` plus a digest of the recipe and both templates: change
any of them and decide()'s pins name a new read.

The pack goes to `/completion` as one request whose `prompt` is an array,
one prompt per question, with `id_slot` -1: llama.cpp gives each prompt a
free slot (run `llama-server` with one slot per question, `-np`, to read a
pack side by side) and each slot's prompt cache keeps what it last read. The
request reads the state once; it is not a promise that the shared prefix is
evaluated once. decide()'s pack is the call's questions in order, each joint
with "does this need more thinking?", then "ask a person?" when the surface
asks it. A call past the decision policy's questions-per-call row (16 by
default) goes as several packs in turn, each with its own "ask a person?"
question.

The read goes to llama.cpp's raw `/completion`, which applies no chat
template, and the server adds no text: the rendered template is the whole
prompt, byte for byte, a trailing newline included. So the template carries
the chat framing the read was measured with. For the house Qwen model that is
the system and user turns, then
`<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n` (each `\n` a
newline), and the label cue as the template's last bytes. A template without
that framing is not the calibrated read.

llama.cpp normalizes over the whole vocabulary before it cuts the list, so a
label among the top `n_probs` reads the same as over the whole vocabulary:
idle-fold test 6 compared the house model's label numbers at 16,384 and at its
full 262,144 bit for bit, 20 of 20 identical, and the shorter answer took
about 1.5 s less to serialize per read. Some labels rank below the top
16,384, so a question whose labels are not all listed is sent again, alone
and once, with `n_probs_full`; its time and tokens count in the read (17% of
test 6's 44-label reads needed it). Without `n_probs_full` there is no retry,
so set `n_probs` to the whole vocabulary then, and raise `max_response_bytes`
to hold every question's full answer in one body (about 25 MiB each).

Every answer is checked: no text came back, and generation stopped at the
forced end token, on a retry as on the first call. A read with any question
that fails a check, or still misses a label, is refused whole, typed (`LabelRead`: `EmittedText`,
`NotEosStop`, `MissingLabels`, `Malformed`) and is never read as a
probability of zero.

`person_threshold` starts the PersonThreshold row high, so "ask a person?"
stays rare (0.9 asked nobody on test 5's held-out set) until the Coach tunes
it from the cases where a person changed the answer. A host passes it to
`DecisionBandPolicy::set_person_threshold`. Without the row, the person
reading is recorded on every receipt and routes nothing.

`think_threshold` starts the ThinkThreshold row: a paired "does this need
more thinking?" reading (Q2) at or above it lets the call step up a rung
while its clock allows (`ReasoningCause::PairedHigh`). The house read
measures Q2 jointly with each question's labels. A generated read (a
caller's own model, `DecisionLadder::run_pack_generated`) asks the ladder's
paired question, the recipe's `paired` wording, beside each of its questions
in the same generation, and reads its P(yes) per question. A host passes the
value to `DecisionBandPolicy::set_think_threshold`. A door a host builds
itself has no row, so its Q2 readings stay on the receipt and route nothing.

"Ask a person?" asks for escalation, not for an actor. Who the ask goes to is
the caller's: it sets `DecisionLadder.ask_to` to an `AskTo` (the role asked,
`Responsible { actor, project }`, `Board { project }` or `Owner`; the highest
`RoleRank` it may climb to; and the act an answer authorises). With none set,
the ask goes to the vault's owners, as before. When `DecisionAsks` queues the
ask, the vault resolves the first role on the chain that has a live holder:
the responsible actor, then the boards of its project and that project's
parents, then the owners, cut at the ceiling. A live person or a live bound
agent can hold a role. An `ESignature` or `Payment` act resolves only to a
person. When no role up to the ceiling has a holder, the ask stays unresolved;
it never goes wider. A holder answers through `DecisionAsks::answer_as` with
its verified `WriteActor`, and the door reads the role's holders again before
it takes the answer. The owner door answers any ask whose ceiling is `Owner`.
`DecisionAsks::climb` moves an open ask to the next role. The answer keeps the
role and the kind of actor that gave it.

To tune it, the host keeps each changed answer
(`HumanDecisionRequest::changed_by`) with `Vault::record_person_changed_answer`,
bound to its ask. The Coach's nightly `coach.person_threshold` job (a host job:
lease it with `admit_next_coach_host_job`, run it with
`Vault::run_coach_person_threshold`) reads each record once, asks the host's
`PersonThresholdPolicy` for a number and files it as a Proposed
`coach.person_threshold.proposal` row. The Coach never sets the live row; the
host applies an accepted proposal with `set_person_threshold`.

The owner can probe the read at `POST /v1/llm/decision_read`
(`oneiron.skills.md`): it returns the raw read, writes nothing and decides
nothing. Each probe is a paid call on `models.raw_budget_units`, and past
`[limits] decision_reads` probes wait their turn.

The decision read takes yes/no and choice questions over text. A Box question
("where is `mug` in `camera`?"), and any question over images, goes only to a
rung that reads images: a host `DecisionModel` whose `reads_images` is true
(the Local-vision seat at the Local rung, below), or the opt-in System One
rung and seat (`decide_at_remote_seat`). The ladder skips
every other rung (`DecisionLadder::run_images`, `run_pack_images`). A Box
answer is `{top, bottom, left, right}` in 0–1 fractions of the image from its
top-left corner, edges in order, with its confidence; it is `null` when the
target is absent. The box centre is the point answer. A call carries at most
8 named PNG or JPEG images, 10 MiB each and 20 MiB in all. Each fills the
state field of its name, and each receipt keeps every image's evidence ref
and body version, never its pixels. The System One seat sends each image as an
asset, downscaled to a 1,568-pixel long edge (a box in fractions reads the
same on the smaller copy), with the `TypeSafe-Danger-Zone-Images: true`
header that Jev 1.14 needs for images and boxes.

A question can also hear audio clips (`DecisionLadder::run_media`,
`run_pack_media`): at most 4 named WAV or MP3 clips, 10 MiB each and 20 MiB in
all, named apart from the call's images. Each fills the state field of its
name, and each receipt keeps every clip's evidence ref and body version,
never its samples. Only a rung whose `reads_audio` is true takes a call with
clips, and a call with images and clips only a rung that reads both; the
ladder never drops one to fit. The Big rung hears audio when the vault
manifest's binding of its role says `reads_audio = true` and every rung
serving that model has `audio_input`. With no manifest, the seat's
`audio_input` capability is the declaration. It sends each clip as a chat
`input_audio` part after a line naming it. No other rung hears audio yet.

## 10. Media calls (`ai.image`, `ai.video`, `ai.speech`, `ai.transcribe`, `ai.embed`)

Image, video, speech, transcription and embedding calls have their own seats,
outside the text tiers: one ladder per operation in `[models.media]`, each rung
`"<provider>:<model>"` on an OpenAI-compatible provider (`openai-compat` or
`local-openai-compat`, keyed by `key_env` or `key_secret`), or an image or
video rung on a `gemini` provider (below). A
media call is admitted, sent and settled like a text call:
each rung it reaches gets its own permit on the media meter, an offer refused
for a limit rests and the call goes to the next rung, and the run's receipts
show every rung.

```toml
[models.media]
budget_units = 10000000          # the media meter, in token units

[models.media.image]             # POST /v1/images/generations, /v1/images/edits
rungs = ["openai:gpt-image-1"]
max_references = 8               # reference images make the call an edit
rates = [{ unit = "image", per = 1, tokens = 4000 }]

[models.media.video]             # POST /v1/videos, polled, then /content
rungs = ["openai:sora-2"]

[models.media.speech]            # POST /v1/audio/speech
rungs = ["openai:gpt-4o-mini-tts", "local:kokoro"]

[models.media.transcribe]        # POST /v1/audio/transcriptions
rungs = ["local:whisper-large-v3"]

[models.media.embed]             # POST /v1/embeddings
rungs = ["local:qwen3-embedding"]
```

A media rung on a `key_secret` provider sends through the credential broker
(§2), as a chat call does. The server builds each exchange's exact request,
and the broker checks it against the exchange's own shape before the key is
read at the custody door. That covers an image (JSON, or a form with
references), an edit, speech, a transcription, an embedding, a video's start,
poll, clip and removal, and the Gemini API's generate, job start, operation
poll and file. The broker adds the key: Bearer on the OpenAI-compatible paths,
`x-goog-api-key` on the Gemini API's. A JSON or form request is at most
16 MiB. Speech, a video clip and a Gemini file stream back in 1 MiB frames,
up to 512 MiB, and are checked for the key, never rewritten: a reply that
holds it is cut, and the call fails. Each exchange must finish within the
provider's `timeout_secs` (120 s by default), so raise it for long clips. A
Gemini file's one redirect is followed only under the API's own origin.

A `gemini` provider is Google's Gemini API, its origin as `base_url` and its
key in `key_env` or `key_secret` (sent as `x-goog-api-key`). It serves the image and video
seats only. An image is `models/{model}:generateContent` asked for image
output: the instruction and each reference image go inline, a `size`
(`"WxH"`) or `width`/`height` becomes the nearest drawn `aspectRatio` and an
`imageSize` (`1K` up to 1024 px a side, `2K` up to 2048, else `4K`),
`aspect_ratio` / `image_size` name them outright, and any other param joins
`generationConfig`. It is charged the tokens the answer counts. A video is a
Veo job (`models/{model}:predictLongRunning`; one reference image is its first
frame). `seconds` becomes `durationSeconds`, a `size` an `aspectRatio` and
`resolution`, and other params go as `parameters`. The poll reads the
operation, and a finished job's clips are fetched from the file URIs it names:
the key goes to the API's origin only, and the one redirect to storage is
followed without it. The operation names no clip length, so a clip is charged
its call's reservation. The API has no cancel for a Veo job, so a cancel lets
the job go here and the provider finishes it unread.

```toml
[models.providers.gemini]
kind = "gemini"
base_url = "https://generativelanguage.googleapis.com"
key_env = "GEMINI_API_KEY"

[models.media.image]
rungs = ["gemini:gemini-2.5-flash-image"]
max_references = 3

[models.media.video]
rungs = ["gemini:veo-3.1-generate-preview"]
```

A provider that counts tokens is charged them; one that counts images,
seconds or characters is charged its row's `rates` (defaults: an image 4000
tokens, an audio second 50, a video second 10000, four characters of speech
one). `inputs = ["text", "image"]` narrows or widens what a row takes.

An embed row takes text only until its `inputs` widen it (`inputs = ["text",
"image", "audio"]` for a multimodal model). Texts go as one `input` batch. A
call with an image or audio sends each part as its own document in the chat
form (`messages` in place of `input`, an image as a `data:` URL, audio as
`input_audio`), as vLLM serves multimodal embedding models, and gets one vector
per part, in order. Every vector of one answer has one width, the `dimensions`
param's when the call names one. The stored-media backfill and the context
pack's `media` query embed through this row, and each refuses a vector whose
width is not its space's declared width.

The verbs, each the owner's and checked against the vault's inference policy:

- `GET /v1/ai/options?operation=image&inputs=text,image`: every row the
  caller could call now (text seats' rungs too), where it runs, what it
  takes, its rates, `cost` (its price per million tokens as the vault's model
  registry holds it; `null` when no registered row prices it), `units_left`
  (what the meter its call spends has left: the raw routes' for a text row,
  the media meter for the rest), and `media_units_left`. A caller the `ai.*`
  doors refuse (anyone not owner-grade, a run's agent too) gets no rows. A row
  the vault's inference policy refuses is left out, as is a rung whose
  provider is down, whose one probation request is out, or that a limit
  holds, until it is back. The facade's and MCP's `ai.options` list the same
  rows.
- `POST /v1/ai/image`, `/speech`, `/transcribe`, `/embed`:
  `{"prompt": "...", "input": [parts], "references": [parts], "params": {...},
  "model": "<row or seat id>"}`. A part is `{"kind": "text", "text": ...}` or
  `{"kind": "image" | "audio", "media_type": ..., "data": "<base64>"}`. The
  answer is `{"model", "parts", "usage"}`.
- `POST /v1/ai/video` answers `202` with a job ticket; `GET
  /v1/ai/video/{job}` polls it, and `DELETE` stops it or drops it once it
  ended. A job's permit is held while it renders and settled when it ends.
  The server keeps each job in the vault: a restart loses none (the server
  takes each running job up again as it starts, on a fresh permit, and sends
  nothing again; a job it could not take up is retried on its next poll),
  and a finished job answers with its clip on every poll, a lost reply's
  included, until it is deleted.

Seats show in `GET /v1/ai/status` as `media.<operation>`.

### Voice on the media seats

A speech call can name its voice: `"voice": {"kind": "stock", "name":
"alloy"}` for a provider's own voice, or `"voice": {"kind": "bank",
"voice_id": "...", "include_generated": false}` for a banked identity. A
banked voice lives in the vault's reference bank. A provider sees only the id
of the clone recorded for its target, and the target is the rung's provider
name in `[models.providers]`. The call binds the voice on every rung of its
ladder whose target already holds a current clone (or, on a rung that
renders from the bank's refs, the identity's fenced clip) under consent still
in force. It goes only to those rungs, in ladder order, each in its own
binding. When one is down, rate-limited or out of quota, the call moves to the
next rung that holds the voice, never to one that does not. No voice is cloned
and no consent is asked mid-call, and the owner's fallback (`use_fallback`)
takes no voiced call. When no rung that holds the voice answers within the
vault's longest wait, the call ends with the provider's failure (`502
provider_unavailable` here), and a repeat call after recovery renders. With no
rung holding the voice, the call answers `409 voice_not_provisioned`. Each
rung's binding is checked again before the call goes out on it. If the voice
is withdrawn or its clone re-recorded while the call renders, or everywhere
while it waits, it answers `409 voice_withdrawn` and no audio is returned. A
stock voice (or a raw `voice` param) is one provider's name: it stays on the
first rung whose row serves the call. A call that names a voice names no
`voice` param, and only a speech call names one. Each receipt lists a rung
it skipped for the voice as `voice_not_held`.

The speech seat also takes the hosted voice tiers, which are not
OpenAI-compatible. A `cartesia` provider speaks Cartesia's `POST /tts/bytes`
with its key in `x-api-key` and a `Cartesia-Version` header (`2026-08-14`
unless `headers` names one). An `elevenlabs` provider speaks ElevenLabs'
`POST /v1/text-to-speech/{voice}` with its key in `xi-api-key`. Either one
serves the speech seat only, never a role or another media seat. Each call
names a voice, typed or as the `voice` param (these wires have no default
voice), is asked for raw 24 kHz PCM16, comes back as a WAV, and is charged
its characters. Name the providers `cartesia` and `elevenlabs_flash` to
share the clones the cascade's hosted adapters record.

```toml
[models.providers.cartesia]
kind = "cartesia"
base_url = "https://api.cartesia.ai"
key_env = "CARTESIA_API_KEY"

[models.providers.elevenlabs_flash]
kind = "elevenlabs"
base_url = "https://api.elevenlabs.io"
key_env = "ELEVENLABS_API_KEY"

[models.media.speech]
rungs = ["cartesia:sonic-3.6", "elevenlabs_flash:eleven_flash_v2_5"]
tiers = { "tts-live" = "cartesia:sonic-3.6" }
```

The shipped `tts_live` voice row is `own_server`, so a vault that speaks live
on Cartesia sets that row's locality to `third_party`.

A `voxcpm2` provider is the own-server VoxCPM2 worker (`deploy/voxcpm2`). It
keeps no clones. A banked voice renders on it from the identity's own source
clip and transcript: the named register's clip in the cascade, or the
identity's first source clip for an `ai.speech` call. Generated refs are
never used. The bank fences the clip at its revision of the identity's refs,
and checks it again before the clip is sent and before the audio comes back.
The worker speaks in no stock voice. Its `base_url` must be
`http://127.0.0.1:<port>`, it is never reached through an environment proxy,
and `key_env` names the worker's `VOXCPM_TOKEN`. A reference never goes to a
`third_party` route.

```toml
[models.providers.voxcpm2]
kind = "voxcpm2"
base_url = "http://127.0.0.1:8769"
key_env = "VOXCPM_TOKEN"

[models.media.speech]
rungs = ["voxcpm2:voxcpm2", "cartesia:sonic-3.6"]
tiers = { "tts-live" = "voxcpm2:voxcpm2" }
```

The two-way voice cascade speaks and hears on these seats too. Bind voice
tiers to rungs on the speech and transcribe seats:

```toml
[models.media.speech]
rungs = ["openai:gpt-4o-mini-tts", "local:kokoro"]
tiers = { "tts-live" = "local:kokoro", "tts-deferred" = "local:kokoro" }

[models.media.transcribe]
rungs = ["local:qwen3-asr", "openai:gpt-4o-transcribe"]
tiers = { "asr-live" = "openai:gpt-4o-transcribe", "asr-batch" = "local:qwen3-asr" }
```

The vault's voice rows (`asr_live`, `asr_batch`, `tts_live`, `tts_batch`)
name a tier and a locality. A lane runs on the one bound rung that matches
both, picked before any work. No rung, or two rungs, refuses the lane, and
no other rung is relabelled to fill it. The vault's inference policy admits
the route. The cascade's TTS port (`MediaTtsAdapter`) sends each flushed
sentence as one speech call that asks for a mono PCM16 WAV. Its ASR port
(`MediaAsrAdapter`) sends each utterance the host cuts as one transcription
call, in a WAV of the stream's rate. Each call goes on its own permit through
the media gate and is charged its characters or seconds. A transcription
whose provider reports no duration is charged the length of the WAV it was
sent. These calls are buffered, so live partial transcripts wait for a
streaming media lease.

### The server's own voice loop (`[models.voice]`)

With `socket` set, `serve` listens there for the sibling process that carries
a call's audio (Linux; elsewhere the socket is not bound and voice stays
off). The socket's parent must be an existing owner-only runtime directory.
The socket is created 0600 and removed when serve stops. One call runs at a
time; a second connection waits for the first to end.

```toml
[models.voice]
socket = "/run/oneiron/voice.sock"
extraction_prompt_file = "prompts/voice-extraction.md"  # or extraction_prompt
stock_voice = "alloy"          # or bank_voice = "<voice id>"
queue_capacity = 64            # media calls queued (default 64)
call_budget_units = 64000      # each call's line for the host's own calls
```

`serve --voice-socket <path>` names the socket over the file's `socket`, checked
the same way, where `[models.voice]` sets a prompt or a voice; with neither it
names nothing.

A call opens with one JSON line:
`{"op":"hello","token":"v2.slip...","binding":{"timestamp":..,"nonce":"..","signature":".."},"sample_rate":16000,"channels":1}`.
- The token and binding proof are the owner's capability slip and a fresh
  transport proof, the same ones the HTTP API takes in `Authorization` and
  `x-oneiron-binding`.
- They pass the same doors at the on-device locality, then the owner door.
- A refused hello (a bad or missing token among them) is answered with one
  line, `{"op":"refused","code":"<code>","reason":"<plain text>"}` and a line
  feed, and the socket closes before any audio. The `code` is one of
  `writes_frozen`, `no_hello`, `not_hello`, `credential`,
  `not_capability_slip`, `not_enrolled_device`, `managed_owner`, `nonce`,
  `scope`, `owner`, `principal`, `room`, `roster`, `payer_missing`,
  `payer_needed`, `agent` and `unavailable` (the call could not be prepared
  on this host). The `reason` never carries a token, a proof, a MAC or a
  nonce. An admitted call is answered `{"op":"accepted"}`; a failure after
  that is an `{"op":"error","code":".."}` frame.
- On a managed vault (`serve --managed-by-hypnos`, its `[models.voice]` from
  `--settings-file` and its socket from `--voice-socket`) the hello carries no
  slip:
  `{"op":"hello","managed_owner":{"holder_ref":"..","mac":".."},"issued_at":..,"nonce":"<32 lowercase hex>","sample_rate":16000,"channels":1}`.
  `managed_owner` is the supervisor's `ManagedOwnerAction` for the vault's
  owner, signed with `ManagedOwnerRequest::voice(room, roster, &body)`, where
  `body` is `managed_voice_body(issued_at, &nonce)`.
  The transcript is v2: a keyed BLAKE3 under a key derived from the spawn
  token with the domain `oneiron/managed-account-owner/v2`, over the vault
  name, `holder_ref`, the method, the path, the raw query (right after the
  path), the three bound values and the body, each prefixed with its length
  as eight big-endian bytes. A voice hello signs method `VOICE`, path
  `/voice`, an empty query, the hello's `room` and `roster` (empty when
  absent) as the first two bound values with the third empty, and a 24-byte
  body: `issued_at` (Unix seconds) as eight big-endian bytes, then the 16 raw
  bytes of `nonce`. The `nonce` is 16 fresh random bytes for each hello,
  sent as 32 lowercase hex characters; a managed hello without one, or with
  one of any other form, is refused `nonce`, and no other hello carries one.
  The vault takes each attestation once, within 60 seconds of its
  `issued_at`; two calls opened in the same second sign apart by their
  nonces. The call then runs as that person off-device, while the owner door
  still names them the vault's live owner (checked again every five
  seconds). Each call is admitted like a served write, so a frozen vault
  takes no call, and a call in flight keeps a reap from finding the vault
  quiescent. A slip hello on a managed vault without its enrolled machine's
  claim, or a managed hello on a plain one, is refused.

After that the stream carries:
- **the transcript ops** (`open`, `partial`, `final`, `close`);
- **media in:** `pcm` (STANDARD base64 of whole PCM16LE samples, at most about
  12 KiB raw a frame), `cut`, `speaking`, `roster_changed`, and
  `drained{generation}` once a `generation_end`'s audio has all played;
- **media out:** `pcm{generation, sample_rate, data}` (mono PCM16LE),
  `generation_end`, `flush`, `playout_stop`, `safeguard`, `notice`,
  `memories{generation, found, heard, withheld, part, parts, receipts}` and
  `session_ended`. A turn whose retrieval found rows sends `memories` with
  its first event: how many rows were found, how many the brain heard, how
  many the audience's read withheld, and the read's narrowing receipts. The
  receipts split across frames numbered `part` of `parts` and are never
  dropped. The client shows them to the owner; they are never spoken.

How a call runs:
- Each heard final is answered by the chat role as `/ai/chat` answers it: the
  default agent's instructions, the call's earlier turns and the transcript,
  with tools off, on the owner's budget line (`[models.chat]
  turn_budget_units` a turn).
- Each sentence is spoken on the vault's live TTS route while its safeguard
  runs.
- Partials are enriched with the extraction prompt on the runtime's
  summarizer route, which must name a model that `[models]` serves.
- The enrichment and the safeguard model run on the call's own line.

A full media queue makes heard audio wait for the next cut and a sentence
wait for room. A queue that takes nothing for 30 seconds stops the reply.

#### Live hearing on Soniox

When the vault's `asr-live` row is bound to a soniox rung, the call hears the
owner live instead of transcribing each cut:

```toml
[models.providers.soniox]
kind = "soniox"
base_url = "wss://stt-rt.soniox.com/transcribe-websocket"
key_env = "SONIOX_API_KEY"

[models.media.transcribe]
rungs = ["soniox:stt-rt-v5"]
tiers = { "asr-live" = "soniox:stt-rt-v5" }

[models.media.transcribe.rung_options."soniox:stt-rt-v5"]
language_hints = ["ja", "en"]   # the default; config replaces it
```

- A soniox provider takes a `wss://` URL only, and needs `key_env`. The key
  is sent as `Authorization: Bearer` on the socket's upgrade and nowhere
  else. A soniox rung serves the transcribe seat only, and a buffered
  `ai.transcribe` call on it is refused.
- The socket opens when the call starts, on a stream lease of its own on the
  media meter. Microphone audio goes out as it arrives, and a keepalive goes
  after 5 seconds with nothing sent.
- Each hypothesis is a partial of one utterance, at the next revision, and
  is enriched as a wire partial is. Soniox's own endpoint changes nothing:
  the owner's `cut` finalizes what was said, and that one final starts the
  reply.
- At 10 minutes of audio the socket ends, and the next one opens on a fresh
  lease. Words finalized before the switch stay in the utterance still open.
- A socket that drops is reconnected once, on a fresh lease. A drop means
  the socket fails or closes early, or Soniox reports error 408, 500, 502,
  503 or 504. The words already final stay in the utterance still open, and
  audio not yet sent goes to the new socket. A cut whose `<fin>` never came
  is answered with the words already final. Words Soniox had heard but not
  made final are lost. A second drop before the new socket answers fails
  the hearing.
- A live failure ends the call. A failure here means a drop that the
  reconnect did not clear, any other Soniox error, a frame that does not
  parse, or more than 4 MiB queued. Nothing falls back to batch
  transcription.

### Lazy images and `ask_image`

A read serves each generated image down a ladder. A reader whose request
says it takes images (`"image_input": true`) gets the full image when it
fits. If it doesn't fit, the reader gets a 384-pixel JPEG thumbnail beside
the image's description. If that doesn't fit either, it gets the description
alone. Every rung carries the image's view handle (`<asset>@<hash>`). When
nothing fits, the body is omitted and the vault asks whether everything is
okay (`limits.image_room_bytes`, 32 MiB by default, is the room a model
call's context gets when its host names none). The agent verb
`vault.images.view` (`{"handle", "region": {"x", "y", "width", "height"},
"edge"}`) fetches the full pixels behind a handle: the whole image, a crop,
or a zoom to `edge` pixels.

A hydrate (`/v1/core/hydrate` or `/v1/core/batch/shortId/hydrate`) that
takes images can also name its task (`"task": "Find the receipt's total"`).
When `[models.decisions.image_pick]` words the pick (§13), the host then
asks, for each image it would serve in full, whether the task needs it. The
question reads the task and the image's description, and goes up the
ladder's quick rungs only, to System One, each image on its own `budget_ms`
clock. Only an answer of no inside the band steps the image
down to its thumbnail or its description. An abstain, an answer outside the
band or a failed call serves the image in full. The pick is read for the
caller's principal, or the vault's owner for an owner-grade credential that
names none.

`POST /v1/ai/ask_image` (`{"handle", "question", "region"}`) asks a small
vision model about the pixels instead, so they never enter the asker's
context. Bind that model as its own role:

```toml
[models.roles.local_vision]
rungs = ["local:qwen3-vl-4b"]
```

Its provider needs `image_input` among its capabilities. The answer is
`{"asset_ref", "text", "receipt"}`.

Add `"contract": {"kind": "box"}` (or `"point"`) to ask where something is
instead ("where is the mug in `image`?"). The same seat then answers as the
decision ladder's Local rung (`LocalVisionModel`, a `DecisionModel` that
reads images). It reads the whole image (a Box or Point ask takes no
`region`) and answers with a JSON schema shaped like System One's box
answer; a Point is the box's centre. When the house decision read words a
presence question, the ladder asks it first ("is the target in the
image?"). A confident no answers "absent" without asking for coordinates.
An answer still inside the band steps up to the System One seat
(`[models.decisions.system_one]`) when one is bound.

The answer is `{"asset_ref", "answer", "typed", "presence", "receipt"}`:
- `answer` is the answer on the contract: `{"kind": "box", "value": {top,
  bottom, left, right}}` in 0–1 fractions of the image (a Point's `value` is
  `{x, y}`), `"value": null` when the target is absent, or an abstention.
- `typed` is the decision that stands, with its confidence as `probability`
  and its receipt (the rungs' pins and the image's evidence version).
- `presence` is the presence step, when the coordinates stand on it.

The ask runs on a 60-second clock and queues no person.

Each rung served and each pull (view, crop, zoom, ask_image) is a
`served_form` receipt, so `vault.receipts` shows which rung each image got and
whether the pixels were pulled afterwards.

The same seat answers `ai.verdict` over an image: name its view handle as
`"image"` (the question calls it `image`). The pixels are pulled through the
caller's own scoped read, the image rides the receipt as an evidence ref
with its body version, and the call starts at the Local rung on a run of its
own. There the seat answers a Choice (`{"choice", "confidence"}`), a yes/no
(`{"p_yes"}`) or a Box; a Point is the Box's centre. A rung above Local that
reads no image is skipped.

The request's `contract` says what the answer is: `{"kind": "noul"}` (yes or
no with P(yes), when absent), `{"kind": "choice", "options": [...]}`,
`{"kind": "score", "min": 1, "max": 5}` (one number in that range, in the
units and direction the question names), or `{"kind": "box"}` /
`{"kind": "point"}` (where the target sits in `image`, as fractions of it
from its top left). The call starts at the first rung whose provider takes
its contract over its images, so a Score starts above the rungs that read
none. No image seat reads a score: a score over an image is refused, never
asked without its image. A Box or Point asks the host's presence question
first. A confident no answers `{"kind": "box", "value": null}` (or `point`),
and the answer carries `presence`, that step with its own P(yes); `p` is
the coordinates' confidence, and empty when they were not read.

A code-mode program drives a routine browser or computer step through the
same verb (the CUA-S1 pattern): `"routine": true` makes a Choice's
`options` the step's candidates (1 to 61), and the ladder also offers
`NONE`, `reobserve` and `too complicated, ask up`; a routine Box or Point
acts where it finds the target. The answer gains an `outcome`: one of
`{"outcome": "act", "candidate"}`, `{"outcome": "point", "x", "y", "found"}`
(a routine Point, or a Box's centre, as fractions of the image),
`{"outcome": "none"}`, `{"outcome": "reobserve"}` or
`{"outcome": "ask_up", "reason"}`. A routine step's Box or Point that finds
no target reads as `none`. A ladder abstain reads as
`ask_up`, with the ladder's reason (uncertain, deadline, no rung). The
program passes the count of NONE and reobserve outcomes in a row as
`"misses"`, and `"screenshot": true` says the next observation takes a
screenshot (the second miss in a row). One subgoal shares one clock: the
answer's `until_ms` (Unix milliseconds) goes into the next step's request,
so a reobserve or a retry never restarts it. One call still runs at most
60 seconds. Name `"reversibility": "outbound_effect"` for a step whose
effect leaves the vault: at a cut it abstains and goes up.

A computer step runs on the run's own desktop guest, a Linux desktop the
`[desktop]` section names (`runtime`, a digest-pinned `image` built from
`crates/oneiron-container/guest/desktop`, and the same bounds as
`[browser]`). Its `build.sh` builds the image on a Linux host, pushes it
nowhere, and prints the local image id to pin (its README.md). The section is refused on macOS: the guest never runs on, or
drives, the owner's own desktop. A program drives it with `self.desktop.*`:
the browser's verbs over one window's accessibility tree (`open` takes
`app:<name>` from the guest's app set), plus `key`, `hotkey`, `scroll`,
`windows` and `window`. Its batches take `key`, `hotkey` and `scroll` steps
beside the browser's, and its routine steps call `ai.verdict` the same way;
a window with no tree reads `no_tree: true`, and a click-only step there
locates its target in a `no_accessibility_tree` screenshot. A Return, or
typed text with a line break, takes the press of a send, and every effect's
receipt screenshot has its password fields blacked out before it is held.
The desktop rides the `oneiron.browser` pack and its grants.

The owner can take a run's desktop over and hand it back. A program asks
with `self.desktop.handover({reason})`, or the owner takes it unasked, at
`/v1/owner/desktops`: `GET` lists the run desktops with who has each and
the agent's ask; `POST take`, `screen` (the whole display as a PNG,
unmasked, never kept), `input` (`{"run", "action": {"kind": "click" |
"type" | "key" | "hotkey" | "scroll", ...}}` at that PNG's pixels) and
`return` each take `{"run"}`. While the agent waits on its ask and while the
owner holds the desktop, every desktop verb refuses `desktop_taken_over` (a
batch stops `NEEDS_YOU`) and no receipt screenshot is taken. Handing it back
writes the takeover's record (who, the ask, when it was taken and returned,
how many inputs) as the run's `desktop_takeover` sandbox receipt, and the
agent's next desktop answer carries it as `takeover`. When the window the
agent's verbs read is gone (a dialog closed, an app quit), the session
reads the window in front, and the next answer names the move as
`switched` (`{window, app, title, from}`). Both are typed on every browser
and desktop answer in the code-mode declarations.

A handover is each owner's inbox Ask (producer `guest.takeover`): its source
names the run, its result is the take route, and its `detail` is the
agent's reason. Taking the desktop or handing it back clears it, and so
does a server start, since no run guest outlives the server. `GET
/v1/owner/desktops/stream?run=<hex>` streams the display as server-sent
events while the owner watches or holds it: `state` (the takeover), `frame`
(`{seq, png_base64}`, at most every 500 ms and only when it changed),
`error`, `ended` and `refused`. The owner is re-proved at each frame.

The desktop belongs to the run, not to one door. An `execute_code` entry
that does not finish the run leaves it parked, and the run's next entry
gets the same guest and seat; a pumped run's desktop waits through a
durable wait the same way. It ends when the run ends (an entry that
answers complete, or a pumped attempt that settles other than parked), or
after it sits idle with no door of its run: 30 minutes while its agent has
it, 24 hours while the agent's ask waits or the owner holds it. An owner's
act counts as activity; watching the stream does not. A takeover still
asked or held when the desktop ends lands its record so far as the run's
`desktop_takeover` receipt with outcome `abandoned`.

The run's browser takes the same takeover, so the owner can sign in or pay
inside the page the agent filled. A program asks with
`self.browser.handover({reason})`, or the owner takes it unasked, at
`/v1/owner/browsers` (`GET`, then `POST take`, `screen`, `input` and
`return` with `{"run"}`). `screen` is the viewport as a PNG, unmasked and
never kept. `input` takes `click`, `type`, `key`, `hotkey`, `scroll` at that
PNG's pixels, and `navigate {url}` to an http or https page. While asked or
held, every browser verb refuses `browser_taken_over` (a batch stops
`NEEDS_YOU`). Handing it back writes the run's `browser_takeover` sandbox
receipt, the agent's next browser answer carries the record as `takeover`,
and its next observe is whole. The browser belongs to the run as the
desktop does: parked between `execute_code` entries and through a pumped
run's durable wait, with its cart and login, and ended with the run or on
the same idle limits.

On Chromium the owner sees every tab of the browser. A popup or a tab a
link opens (an OAuth sign-in window, a `target=_blank` link) is followed,
reaches the network through the run's proxy as the first page does, and
comes to the front at the owner's next look while the owner holds the
browser. `GET`
lists each browser's `tabs` (`{tab, url, title, front}`); `screen` and
`input` take an optional `"tab"`, which the holder brings to the front. The
tab the owner leaves in front is the one the agent's verbs read after the
return; a front tab that closes gives way to the tab that opened it. `GET
/v1/owner/browsers/stream?run=<hex>` streams the front tab as the desktop's
stream does, with a `tabs` event when the tabs change.

On Chromium the agent's own verbs follow the tabs too. A tab the agent's
click opens comes to the front once it loads, and the click's observation
reads it whole; a tab opened between calls comes to the front at the next
verb; and a front tab that closes while the agent drives it gives way to
the tab that opened it, else the newest. The next answer names the move as
`switched` (`{tab, url, title, from, why}`, `why` being `opened` or
`closed`). Lightpanda serves one page per guest and follows no popup: a
verb that meets a second tab, or a new tab once its only page closed,
refuses `browser_unsupported`, as `click_at` does there, and the refusal's
detail names `self.browser.switch_engine` as the way to Chromium.

A run's browser starts on the engine the `[browser]` section's `engine`
names: `lightpanda`, the default and the engine agents start on, or
`chromium`. Every browser answer names the engine that ran it as `engine`,
read verbs included, and so does every effect receipt. An act whose page
showed no change at all within about a second of its input answers at once
with a `fact` on its observation and its receipt: `click_no_effect` (a
`click` or `click_at`), `type_no_effect` (a `type` or `select` whose
target's value did not move either) or `navigate_no_effect` (an `open`
whose navigation started nothing), each with the engine, the target or URL,
the reason `no_observable_change` and `window_ms`. A fact is never a
refusal: the act still answers and is receipted, a batch runs on, and
nothing changes engine by itself. A Lightpanda guest takes CDP messages up
to the egress door's `max_response_bytes` in base64 plus 1 MiB, so one
setting moves both.

`self.browser.switch_engine({engine, reason})` moves the run's browser to
the other engine when the model decides a page does not work on this one.
It carries the page's URL, its cookies, the local and session storage of
every top-level origin its tab visited, and its scroll position. The
current origin's stores are read at the switch; every other origin's come
from the session's last read of them while a document of it stood: right
before each act's input (inside the change check's mark, in its window),
once each act's or open's page settled, before a person's input in a
takeover and when they hand the browser back, and on Chromium as each
document is left (a `pagehide` listener in an isolated world of the
driver's own, which no page script sees). Lightpanda 1.0.0 fires no
`pagehide`, so writes a page made after its last read, before it was left,
are not seen. The new engine's guest starts as the first one did (its own
fence, the run's egress door); it takes the cookies first, then each
origin's storage, one origin after another and the current one last,
written into a one-shot document of that origin which the host answers
itself, so no page script runs before it, and read back key by key; then
it loads the URL, scrolls, and reads the page whole. The answer carries
the switch's `receipt` (verb `switch_engine`), whose `engine_switch` is its
record (`{from, to, reason, url, carried, not_carried, outcome}`), and the
new page's `observation`. A carried store names its origin, its item
count, its `phase` (`pre_input`, `post_act`, `exit`, `hand_back` or
`switch_export`) and `after_receipt`, the last receipt the run had landed
when it was read. `not_carried` lists, by component, origin, cookie
`name@domain` and attribute, never a value, what the new engine does not
hold exactly and why: Lightpanda refuses some cookie attributes (a
priority other than Medium, `sameParty`, `sourceScheme`, `sourcePort`) and
ignores `partitionKey`; an origin no read caught reads `never_sampled`;
one whose page may have written after its last read reads
`departure_tail_unobserved`, with that read's `after_receipt`; a store that
gave no answer, threw or was past the bounds reads `context_lost`,
`read_exception` or `limit`; an origin the session's snapshots gave up to
stay within their bounds (64 origins a tab, 64 MiB in all, oldest read
first) reads `evicted_oldest`; an in-page frame of another origin reads
`cross_origin_frame`, a sandboxed page `opaque_origin`, a file or data
page `not_web_page`, and a Lightpanda page that relaxed `document.domain`
`effective_origin_mismatch`; a store that did not read back as written
reads `readback_mismatch`; the browser's other tabs read `other_tab`. The
browser switches all the same. A switch fails
(`outcome` `{state: "failed", stage, code, detail}`) only when the new
engine's guest does not start, its driver does not attach, it refuses the
cookies or it does not load the URL; the page then stays on its engine as
it was. The engine already running answers `unchanged`. Each switch,
switched, unchanged or failed, is one receipt in the run's sequence. The
run keeps its press policy and spent batches, its receipts, its takeover
record and its library; handles, observations and held images start anew
on the new engine, so its first read is whole.

Each row of a browser observation carries `ref`, a live handle
(`h<token>:<n>`), and `locator`, its semantic name built from its role,
its accessible name and its named ancestors. A handle is bound to one DOM
node of one document (the tab, the frame, the frame's loader and the
document root, as CDP reports them when the page is read) and is never
reused within the session: not after navigation, a hand-back or a tab
switch. An act takes the handle's own node while it is still in its
document. Once that node is gone (detached, replaced, or its document
navigated away), the act runs once, through the same press and payment
checks, on the first row its locator names now, and the answer and its
receipt carry `rebound` (`{old, new, old_scope, new_scope, locator}`); a
locator that names several rows takes the first and adds `ambiguous` and
`candidates`. A handle the session never minted, or one whose locator
names no row, refuses `browser_stale_ref` as before. `wait_for`, `expect`
and batch steps list such matches as `rebindings`. A replay program (the
library) stores locators only: a proposal's handles are put back to their
locators before the program is checked, and each step resolves its
locators as it runs. A desktop row has no live handle: its `ref` is its
locator.

An observation names its `seq` and its `scope` (`page:` and the documents
it read, or `window:` and the desktop window). It is whole (`full: true`),
or an ordered edit of an earlier observation of the same scope that the
caller holds whole: `base_seq` names that one, and `splice`
(`{start, delete_count}`) names its rows that give way to `rows`, so the
rows read now are the base's rows before `start`, then `rows`, then the
base's rows from `start + delete_count` on. A row that only moved changes
the splice. An effect or `observe` edits the base its input names
(`base: {scope, seq}`), or else the last observation the caller read whole,
every page of it; reads the caller never sees (a routine step's looks, a
library check, a batch's steps before its last) never move that base.
`observe({full: true})` reads whole, as `open` does. A base the session no
longer holds, of another scope, or partial gives a whole observation, never
a refusal. Of the two valid forms the answer carries the one whose pages
take fewer JSON bytes, the whole one on a tie.

A browser or desktop observation comes in pages: an answer whose rows do
not fit one page (256 KiB of rows) carries `next`, and
`observe({cursor: next})` reads the next page of the same observation.
Every page repeats its `seq`, `scope`, `base_seq` and `splice`, with the
`offset` its rows start at; apply an edit once every page is read. The
pages of the last 8 observations stay readable. `find` and `wait_for` page
their rows the same way, read on with `find({cursor: next})`. A desktop
window's tree is read whole: a walk cua-driver cuts at its node budget is
read again with a larger one, and a walk cut at its time budget with a
longer one, up to 12 s. A walk still cut there answers what it reached,
marked `partial` (`{reason, visited, pending, walk_ms}`), as a whole
observation that no later one edits; its last page carries `walk_next`,
and `observe({cursor: walk_next})` walks the window again at four times
the time, up to cua-driver's 120 s ceiling, as a new whole observation
with its own `seq`. A cut is never proof a row is gone: an act on a row
(`click`, `type`, `select`, `key`, `scroll`), and a `find`, `wait_for` or
`expect` that reached no row it seeks, walks the window on itself, longer
each time, until the row is there, the walk reaches the tree's end, or a
walk at the 120 s ceiling is still cut (a wait's own time ends it sooner).
Only a walk that reached the end refuses `browser_stale_ref`; an act whose
row is still past the cut refuses `desktop_tree_cut`. A search still cut
answers what it found, with `partial` on every page and, on the last, a
`walk_next` that `find({cursor: walk_next})` takes to search the window
again, longer; an `expect` that saw no row past a cut is unmet, and a
batch stops on it with `desktop_tree_cut`. A routine `decide` step with
more than 61 candidates asks its decider in pages of 61, moving to the next
page on NONE; a step is never refused for its count, and a batch or a
library program holds one or more steps, never refused for their count.

A browser or desktop `screenshot({trigger})` has its secret fields blacked
out before it is held, and answers the held image by its content ref
(`image`), never a caption, with its `capture_id` (`c<token>:<n>`, from one
counter for the whole session, never reused). Name an earlier capture the
program still holds as `since_capture`: the screenshot is still taken, held
and answered whole, and `unchanged_from` names that capture when the new
image is the same masked PNG, byte for byte, taken in the same scope (the
same documents and URL, or the same desktop window; the same viewport or
window rectangle, scroll, dimensions and scale; the same masking). It means
the same PNG, not that the page did nothing; equal pixels encoded otherwise
read as changed. A capture the session no longer holds (it holds its last
16 images), of another scope, or never its own answers as any screenshot
does, never a refusal. A crop or zoom is no capture. Each effect receipt's
screenshot is a capture of its own (the receipt's `capture_id`), never
compared, and kept as the receipt's evidence even when its pixels repeat.

## 11. When a provider refuses for a limit

A rung refused for a limit hands the call to the next rung of its ladder, and
its offer (adapter, origin, key and model) rests in the vault, so a restart
keeps it:

- **A rate limit** (a 429 that names no long wait) rests for the wait it
  names, or, naming none, for a backoff that doubles with each refusal in a
  row from the vault's default rest, with jitter, up to the longest rest.
- **A spent usage window** ("usage limit", a weekly or monthly allowance, or a
  wait of 15 minutes or more) is parked until the reset it names.
- **Spent prepaid credit** (a 402, "insufficient_quota", "credit balance",
  "billing", Anthropic's `billing_error`) is parked until the owner tops up
  or clears it. The same words in an error inside an open stream read the
  same way.

While only rests stop a call, it waits for the first offer back and tries the
chain again, until its waits pass the vault's longest wait in all (a caller
with its own deadline passes its own budget). A call whose every offer is
parked on credit fails `quota_spent`; one that ran out of wait fails
`rate_limited` with the earliest reset.

Once every rung of a call has parked, each offer parked on a spent window or
spent credit leaves the owner a question in `GET /v1/ai/status`
(`quota_questions`: the provider, model, route, what was spent, the reset if
any, the choices, and `fallbacks`). A call that a later rung serves asks
nothing. `fallbacks` lists the models on other providers that still have
usage left and can take the parked call:

- they speak the seat's wire: a chat model for a chat seat, and a rung of the
  same operation's media seat for a media call (a reranker seat has none);
- they stay on the device when the seat's role must;
- they accept the request itself (streaming, tools, images, audio, a media
  row's inputs).

A speech call that names a voice lists none, since a voice stays on its own
target. While `fallbacks` is non-empty, the choices include `use_fallback`.
Answer with `POST /v1/ai/quota/{id}`
`{"choice": "top_up" | "pay_as_you_go" | "add_account" | "wait" | "use_fallback", "fallback": "<model>"}`:

- `top_up` and `pay_as_you_go` put the offer back in rotation now.
- `wait` and `add_account` close the question and leave the offer parked
  until its reset.
- `use_fallback` names one of `fallbacks` (its engine id). While the offer is
  parked, a call whose every rung has parked goes to that model instead. That
  covers a call, a stream as it opens or after any pass of its chain before it
  has spoken, and a media call. It applies whenever the model's own offer is
  in rotation, the model can take that call, and the call's world may go where
  it runs. The answer keeps the seat's receipt:
  - `rung` is the one after the seat's configured rungs;
  - `provider` and `requested_model` name the fallback;
  - `failed_rungs` and `passed_over` count and list the seat's own rungs
    first.

  Setting it is the permission, paid models included. Once the offer is back,
  calls use it again. The choice is owner policy, kept in the vault's model
  settings rather than with the deployment's cooldowns. A checkpoint keeps
  it, and a restore over a live vault keeps the live vault's choice.

### When a provider is down

A rung whose provider is down hands the call to the next rung, and its offer
rests for its health in memory. A server error, a timeout, a cut stream and an
empty answer all count as down. The rest is 5 s, doubling with each failure
in a row up to 60 s, with jitter. A restart starts every offer healthy. While
every rung the call may use rests, the call waits for the first one back
within the same wait budget as for limits, then tries the chain again. A call
that runs out of wait ends with the provider's own failure, not
`rate_limited`.

When an offer's rest ends it is on probation: a failure rests it again with
one more strike. On probation it takes one request at a time. The call that
sends it holds the offer's probation slot until the request ends: a stream's
last event, or a media job's end. A call that comes meanwhile passes that rung
to the next one. If no rung is left, it waits for the probation request to end,
within its wait budget, and is never refused for it. A stable recovery is three
answers in a row over at least 30 s. It clears the strikes, and the memory
work the outage stopped resumes:

- the attempts this server's Dreamer parked because a provider was
  unavailable are requeued, as a restart requeues them. Each parked attempt
  records its cause, and only `provider_unavailable` counts: a server error, a
  timeout, a cut stream or an empty answer;
- a media backfill that was backing off tries its failing spaces again at
  once.

A recovery never resumes other parked work: work waiting on a signal (a budget
or consent trap, a wait, a seat login), work stopped at the deadline, a
cancelled pass, an executor error, or any other failure.

`GET /v1/ai/status` shows each offer's live health. Each built rung under
`models.seats[].rungs[]` carries `health`:

- `state`: `healthy`, `down` (resting until `until`), or `recovering` (on
  probation);
- `strikes`, `successes`, and `probing` (its one probation request is out);
- any limit `hold` (`until`, `reset`, `spent`), shown apart, since a hold is
  not an outage.

A seat's `state` follows its rungs:

- `ready` while a healthy rung that no limit holds can serve;
- otherwise `recovering` while a free rung is on probation;
- `down` when every built rung rests for its health;
- `unavailable` when no rung could be built.

On raw `/v1/llm/stream`, a stream that fails after it has started ends with
one last line carrying the same typed body as a refusal before it:
`{"error": {"code": "quota_spent", "llm": …, "quota": {…}}}` when credit or a
window runs out mid-stream.

## 12. Batch GPU pods (`[gpu]`)

Re-embeds and backfills are retry-tolerant, so they may run on rented GPU
pods, spot capacity included (ARCH-0019 §5). Queries never do: they stay on
the configured `[embedder]` endpoint. Name one region's pods:

```toml
[gpu]
region = "tokyo"
# Optional: the pods' bearer key. The endpoint's own key never goes to a pod.
api_key_env = "ONEIRON_GPU_POD_KEY"
# Defaults: health_path = "/health", ready_path = "/v1/models", poll_seconds = 15.

[[gpu.pods]]
id = "pod-a"
url = "https://pod-a.example:8000/v1"
capacity = 4
```

`serve` polls each pod at start and then every `poll_seconds`. A pod is
healthy when it answers at all (transport), answers `health_path` with a 2xx
(app), and answers `ready_path` with a 2xx (inference). Both paths resolve
against the pod's origin, so `/health` on `https://pod-a.example:8000/v1` is
`https://pod-a.example:8000/health`. Each document batch
of the endpoint embedder takes a lease on one healthy pod, picked from two at
random by load. The lease renews every 60 s and ends when the batch does. A
lease that lapses mid-batch (the pod was preempted or failed a poll) drops
that batch's answer, and the worker sends it again. With no healthy pod, the
batch goes to the `[embedder]` endpoint. Pods must serve the endpoint's model:
an answer that names another model, or makes vectors another way, is refused
as the endpoint's would be. On a vault bound to an account, each pod's answer
is sealed to that account before it is read. Pod URLs follow the endpoint's
rules: HTTPS unless loopback, and no credential or query in the URL.

## 13. The decision ladder

Every typed decision the server asks (decide()) goes through one ladder,
built when the server starts and lent to each caller
(`SyncServer::decision_ladder()`; the queue, dials and bands are on
`SyncServer::decision_host()`). Its rungs come from the seats you already
bind:

- **Rule**: the host's rule table, always first. It abstains on a question
  it holds no row for, so the call goes to the next rung.
- **System One**: the seat `[models.decisions.system_one]` binds (below).
- **Escalation**: the house model's decision read (section 9), when its
  recipe names the paired question. The recipe's paired question becomes the
  ladder's "need more thinking?" question, and `think_threshold` its row; its
  person question becomes the ladder's "ask up?" question, and
  `person_threshold` becomes its row.
- **Big**: the big model, through the seat `[models.decisions.big]` names
  (below).
- **Local**: the Local-vision seat, when `[models.roles.local_vision]`
  binds one, on its own meter (`models.raw_budget_units`). It answers Box,
  Point and image questions. On a call with no image it abstains before any
  model call, so the ladder steps past it. A caller with a turn budget
  (`ai.verdict`, `graph.ask`) seats its own per-call rung there instead.
- **The owner**: the last rung is a durable queue. Each ask waits in the
  vault until you answer it (owner-actions.md, "Answer the decision
  ladder's asks").

`[models.decisions]` binds the System One seat and words the host's own
questions. A question you don't word is not asked, and its hook stays
unbound:

```toml
[models.decisions]
# The write gate's auto check through the ladder: allow or hold.
auto_check = "Should this claim land without the owner's review?"
# The wire health check's question, past a crossed threshold: a bot, or a
# valid burst. Unlike the other rows, an unworded health check is still asked,
# in the host's own words; a check already asked keeps the words it was asked in.
wire_health = "Is this traffic one of our own tools, or a bot?"

[models.decisions.seat]
# A manifest-backed execute_code run picks its seat through the ladder:
# a model among those described under `facet`, then one of its efforts.
facet = "code-task"
model = "Which model should run this task?"
effort = "At which effort should it run?"
budget_ms = 2000        # each pick's anytime budget

[models.decisions.image_pick]
# A hydrate that names its task asks, for each image it would serve in full:
wording = "Does this task need this image in full?"
budget_ms = 1000        # each image's anytime budget (the default)

[models.decisions.system_one]
endpoint = "https://systemone.example/v1/systemone"   # HTTPS, or HTTP on loopback
key_env = "ONEIRON_SYSTEMONE_KEY"                     # its bearer token
model = "systemone-head"
version = "2026-10-01"
remote_opt_in = false   # a vault that is not hosted sends unit state only with this set
budget_units = 100000   # its own meter; models.raw_budget_units when unset

[models.decisions.big]
role = "generative_reasoner"   # the seat whose model answers (the default)
version = "2026-10"            # the revision the rung's pin names
wording = "You answer one typed question about the state you are given."
reply = "json"                 # or "lines"
budget_units = 50000           # its own meter; models.raw_budget_units when unset

[models.decisions.booking_parse]
role = "checker"        # the cheap seat a booking page's free text is parsed on
max_input_bytes = 4096  # the longest text one parse reads (the default and the most)

[models.decisions.connector_slate]
# A connector's register and refresh doors ask, for each tool on its grant slate:
wording = "What should this connector tool's setting be?"
budget_ms = 30000       # the whole draft's budget (the default)

[models.decisions.import_audience]
# Each topic a history import's claims raise is asked, once:
sensitive_wording = "Is this imported topic sensitive?"
audience_wording = "Who may see what later imports say about this topic?"
budget_ms = 30000       # one topic's sensitivity read (the default)
```

The Big rung asks each question as one model call on that seat. The call is
routed against the vault's live model policy, like a chat turn, and sent under
its own run on the rung's meter. `wording` is the system message. The question,
what it takes and the state follow as the user message, with the reply format:
one JSON object `{"answer", "probability"}`, or two lines `answer:` and
`probability:`. A reply that names nothing the question takes, or no
probability from 0 to 1, abstains, and the ladder moves on. The rung takes
noul, choice and score questions, not boxes.

A booking page's free-text constraint ("tuesday afternoons, not before 2")
is parsed on the `booking_parse` seat, then solved like an object. The parse
asks the ladder whether the text is a scheduling preference at all, with the
seat's read first, and a text that is not one is refused. Then one extraction
call returns the constraint object and, when the text names one, the visitor's
timezone. The sentence never reaches the slot oracle. Each call is admitted as
a call of the seat's role against the vault's live model policy. An
authenticated caller's parse is paid on its principal's line. An anonymous
visitor's parse is paid on the owner's line, since the owner publishes the
page. Without the row, free text is refused, and a constraint object still
works.

A connector's grant slate (`POST /v1/owner/connectors/register` and
`/refresh`) is drafted one tool at a time, up to the Big rung, when
`[models.decisions.connector_slate]` words the question. The question reads
the tool, the owner's past rulings on tools like it and the rule draft, and
picks auto, always ask or never allow; only the owner picks always allow. An abstain, an answer
outside the options, a failed call or a row past `budget_ms` keeps the rule
draft. Without the row, the rule draft alone fills the slate. The owner
stamps the slate either way.

An imported topic's audience (OF-492) is asked once per topic when
`[models.decisions.import_audience]` words the two questions. Serve sweeps
the pending history-import reviews every minute, CLI imports included, since
their extraction runs in serve. It groups their extracted claims by the
extractor's `topic_key` (an exact match; a claim with no topic joins none) and
asks each new topic whether it is sensitive, up to the Big rung. A topic read
as not sensitive is left alone. A sensitive or unsure one goes to the owner's
ask queue as ONE choice: only me, one of the vault's projects (by goal and a
short id; the root and corpora are not offered; at most 62), or everyone the
source shared it with. Both questions show the model and the owner the topic
and up to 16 of its claims. The owner answers on the decision-ask door, and a
later sweep keeps the answer as a standing `disclosure.import_audience` rule
for the topic's LATER imports. The import that raised the ask stays private,
and nothing waits on the answer. Without the row, no topic is asked and every
import stays private.

The System One seat takes noul and choice questions. Each is one call,
admitted and settled on its meter. It never runs on a relay vault. The
escalation read is metered on `models.raw_budget_units`. A model rung blocks
on the server's runtime, so a caller runs a ladder call on a blocking thread.

An `ai.verdict` is paid by its caller (rule 5). Every model rung the call
reaches (Local-vision, System One, the escalation read and Big) admits and
settles on the asking actor's own line instead of its rung's meter, and that
line has no limit, so a verdict is never refused for spend. When one
caller's verdicts spend past 10,000,000 units in a day, the host raises one
"is everything okay: a bot, or a valid burst?" health check naming that
caller. The model rungs, or the owner's ask queue, answer it, and the calls
go on while it is asked.

### Standing questions over graph units

A standing question (a typed question saved over a set of graph units, with
`refresh.every_seconds` or `refresh.on_arrival`) is answered on this ladder
without a caller. Only the vault's home node runs the pump: the node the
vault's home designation names. A server whose vault has no home yet claims
it, so the pump runs with the Dreamer off. The pump sleeps until the next
question is due, and a committed write wakes it early (a question's create,
edit or resume, or a claim write). It also re-reads its due work at least
once a minute, because an arrival on a unit that is not a claim does not wake
it. It answers each unit for the question's own principal, reading under
that principal's grants, and climbs the question's own dial. A dial up to
`human` asks a person by role (OF-516): the ask goes to the question's
principal as its responsible actor and can climb to the vault's owners. The
run is written by the first live holder on that chain, so a question whose
principal is gone runs as an owner. With no live holder up to the owners, the
question waits and is tried again later. Each pass also moves every open ask
whose role has no live holder left to the next role that has one. A role
holder lists the asks at its role at `GET /v1/core/decisions/asks` and
answers one at `POST /v1/core/decisions/asks/answer` (`{"seq", "answer"}`).
The holder is checked again when the answer lands. The same calls are the
SDK and MCP verbs `self.decisions.asks` and `vault.decisions.asks.answer`.
`vault.decisions.asks.climb` (`{"seq"}`) passes an open ask up to the next
role with a live holder. It may be called by a holder of the ask's role, the
ask's principal or an owner. From the CLI, use
`oneiron api raw POST /v1/core/facade/<verb> --data -`. The owner can answer any
of them at `/v1/owner/decisions/asks`. A one-off graph ask still holds
`human` at Big. Each unit has its own
clock: the definition's `deadline_ms` (1 to 60000), or 10 seconds when it
names none.

- **What the ladder reads.** The unit's body and the bodies of its outgoing
  neighbours go into the call's state, as the JSON a reader is served. A
  one-off graph ask reads the same neighbours (up to 16, under the
  principal's grants). A unit whose neighbours sit in scopes that no single
  answer can stay inside abstains before any model runs. The definition's
  `criteria` (`yes_if_all`, `no_if_any`, `not_a_reason_to_say_no`) ride in
  the state as `criteria`. An edit to a line mints the next question version.
- **Images.** When `[models.roles.local_vision]` is bound, the dial spans the
  Local rung, and the definition's `media.images` is on (the default), each
  image asset among the unit and its neighbours is read as an image at the
  Local-vision rung. The pull is recorded as an `ask_image` served form.
  Without that seat, or with `media.images` off, the asset is read as its
  text alone.
- **Audio.** When a rung inside the dial hears audio (the Big rung above), a
  WAV or MP3 audio asset is read as a clip and the call starts at that rung.
  The clip goes to the model as audio, never as a transcript. A unit with
  both an image and a clip starts at a rung that reads both, or abstains.
  Otherwise the asset is read as its text alone.
- **What lands.** Each answer lands as a proposed `judgment.answer` claim,
  readable only by the principal (the definition's `audience` is `asker`). It
  reads no wider than any source it rests on, and it names each of them as
  evidence. It keeps the ladder's full receipt: the providers, band, paired
  and person readings, clock and any owner-ask reason, plus the version of
  every source, image and clip it read. Before the answer lands, the pump
  reads the neighbours and every source again. If any changed, nothing in
  that pass lands.
- **Arrivals.** With `refresh.on_arrival`, a write to a unit queues that
  unit, and so does a write to anything its newest answer rests on: a
  neighbour it read, or a source it names as evidence. Each new answer
  replaces what the one before it rested on. A unit dropped from the
  definition drops its watchers.
- **Failures.** A question that fails is held for five minutes and then runs
  again. An edit or a resume lifts the hold. The server logs the error's
  kind only.

The engine's one-off graph ask and saved graph recipes take the same
answerer and keep the same receipts.

### Typed questions over files

The same ladder answers a typed question over parts of a file. Each unit is
one call, read from the file version the ask pinned:

| Unit | What the call reads | Where the answer lands |
|----|----|----|
| A sheet row | The row's cells across the asked range, plus an optional header row | A cell in the answer column: yes/no as a boolean, a pick as text, a score as a number |
| A paragraph | The paragraph's text | A Word comment quoting it, in your display words |
| A slide or shape | Its text, and its rendered image as an image | A modern comment with a severity band |
| A file in a folder | An office file's text, a text file, or a PNG or JPEG as an image | One cell per file in a column of a result workbook |

**Images.** Images are read at the Local-vision rung when
`[models.roles.local_vision]` is bound and the dial spans the Local rung.
Without that seat, a slide is read as its text alone, and an image file in a
folder abstains.

**Proposals.** The answers become one proposal on a copy. Keep or Discard
settles it once (`vault.artifacts.keep`/`discard`). A unit with nothing to
read abstains and writes nothing; an abstention is never a no. If every unit
abstains, no proposal is made.

**Receipts.** Every answer, abstentions included, keeps the ladder's full
receipt and the file version it read. Keep's receipt carries the sheet
answers and paragraph judgments next to the slide judgments.

**Units that change while an answer waits.** Somebody may edit a row, a
paragraph or a file after its answer was judged and before Keep. Keep then
lands only the answers whose units are untouched, carried onto the current
head, and withdraws the rest. A row is changed when a cell it read, its
header row or its answer cell changed; a paragraph when its text changed or it
is gone; a folder file when it has a newer version. Keep's receipt names the
revision each kept answer was judged against (`judged_version` and its
evidence hash), and lists each withdrawn answer under `withdrawn_units`, with
that revision and the version it changed in. If no answer stands, nothing is
appended and the receipt's reason is `units_withdrawn`.

After a quiet interval the proposer is woken with the changed units. The
interval is the `artifact_answer_quiet_seconds` policy row, 60 seconds as
shipped, measured from the last change to what they read. The same question
is asked again of those units on the head, as the ask's principal, and the
answers wait as a fresh proposal for Keep (its ref is `reask:<…>`). A unit
that changes while its proposal still waits is withdrawn and asked again the
same way. A wake never keeps anything, and a discarded proposal's units are
not asked again. Only the vault's home node runs the wakes, in the
standing-question pump. A wake that fails is held for five minutes. Slide
reviews are not split: a moved head strands the whole review, as before.
Answers never go to the owner's queue: the slide door holds its ceiling at
Big. On a server the engine's
`Memory::artifacts_ask_through` answers these asks. Until its door is in the
SDK table, `vault.artifacts.review_slides` is the only door that serves one.

A `vault.artifacts.review_slides` unit may name no image (neither
`review_image` nor `review_image_ref`). On a host with the LibreOffice slide
renderer, the door then renders that slide from the head itself, on local CPU
and unmetered, and saves the host renderer's name on the judgment. Without the
renderer, or when the render fails, the unit is read for its structure only
and abstains. It is never refused. A unit that names both images is refused.

## 14. Tagger tiers and the teacher's handoff

A host may keep several local tagger bundles as named tiers and serve one.
The label is yours (`tiny`, `medium`, ...); which candidate wins is measured
outside the engine and bound by the vault's model manifest.

```toml
[oneironer]
provider = "local"
tier = "tiny"                   # or --oneironer-tier / ONEIRON_ONEIRONER_TIER

[oneironer.tiers.tiny]
model_dir = "/models/oneironer-tiny"
checkpoint_sha16 = "0123456789abcdef"
label_count = 9

[oneironer.tiers.medium]
model_dir = "/models/oneironer-medium"
checkpoint_sha16 = "fedcba9876543210"
label_count = 9
max_input_tokens = 512          # its own window, when it differs
```

The named tier's row sets `model_dir` and the identity keys. `oneiron init
--oneironer local --oneironer-model-dir <dir> --oneironer-tier tiny` writes
the first row. A vault whose manifest binds `extraction_encoder` at another
tier's checkpoint stops tagging and names that tier in the log.

`device = "cuda"` opens only in a server built with candle's CUDA kernels,
and a named device never falls back to the CPU: a build without them refuses
at startup (`oneironer engine candle/cuda does not run on this machine`).
`oneiron-server` has no `cuda` feature, since `--all-features` would then
build CUDA everywhere. On a host with the CUDA toolkit (`nvcc` on `PATH`),
build with candle's own features:

```sh
cargo build --release -p oneiron-server --features candle-core/cuda,candle-nn/cuda
```

`deploy/install-oneiron-server.sh` adds the same features when
`ONEIRON_CUDA=1` is set. Its default build, and every CI build, has none.

The extraction teacher is offline by default. It runs the Dreamer's
extraction passes and teaches the tagger, and the manifest refuses a served
call through it (chat, checks, routing, voice). To route a seat to it, set
`"disposition": "served"` on its manifest row. That changes the teacher's
binding, so the row needs a passing probe approval again.

The distillation handoff runs with the server stopped:

```sh
# One job per student: the candidate manifest's extraction_encoder row.
oneiron oneironer distill --candidate candidate.json --fork fork.json \
  --recipe-blake3 <hex> --corpus-blake3 <hex> --out job.json
# The model project trains the student, then binds it to the job.
oneiron oneironer export --request job.json --checkpoint student.pack --out export.json
# Pin the student and its provenance with the candidate manifest.
oneiron oneironer publish --manifest candidate.json --export export.json --checkpoint student.pack
```

`publish` prints the configured tier that serves the student, if any.

`publish` opens the vault itself, so it runs only with the server stopped,
never on a managed vault. On a running server the owner binds the tagger it
has loaded through `vault.models.oneironer.bind`:

```http
POST /v1/core/facade/vault.models.oneironer.bind
Content-Type: application/json

{"expected_checkpoint_sha16": "0123456789abcdef"}
```

- The binding is the tagger the server has loaded, never one the caller
  names: its model, `oneironer/local@<checkpoint_sha16>`, in the `oneironer`
  slot, at the section's named `tier`, else at the loaded bundle's
  `stack_sha16`, never the tier the row already holds. That is the binding
  the tagger checks the vault against, so the loaded tagger is the one
  selected.
- Both input fields are optional and only compare. `expected_checkpoint_sha16`
  and `expected_stack_sha16` must match the loaded checkpoint and stack, or
  the call is refused. `{}` binds whatever is loaded.
- One write sets `roles.extraction_encoder` and
  `routes.oneironer = "on_device"` in the current manifest and keeps every
  other role, route, the verdict and the seat policy. It is the guarded write
  `vault.models.manifest.replace` runs: the owner's proof is checked again
  inside it, the saved teacher approval must still pass under the live probe
  policy, the manifest checks must pass, an encoder export the new binding
  no longer matches is dropped, and every resident route override is
  cleared. It publishes no encoder export. The answer is the manifest it
  published.
- A vault with no manifest is refused (`manifest not configured`): one row
  cannot make a complete v2 manifest or its teacher approval. The door also
  refuses when no Oneironer slot is loaded, when the slot is disabled, is not
  `provider = "local"` or has no loaded model card, when a guard does not
  match, and when the caller is not the vault's owner.

A vault with no manifest tags with the host's `[oneironer]` section as its
selection, and `vault.models.roles.read` and `vault.models.roles.invoke`
both report `extraction_encoder` from that section for it, with one receipt
that names the loaded tagger: role `extraction_encoder`, slot `oneironer`,
revision the configured `checkpoint_sha16`, route `on_device`, the section's
provider, and its tier. Every other role, and every role of a vault with a
manifest, is read and served from the manifest as before.

Bind and that receipt name the tier in one order: the section's named
`tier`; else the `stack_sha16` of the model card the probe accepted, the
loaded bundle; else the configured `stack_sha16`; else the configured
`checkpoint_sha16`. The last two only name a slot whose probe has not
accepted a card yet, such as an endpoint that has not answered: they are
configured identity, not a bundle a card attested. Neither ever takes the
manifest row's old tier or `extraction_encoder`.

The startup probe logs the bundle that serves, so the log alone says which
one answers:

```text
tagger probe succeeded provider=local label_count=53 links=false checkpoint_sha16=0123456789abcdef stack_sha16=<16 hex> decode_revision=oneironer-decode-v1 stack_pinned=true
```

`checkpoint_sha16` and `stack_sha16` come from the accepted card;
`decode_revision` is the native decoder this build runs, `-` for an
endpoint, whose card names none. `stack_pinned` says whether the section
pins `stack_sha16` too.

### Fetch a shipped release (`oneiron oneironer fetch`)

The engine carries a catalogue of shipped tagger bundles. Each one is pinned
file by file, by size and SHA-256, under its `stack_sha16`. One release ships
today: stack `fde950a412728a86`, checkpoint `eeeaf8bea4e8d166`, 53 labels,
licence Apache-2.0. It has five files, about 1.2 GB in all: `oneironer.json`,
`config.json`, `char_config.json`, `tokenizer.json` and `trunk.safetensors`.

```sh
oneiron oneironer fetch [--stack <stack_sha16>] [--into <models-root>] \
  [--repo <org/name>] [--token-file <path>]
```

- `--stack` picks a release. Without it, the fetch takes the default. An
  unknown stack is refused, and the refusal lists the known ones.
- `--into` is the models root. The bundle lands at
  `<root>/oneironer/<stack_sha16>/`, the layout the shared model root uses.
  Without `--into`, the root is the embedder's:
  `$XDG_DATA_HOME/oneiron/models`, else `$HOME/.local/share/oneiron/models`.
  With it, the fetch reads no environment variable.
- `--repo` is the Hugging Face model repo, `oneiron-dev/oneironer` by
  default. Each release sits at a git ref named by its `stack_sha16`, and each
  file is read from `https://huggingface.co/<repo>/resolve/<stack_sha16>/<file>`.
- `--token-file` names a file holding a Hugging Face read token. The repo
  stays private until the model is final, and then goes public under
  Apache-2.0. Until then, a fetch needs the token. The fetch sends the token
  to `huggingface.co` only, never on a redirect to its CDN, and never prints
  or logs it. Pass a file, such as a systemd credential at
  `$CREDENTIALS_DIRECTORY/<name>`. There is no way to pass the token itself.

The fetch stages files in `<root>/oneironer/.staging-<stack_sha16>/`, under
the lock file `<root>/oneironer/.staging-<stack_sha16>.lock`. A second fetch
of the same stack waits for the first, then reuses its bundle. Each file
downloads to `<file>.partial`. After an interrupted run, the next run resumes
the partial with an HTTP `Range` request. Every file is checked for size, then
for SHA-256. When a file's size or digest is wrong, the fetch deletes its
partial and fails. Once all five files pass, the staging directory is renamed
into place in one step, with directories at `0755` and files at `0644`.

A bundle already in place is checked the same way and reused. If it fails the
check, the fetch fails and leaves the directory as it is. Look at it, then
remove it yourself.

The command prints one JSON object:

```json
{"outcome": "downloaded", "stack_sha16": "fde950a412728a86",
 "repo": "oneiron-dev/oneironer", "licence": "Apache-2.0",
 "model_dir": "/srv/oneiron/models/oneironer/fde950a412728a86",
 "bytes": 1243862518, "resumed_bytes": 0, "file": null, "message": null,
 "oneironer_block": "[oneironer]\nprovider = \"local\"\n..."}
```

- `outcome` is one of four values. `reused` and `downloaded` mean the bundle
  is in place. `not_published` means a file answered 404: the release is not
  uploaded yet. `unauthorized` means a file answered 401 or 403: the release
  is private and the fetch had no token, or its token has no access.
- `bytes` and `resumed_bytes` are set on a download only. `bytes` came over
  the network on this run. `resumed_bytes` were already on disk from an
  earlier run.
- `file` and `message` are set on `not_published` and `unauthorized` only.
  For these two outcomes the command prints the object, then exits non-zero.
- `oneironer_block` is the `[oneironer]` section that serves the bundle, ready
  to paste into a settings file. It is null until the bundle is in place.

```toml
[oneironer]
provider = "local"
model_dir = "/srv/oneiron/models/oneironer/fde950a412728a86"
checkpoint_sha16 = "eeeaf8bea4e8d166"
stack_sha16 = "fde950a412728a86"
label_count = 53
```

A managed engine never downloads a bundle, and a managed vault has no fetch
setting or flag. Hypnos places the bundle: it runs this command as root once
per node, with `--into <shared_model_root>`. Each vault's `[oneironer]
model_dir` then names `<shared_model_root>/oneironer/<stack_sha16>/`, which
the shared-root check in section 2 admits.

### Where the engine rows live

With `device = "auto"`, the engine measures each engine on this machine
against the bundle's `parity.json`. It keeps the results as rows in
`engines.json`, so a later start skips the measurement. A self-hosted server
and `oneiron init` keep the rows at
`$XDG_DATA_HOME/oneiron/oneironer/engines.json`, else at
`$HOME/.local/share/oneiron/oneironer/engines.json`. A managed vault keeps
them at `<data_dir>/oneironer/engines.json` and reads no HOME or XDG. Rows
never go into the shared model root or into a bundle directory. If the rows
file cannot be written, the server logs a warning, and the next start
measures again.
