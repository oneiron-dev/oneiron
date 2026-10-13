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

`GET /api/health` reports `"ai": {"dreamer": "idle", "dreamer_reason": "no_model_configured"}`.
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
local = "llama:qwen3:8b"
cloud = "router:anthropic/claude-sonnet-4.5"
prefer_local = true                     # false puts the cloud rung first

[models.providers.llama]                # llama.cpp `llama-server`, vLLM, MLX `mlx_lm.server`
kind = "local-openai-compat"
base_url = "http://127.0.0.1:8080"

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
  { model = "llama:qwen3:8b", prompt_file = "prompts/dreamer-local.md" },
  { model = "claude:claude-sonnet-4-5" },
]

[models.providers.claude]               # any Anthropic-compatible /v1/messages server
kind = "anthropic-compat"
base_url = "https://api.anthropic.com"
key_env = "ANTHROPIC_API_KEY"
```

Role keys are the model manifest's (ARCH-0036): `generative_reasoner` (chat and
saved workflows), `local_reasoner`, `checker`, `dreamer_current`,
`dreamer_target`, `extraction_encoder` (a tagger, `kind = "oneironer"`), and the
rest of the manifest list. The retrieval embedder stays in `[embedder]`, where
`provider = "endpoint"` takes any OpenAI-compatible `/v1/embeddings` server.

Provider fields: `kind` (`openai-compat`, `anthropic-compat`,
`local-openai-compat`, `oneironer`), `base_url`, `key_env` or `key_secret`, `headers`
(non-credential only), `timeout_secs` (120), `context_tokens` (128000),
`max_output_tokens`, `output_limit_field`, `capabilities` (`streaming`,
`json_response`, `tool_calling`, `tool_results`, `image_input`, `reasoning`),
`locality` (`own_server` or `third_party`) and `revision` (`live`). Plain
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
A `key_secret` provider answers whole replies only for now: a streamed call to it
is refused before it starts.

The broker holds `<socket>.lock` while it serves, so a second broker on the same
path refuses to start. `scripts/ci/broker-fixture.sh` runs the paid-leg fixture with
the broker as a second OS user. It needs an `/etc/subuid` and `/etc/subgid` range
for the user that runs it, and `newuidmap`. A Linux host that is meant to prove the
broker runs it; there, a missing prerequisite fails the run instead of skipping it.
The full gate (`SCOPE_FULL=true scripts/ci/run_scoped.sh test`) runs it after the
workspace tests, so the host that runs the full gate needs the range and
`newuidmap`.

`max_output_tokens` is a ceiling on every call to that provider: it is sent
when a call names no limit, and a larger limit is cut down to it. An
OpenAI-compatible endpoint reads it from `max_tokens` unless
`output_limit_field = "max_completion_tokens"` says otherwise (some hosted
reasoning models accept only that one). An Anthropic-compatible call always
carries `max_tokens`, 4096 when nothing else names it.

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
| vault defaults that route extraction and consolidation to where the Dreamer extracts (the seat's widest rung, or the route of the extraction teacher the vault's model manifest pins): `oneiron dreamer grant --extraction-route own_server` (or `third_party`), or `PUT /v1/llm/defaults` | `extraction_route_not_set` |
| with a model manifest, its extraction teacher served by `[models]` at the vault's route | `extraction_model_not_served` |
| the Dreamer's three policy rows (a fresh vault ships them) | `needs_owner_grant` |

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
signal lets it spend again. `SIGTERM` or Ctrl-C stops cleanly: a pass in
flight reaches its attempt boundary first.

## 4. Chat

`POST /v1/ai/chat` with `{"conversation_ref": "<32-hex>", "text": "…"}` (plus
optional `history`) streams NDJSON: `accepted`, one `delta` per text chunk,
`done`, then `saved` with the message receipt. The same deltas reach every
owner socket on `/ws` as transient presence. Only the final message is written
to the vault, once. The credential needs read and write scope, and must be
able to read the answering agent's definition. It is checked for the whole
turn: once it is revoked or expires, the body sends one
`{"type":"error","code":"credential_revoked"}` line and ends, the model call
stops, and the message is cancelled rather than saved as an answer. The seeded
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
component, calling the vault through `self.memory.<verb>` under the
connector's own grants. It is listed on `tools/list` only when the seat has a
rung and a prompt package for the executor is named:

```toml
[models.code_mode]
prompt_package = "prompts"   # holds blocks/engine-executor-wire.md; relative to this file
budget_units = 10000000      # optional; process-lifetime meter for its model calls
```

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
`executor/repl/<step>.code-check.json`: backend and pin, latency, the first 32
diagnostics in program coordinates (`diagnostics_omitted` counts the rest), or
a failure code. Each check also logs one `oneiron::code_check` line with the
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

## 7. Raw calls

With `[models]` set, `/v1/llm/generate` and `/v1/llm/stream` call any
configured model by its engine id (`<provider>/<model>@<revision>`, shown in
`GET /v1/ai/status`), or a seat by its seat id. Their process-lifetime meter is
`models.raw_budget_units`.
