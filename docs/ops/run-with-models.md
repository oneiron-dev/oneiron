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
rest of the manifest list. The retrieval embedder stays in `[embedder]`, where
`provider = "endpoint"` takes any OpenAI-compatible `/v1/embeddings` server.

Provider fields: `kind` (`openai-compat`, `anthropic-compat`,
`local-openai-compat`, `oneironer`, and the speech-only `cartesia`,
`elevenlabs` and `voxcpm2`), `base_url`, `key_env` or `key_secret`, `headers`
(non-credential only), `timeout_secs` (120), `context_tokens` (128000),
`max_output_tokens`, `output_limit_field`, `response_format` (`schema`, the
default, or `none`; OpenAI-compatible providers only), `capabilities` (`streaming`,
`json_response`, `tool_calling`, `tool_results`, `image_input`, `audio_input`,
`reasoning`; `audio_input` sends a chat message's audio clips as `input_audio`,
WAV or MP3, on OpenAI-compatible providers only, and no provider has it unless
the list says so; a `local-openai-compat` provider declares `streaming`, `json_response` and
`reasoning` unless the list is written out),
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
`SCOPE_FULL=true scripts/ci/run_scoped.sh test` runs it after the workspace
tests, so a host that runs that command needs the range and `newuidmap`.

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
run per night. Approve a curator run and its next pass applies each demotion
whose target is unchanged since grading; a retune proposal is advice only and
changes nothing.

The vault cleanup pass proposes archives and archives nothing until you
accept (`/v1/owner/cleanup`); automatic archiving stays off until ARCH-0066's
teeth #5 and #9 close. The next regular proactivity digest
(`/v1/owner/proactivity/digest`) carries one `dreamer.cleanup` line: what
cleanup archived since the last digest, and how many records wait in open
proposals, with the cleanup view to restore any of them. Each proposal and
your accept or reject count in the healer oversight receipts
(`/v1/owner/healer/oversight`).

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
broker sends chat calls only for now) refuses the same way. The request
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
`local-openai-compat`, keyed by `key_env`; the credential broker sends chat
calls only), or an image or video rung on a `gemini` provider (below). A
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

A `gemini` provider is Google's Gemini API, its origin as `base_url` and its
key in `key_env` (sent as `x-goog-api-key`). It serves the image and video
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

- `GET /v1/ai/options?operation=image&inputs=text,image`: every row that
  serves the call (text seats' rungs too), where it runs, what it takes, its
  rates, and `media_units_left`.
- `POST /v1/ai/image`, `/speech`, `/transcribe`, `/embed`:
  `{"prompt": "...", "input": [parts], "references": [parts], "params": {...},
  "model": "<row or seat id>"}`. A part is `{"kind": "text", "text": ...}` or
  `{"kind": "image" | "audio", "media_type": ..., "data": "<base64>"}`. The
  answer is `{"model", "parts", "usage"}`.
- `POST /v1/ai/video` answers `202` with a job ticket; `GET
  /v1/ai/video/{job}` polls it (a finished job answers with its clip, once)
  and `DELETE` stops it. A job's permit is held while it renders and settled
  when it ends.

Seats show in `GET /v1/ai/status` as `media.<operation>`.

### Voice on the media seats

A speech call can name its voice: `"voice": {"kind": "stock", "name":
"alloy"}` for a provider's own voice, or `"voice": {"kind": "bank",
"voice_id": "...", "include_generated": false}` for a banked identity. A
banked voice lives in the vault's reference bank. A provider sees only the id
of the clone recorded for its target, and the target is the rung's provider
name in `[models.providers]`. The call renders on the first rung of its
ladder whose target holds a current clone, and on that rung alone. With no
such rung the call answers `409 voice_not_provisioned`. If the voice is
withdrawn or its clone re-recorded while the call renders, it answers `409
voice_withdrawn` and the audio is not returned. A call that names a voice
names no `voice` param, and only a speech call names one.

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

A call opens with one JSON line:
`{"op":"hello","token":"v2.slip...","binding":{"timestamp":..,"nonce":"..","signature":".."},"sample_rate":16000,"channels":1}`.
- The token and binding proof are the owner's capability slip and a fresh
  transport proof, the same ones the HTTP API takes in `Authorization` and
  `x-oneiron-binding`.
- They pass the same doors at the on-device locality, then the owner door.
- A bad or missing token closes the socket before any audio. An admitted call
  is answered `{"op":"accepted"}`.

After that the stream carries:
- **the transcript ops** (`open`, `partial`, `final`, `close`);
- **media in:** `pcm` (STANDARD base64 of whole PCM16LE samples, at most about
  12 KiB raw a frame), `cut`, `speaking`, `roster_changed`, and
  `drained{generation}` once a `generation_end`'s audio has all played;
- **media out:** `pcm{generation, sample_rate, data}` (mono PCM16LE),
  `generation_end`, `flush`, `playout_stop`, `safeguard`, `notice` and
  `session_ended`.

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

`POST /v1/ai/ask_image` (`{"handle", "question", "region"}`) asks a small
vision model about the pixels instead, so they never enter the asker's
context. Bind that model as its own role:

```toml
[models.roles.local_vision]
rungs = ["local:qwen3-vl-4b"]
```

Its provider needs `image_input` among its capabilities. The answer is
`{"asset_ref", "text", "receipt"}`.

Add `"contract": {"kind": "box"}` to ask where something is instead
("where is the mug in `image`?"). The same seat then answers as the decision
ladder's Local rung (`LocalVisionModel`, a `DecisionModel` that reads
images): it reads the whole image (a Box ask takes no `region`) and answers
with a JSON schema shaped like System One's box answer. The answer is
`{"asset_ref", "typed", "receipt"}`, where `typed` is the typed decision:
`{"kind": "box", "value": {top, bottom, left, right}}` in 0–1 fractions of
the image, or `"value": null` when the target is absent, with its
confidence as `probability` and the decision's receipt (the Local rung's
pin and the image's evidence version). The ask runs at the Local rung alone,
on a 60-second clock, and queues no person. Only a Box contract is answered
here. Each rung served and each pull (view,
crop, zoom, ask_image) is a `served_form` receipt, so `vault.receipts` shows
which rung each image got and whether the pixels were pulled afterwards.

The same seat answers `ai.verdict` over an image: name its view handle as
`"image"` (the question calls it `image`). The pixels are pulled through the
caller's own scoped read, the image rides the receipt as an evidence ref
with its body version, and the call starts at the Local rung on a run of its
own. There the seat answers a Choice (`{"choice", "confidence"}`), a yes/no
(`{"p_yes"}`) or, with `"locate": true`, a Box. A Score abstains. A rung
above Local that reads no image is skipped.

A code-mode program drives a routine browser or computer step through the
same verb (the CUA-S1 pattern): `"routine": true` makes `options` the step's
candidates (1 to 61), and the ladder also offers `NONE`, `reobserve` and
`too complicated, ask up`. The answer gains an `outcome`: one of
`{"outcome": "act", "candidate"}`, `{"outcome": "point", "x", "y", "found"}`
(a routine Box's centre, as fractions of the image), `{"outcome": "none"}`,
`{"outcome": "reobserve"}` or `{"outcome": "ask_up", "reason"}`. A routine
step's Box that finds no target reads as `none`. A ladder abstain reads as
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
`[browser]`). The section is refused on macOS: the guest never runs on, or
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
  recipe names the paired question. The recipe's person question becomes the
  ladder's "ask up?" question, and `person_threshold` becomes its row.
- **Big**: the big model, through the seat `[models.decisions.big]` names
  (below).
- **The local head**: no typed provider fills it yet, so the ladder steps
  past it.
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

[models.decisions.seat]
# A manifest-backed execute_code run picks its seat through the ladder:
# a model among those described under `facet`, then one of its efforts.
facet = "code-task"
model = "Which model should run this task?"
effort = "At which effort should it run?"
budget_ms = 2000        # each pick's anytime budget

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
```

The Big rung asks each question as one model call on that seat. The call is
routed against the vault's live model policy, like a chat turn, and sent under
its own run on the rung's meter. `wording` is the system message. The question,
what it takes and the state follow as the user message, with the reply format:
one JSON object `{"answer", "probability"}`, or two lines `answer:` and
`probability:`. A reply that names nothing the question takes, or no
probability from 0 to 1, abstains, and the ladder moves on. The rung takes
noul, choice and score questions, not boxes.

The System One seat takes noul and choice questions. Each is one call,
admitted and settled on its meter. It never runs on a relay vault. The
escalation read is metered on `models.raw_budget_units`. A model rung blocks
on the server's runtime, so a caller runs a ladder call on a blocking thread.

### Standing questions over graph units

A standing question (a typed question saved over a set of graph units, with
`refresh.every_seconds` or `refresh.on_arrival`) is answered on this ladder
without a caller. Only the vault's home node runs the pump: the node the
vault's home designation names. A server whose vault has no home yet claims
it, so the pump runs with the Dreamer off. The pump sleeps until the next
question is due, and a committed write wakes it early (a question's create,
edit or resume, or a claim write). It also re-reads its due work at least
once a minute, because an arrival on a unit that is not a claim does not wake
it. It answers each unit as the question's own principal, reading under that
principal's grants, and climbs the question's own dial. A ceiling of `human`
is held at Big, so the pump never queues an owner ask. Each unit has its own
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

**Stale answers.** A folder column refuses Keep when a file it read has
changed since; ask again. Answers never go to the owner's queue: the slide
door holds its ceiling at Big. On a server the engine's
`Memory::artifacts_ask_through` answers these asks. Until its door is in the
SDK table, `vault.artifacts.review_slides` is the only door that serves one.

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
