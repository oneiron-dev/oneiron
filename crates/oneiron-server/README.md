# oneiron-server

Local sync daemon for a single Oneiron vault.

```sh
cargo install oneiron-server
oneiron-server init ~/.local/share/oneiron/default
oneiron-server serve --vault-path ~/.local/share/oneiron/default
oneiron-server skills-pack > oneiron.skills.md
oneiron-server skills-pack --json
oneiron-server skills-pack --path
```

`skills-pack` exports the committed agentskills-compatible pack without
opening a vault or starting the daemon. It prints raw Markdown by default;
`--json` emits a machine-readable envelope.

See the workspace [`README.md`](../../README.md) and
[`DEPLOYMENT.md`](../../DEPLOYMENT.md) for local daemon configuration,
service templates, and dictionary layout.

## Semantic retrieval: the `[embedder]` section

The vault stores vectors; it does not own a model. A server with no `[embedder]`
section keeps the posture it has always had — writes land, lexical and graph
reads answer, and vectors arrive from whoever calls
`GET /api/search/vector`. Naming the section selects a provider and starts a
worker that fills the pending-embedding queue, and opens
`POST /api/search/semantic`, which embeds query text server-side.

One vault holds one embedding space, so `model_id` is pinned into the vault at
open and every provider reports exactly it. `embedder.dimensions` must equal the
vault's `dimensions`.

```toml
dimensions = 1024

[embedder]
provider = "local"                  # local | endpoint | none
model_id = "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee"
dimensions = 1024
# quant = "q8_0"                    # q8_0 | none (none = bf16, GPU only)
# device = "auto"                   # auto | cpu | metal
# models_dir = "/Volumes/Cinema/models/oneiron"
batch_size = 32
lease_ms = 30000                    # 120000 is a better fit on a CPU-only host
```

`provider = "local"` runs the model in-process on candle. On first use it
downloads six files (1.19 GB) to
`$XDG_DATA_HOME/oneiron/models/<org>/<name>/<revision>/`, verifies each against
a pinned sha256, and quantises the projections to Q8_0 at load. Nothing is
downloaded at boot: the vault serves at rung 0 until the artifacts are verified,
then starts filling. Point `model_dir` at a directory already holding those six
files and no download is attempted at all — the offline-host door.

`provider = "endpoint"` speaks to any OpenAI-compatible `/v1/embeddings` server:

```toml
[embedder]
provider = "endpoint"
model_id = "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee"
dimensions = 1024
endpoint = "http://127.0.0.1:1234/v1"
model_key = "text-embedding-harrier-oss-v1-0.6b"
locality = "on-device"              # on-device | owner-server
```

Every key mirrors a `--embedder-*` flag and an `ONEIRON_EMBEDDER_*` environment
variable, in the usual precedence: defaults, then the file, then the
environment, then argv.

At startup a configured endpoint is probed once. A reachable endpoint that does
not serve `model_key`, or that returns a different number of components, stops
`serve`: filling one vault from two embedding spaces is not recoverable. An
UNREACHABLE endpoint is not fatal — it is logged once and the worker keeps
retrying.

Host recipes:

```sh
# macOS, LM Studio
lms load text-embedding-harrier-oss-v1-0.6b --context-length 4096 -y
# Linux, llama-server
llama-server -m harrier-oss-v1-0.6b.f16.gguf --embeddings --pooling last -c 4096 --port 8089
```

## Optional Linear TASK mirror

The **bare** `oneiron-server serve` host can run a vault's Linear mirror. It
is off by default. Supply these five required variables in the host's
secret-bearing environment, not in a repository, checkout, or vault row:

- `ONEIRON_LINEAR_SYNC_ENABLED=true`
- `ONEIRON_LINEAR_API_KEY` — a Linear API key for the intended workspace
- `ONEIRON_LINEAR_TEAM_ID` — the team's opaque Linear ID
- `ONEIRON_LINEAR_SCHEDULER_ACTOR` — a registered vault Machine/System actor with an
  active owner-consented outbound grant for the team and both Linear issue verbs;
  the owner policy must separately give this Machine/System actor an Auto ceiling
- `ONEIRON_LINEAR_STATUS_NAMES` — a JSON map from TASK status tokens to exact
  Linear workflow state names for that team, e.g.
  `{"queued":"Backlog", "working":"In Progress", "interrupted":"Blocked", "completed":"Done"}`.
  Names must be unique. Unmapped inbound or outbound states fail closed.

Optional `ONEIRON_LINEAR_ASSIGNEE_IDS` is a JSON map of local actor/agent
entity IDs (32 lowercase hex) to Linear user UUIDs. Mapping must be one-to-one.
Unmapped outbound assignees remain dirty with a typed refusal, not a
provider call. A linked inbound issue with an unmapped provider assignee stays
unapplied at its saved cursor; unrelated issues and outbound TASKs still run.
The scheduler AND the attributed TASK writer each need a live grant for the exact
`linear_issue_create` and `linear_issue_update` verbs. An owner can narrow each
grant with a `BriefVerbClass` scope bound to the team ID. A raw or replicated
TASK write has no verified writer stamp and is never sent. No Linear worker
starts when unauthenticated core writes are enabled or no auth secret exists.

A partial configuration refuses server startup. The trusted vault policy
manifest supplies the `linear_host_policy` row with these shipped defaults:
`precedence=nested_narrowing`, `interval_secs=60`, `missed_tick=skip`,
`page_size=50`, `timeout_secs=15`, `max_response_bytes=4194304`,
`permission=conditional`, and `risk=normal`. A full TOML row in host variable
`ONEIRON_LINEAR_POLICY_MANIFEST` may narrow but never widen the current vault
row (a longer interval, smaller limits, denied permission, or held risk). The
preference mode is itself pinned to `nested_narrowing`. The server resolves this
trusted row before it starts the worker; the engine rechecks permission and
risk at each external-effect Gate decision. The adapter uses only
`https://api.linear.app/graphql`, no redirects or ambient proxy, and bounds
requests/responses by the resolved policy. The key stays in the host process; no
credential is persisted in the engine. A pass pulls one change page first.
Only after the page stream catches up does it push dirty TASK rows. Failed
passes retain their cursor and dirty revisions for the next tick. Conflicts
leave the affected dirty TASK queued for resolution, not silently overwritten.
The supervised managed child does not read these variables or start this worker.
