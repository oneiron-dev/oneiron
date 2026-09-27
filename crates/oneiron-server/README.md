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

## Linear mirror host bridge (opt-in)

The server starts a mirror pass only when both
`ONEIRON_LINEAR_BRIDGE_URL` and `ONEIRON_LINEAR_BRIDGE_TOKEN` are set. The URL
must be HTTPS (or loopback HTTP for a local bridge). A partial or blank config
stops startup. Poll wait and request timeout resolve from vault policy manifest rows
`linear_mirror_policy` (seeded 30s/15s), and the page allowance from
`linear_sync_budget` (seeded 64); allowed holder selectors may only narrow
the resolved vault bounds. The daemon re-resolves these at each pass. The
token is sent only as an `Authorization: Bearer` header; it
is not stored in the vault. Unmanaged `serve` starts the pass. A failed pass
keeps the TASK outbox revision and inbound cursor for retry.

The bridge is a host-owned authenticated provider/OF-327 outbound-door adapter,
not a direct Linear GraphQL client. A snapshot poll of current issues cannot
supply stable per-change event IDs or the historical field values needed for
safe echo and conflict handling. The bridge must preserve those from its
authenticated Linear event source (for example a webhook inbox), and must
collapse repeated `operation_id` values before making provider writes.

It exposes three JSON operations below the configured URL:

- `GET changes?cursor=<opaque>` returns `LinearChangePage` (`changes` plus
  `next_cursor`), ordered by `updated_at_ms`; each `LinearIssueChange` contains
  stable nonempty `event_id`, `issue`, `updated_at_ms`, and `fields`.
- `POST issues` accepts `operation_id` (64 lowercase hex), `task_ref` (entity
  hex), and `fields`; returns `LinearIssueChange` for the created issue.
- `POST issues/update` accepts `operation_id`, `issue` (`LinearIssueRef`),
  `expected_base_field_hashes` (all five canonical field names to 64-hex
  hashes), and `fields`. It must atomically compare the CURRENT remote fields
  against every expected hash before applying the full snapshot. A mismatch
  returns 409/412 without writing; the daemon retains that TASK's dirty row.
  Replayed `operation_id`s return their original receipt before the compare;
  otherwise a lost response after a successful write would look like a new
  remote conflict on retry. A bridge that cannot provide an atomic compare
  must refuse linked updates rather than publish best-effort last-write-wins. Linear's public GraphQL
  `issueUpdate` alone is not a CAS primitive, so a bridge must not claim this
  guarantee by merely reading the issue immediately before a mutation.

The bridge must return non-2xx on transport or authority failure, not an empty
success page. The pass reads one page at a time and stores its cursor only
following successful application. Host deployments without a bridge do not
start any mirror or make a tracker request.
