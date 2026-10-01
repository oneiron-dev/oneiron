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
model_id = "perplexity-ai/pplx-embed-v1-0.6b@2c4d510dd4a732063c31a0f70193e35067b51fd8"
dimensions = 1024
# quant = "q8_0"                    # q8_0 | none (none = bf16, GPU only)
# device = "auto"                   # auto | cpu | metal | cuda
# models_dir = "/Volumes/Cinema/models/oneiron"
batch_size = 32
lease_ms = 30000                    # 120000 is a better fit on a CPU-only host

# Optional vault-local auto-device policy. The shipped manifest at
# policy/embedder.toml says ["metal", "cuda", "cpu"]. File, environment
# (ONEIRON_EMBEDDER_AUTO_DEVICES=cuda,cpu), and CLI
# (--embedder-auto-devices cuda,cpu) use the normal precedence, but each
# higher layer can only narrow/reorder the preceding candidate set by default.
# [embedder.policy]
# auto_devices = ["cuda", "cpu"]
# precedence = "nested-narrowing"    # shipped default
# Alternative: "vault-capped-holder-override" lets the CLI holder override
# an environment choice, but never add a candidate excluded by this vault file.
```

`provider = "local"` runs the model in-process on candle. On first use it
downloads the model's files (five, 2.38 GB, for the default
`perplexity-ai/pplx-embed-v1-0.6b`) to
`$XDG_DATA_HOME/oneiron/models/<org>/<name>/<revision>/`, verifies each against
a pinned sha256, and quantises the projections to Q8_0 at load. Nothing is
downloaded at boot: the vault serves at rung 0 until the artifacts are verified,
then starts filling. Point `model_dir` at a directory already holding those
files and no download is attempted at all — the offline-host door.

`model_id` names the weights. A section that names a `model_id` and no
`repo`/`revision` loads that space's own repository and commit, so a vault
created under the earlier default, `microsoft/harrier-oss-v1-0.6b@f9b9dc8…`,
keeps loading Harrier's pinned files after the default moved. A section that
names `repo`/`revision` and no `model_id` fills the space those files spell.
Naming both is allowed only when they agree: a `model_id` beside another
model's files is refused at startup. A vault pinned to one model refuses to
open under another (`EmbeddingModelChanged`); see *Changing a vault's
embedding model* below.

The provider names no model in code. It reads everything about a checkpoint
from the checkpoint's own files, so any model with a Qwen3 body runs from its
`repo` and `revision` alone:

- attention: `use_bidirectional_attention` or `is_causal` in `config.json`,
  causal when neither is set;
- the module chain from `modules.json`: a Transformer at the repository root,
  one Pooling (`lasttoken`, `mean_tokens` or `cls_token`, honouring
  `include_prompt`, which defaults to true), then any of `Dense` (Identity or
  Tanh), `Normalize` and `FlexibleQuantizer` (int8 or binary tanh) in their
  declared order. Modules are matched by their exact import path
  (`sentence_transformers.models.*`, `st_quantize.FlexibleQuantizer`); any
  other module, pooling mode or order is refused by name, and so is a module
  path that leaves the model directory;
- prompts from `config_sentence_transformers.json`: a query takes
  `query_instruction`, else the `query_prompt_name` prompt, else the prompt
  named `query`, else `default_prompt_name`, else none; a document takes the
  first of `document`, `passage` or `corpus`, else `default_prompt_name`. No
  file means no prompt.

Every repository fetches exactly the files its `modules.json` names; the
shipped defaults' files are also pinned by sha256, and any other repository
runs unpinned. Keys for a checkpoint whose files say less than they should:

```toml
[embedder]
# attention = "auto"                # auto | causal | bidirectional
# output_quantization = "int8"      # int8 | binary, for a FlexibleQuantizer
# query_prompt_name = "web_search_query"   # a named prompt from the model's file
# query_instruction = "…"           # literal query prefix; wins over the file
```

Beside the `model_id`, a vault pins its embedding transform: a descriptor of
everything that moves a stored vector under the same model. For a local model
it is read from the model's files and these keys, e.g. the default's
`attn=bidirectional;pool=mean;include_prompt=true;doc_prompt=none;chain=quantize:int8;dims=1024`;
an endpoint's is `endpoint;dims=<n>`; `none` pins nothing. Query settings,
weight precision, device and batch size are not part of it. Changing
`attention` or `output_quantization` on a filled vault therefore stops the
next open (`EmbeddingTransformChanged`) until `oneiron-server reembed` (below)
re-embeds the vault the new way. A vault from before the pin adopts the
transform it is first opened with; a local model whose files arrive after
open is checked once they load.

Harrier's `config_sentence_transformers.json` names its prompts by task
(`web_search_query`, `sts_query`, `bitext_query`) and sets no default, so
Harrier carries no query prompt unless its config names one. A vault kept on
Harrier needs this section:

```toml
dimensions = 1024

[embedder]
provider = "local"
model_id = "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee"
dimensions = 1024
# The instruction Harrier vaults were queried with before the default moved:
query_instruction = "Instruct: Given a question, retrieve passages that answer it\nQuery: "
# Or the model card's own web-search prompt, from the model's file:
# query_prompt_name = "web_search_query"
```

Documents need no line: Harrier has no document prompt, so they embed as
before. An `endpoint` provider reads no model files: its queries carry
`query_instruction` or nothing.

On a CUDA toolkit host, build the same server with candle's dependency features
explicitly enabled (not a `oneiron-server` feature):

```sh
cargo build -p oneiron-server --release --features candle-core/cuda,candle-nn/cuda
```

The default build and `--all-features` remain toolchain-free on Linux. CUDA
requires the CUDA toolkit and a compatible NVIDIA driver at build/run time.
`device = "cuda"` fails before any model download if CUDA is unavailable;
`auto` tries only the vault policy's ordered candidates (Metal, CUDA, then CPU
by default). If policy excludes CPU and no allowed GPU is reachable, `auto`
fails closed instead of silently falling back to CPU. Q8_0 weights are
quantised on the CPU at load and uploaded to CUDA.
For a Linux Radeon host, candle has no Vulkan backend: use `cpu`, or set
`provider = "endpoint"` to a separately hosted OpenAI-compatible embeddings
server (for example llama-server with Vulkan), with the correct `model_id`,
`dimensions`, and `locality`. No Vulkan accelerator is claimed for `local`.

`provider = "endpoint"` speaks to any OpenAI-compatible `/v1/embeddings` server:

```toml
[embedder]
provider = "endpoint"
model_id = "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee"
dimensions = 1024
endpoint = "http://127.0.0.1:1234/v1"
model_key = "text-embedding-harrier-oss-v1-0.6b"
query_instruction = "Instruct: Given a question, retrieve passages that answer it\nQuery: "
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

### Changing a vault's embedding model

A server whose `model_id` or embedding transform differs from the one the
vault holds stops at open and leaves the vault untouched. The refusal names
both ways forward: keep the vault in its space (the vault's `model_id` with
that model's query settings, `query_instruction` / `query_prompt_name`, or the
`attention` / `output_quantization` that made it), or move it. With the
server stopped:

```sh
oneiron-server reembed --config <same config serve reads>
# {"from":"microsoft/harrier-oss-v1-0.6b@f9b9dc8…","to":"perplexity-ai/pplx-embed-v1-0.6b@2c4d510…","transform":"attn=bidirectional;…","migrated":true}
```

`reembed` repins the vault to the configured `model_id` and transform in one
transaction, drops the vector graph and every staged vector, and queues every
record that is embedded: claims and epoch summaries. The next `serve` embeds
them all again in the background; lexical and graph reads answer throughout,
and semantic results fill in as vectors land. A vault already in the
configured space is left as it is (`"migrated":false`), unless `--force` asks
for the same swap under the pins it already holds. A vault's dimensions are
fixed when it is created: a model of another width needs a new vault, and
`reembed` says so.

## Linear mirror host bridge (opt-in)

The server starts a mirror pass only when both
`ONEIRON_LINEAR_BRIDGE_URL` and `ONEIRON_LINEAR_BRIDGE_TOKEN` are set. The URL
must be HTTPS (or loopback HTTP for a local bridge). A partial or blank config
stops startup. An enabled mirror also requires authenticated core writes (an
`auth_secret`, and no `--insecure-allow-unauthenticated`), and
`ONEIRON_LINEAR_SCHEDULER_ACTOR`: the entity id of the stored Machine actor the
scheduler acts as. Before the bridge receives any create or update, the vault's
ExternalEffect Gate must admit it for both that scheduler and the verified
writer of the TASK revision (live standing grants and `linear` connector
budgets); a raw or replayed TASK write has no verified writer and is never
sent. Poll wait and request timeout resolve from vault policy manifest rows
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
