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
downloads six files (1.19 GB) to
`$XDG_DATA_HOME/oneiron/models/<org>/<name>/<revision>/`, verifies each against
a pinned sha256, and quantises the projections to Q8_0 at load. Nothing is
downloaded at boot: the vault serves at rung 0 until the artifacts are verified,
then starts filling. Point `model_dir` at a directory already holding those six
files and no download is attempted at all — the offline-host door.

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
