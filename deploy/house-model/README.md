# The house model (OF-129)

The house model is Qwen3.8-27B on two GPUs of the owner's own machine. It
serves every generative seat and the local reasoner, with no cloud rung. The
engine names no model: these files are the deployment, and `models.toml` is
the `[models]` data that binds it.

| Server | GPU | Port | What it is | Seats |
|---|---|---|---|---|
| `serve-exl3.sh` | 0 | 18091 | `exl3_server.py`: EXL3 4 bpw target with the DFlash2 5 bpw draft at depth 7, Q8 caches, up to four requests in flight (see "The EXL3 scheduler") | first rung of `generative_reasoner`, `checker`, `dreamer_current` |
| `serve-llama.sh` | 1 | 18134 | llama.cpp `llama-server`: Q4_K_M target with the 0.8B Q8_0 draft, 2 slots | the fallback rung of those seats; the one rung of `local_reasoner`, which decide()'s decision read reaches on `/tokenize` and `/completion` |

The rulings this setup carries:

- **EXL3 with DFlash2, no schema** (owner, 2026-10-14, NIGHTLY-SWITCH = A):
  it decoded 2.11 times faster per request than the llama.cpp recipe and
  scored higher (RESEARCH-1232). Its provider sets `response_format = "none"`.
  llama.cpp with the schema stays as the rollback, here the fallback rung.
- **Draft depth 7 for every workload** (owner, 2026-10-16: "sure lets do 7
  and update if new evidence comes out"; RESEARCH-1305). `--draft-tokens`
  sets it; `ONEIRON_HOUSE_DRAFT_DEPTH` in `/etc/oneiron-house.env` moves it.
  The server refuses a depth deeper than the draft's own block.
- **The decision read runs on the house weights** (owner, 2026-10-16: no Jev
  API; escalation goes to the self-hosted house model). It needs llama.cpp's
  native API, so `local_reasoner` is the llama server alone.

## Weights

Put each under `/var/lib/oneiron-house/models/` (or set the paths in
`house.env.example`), and pin the revision you verified:

- EXL3 target: `turboderp/Qwen3.8-27B-exl3`, the 4.0 bpw branch, as
  `qwen3.8-27b-exl3-4bpw/` (it ships `chat_template.jinja`, which the server
  renders).
- DFlash2 draft: `Mia-AiLab/Qwen3.8-27B-DFlash2-EXL3-5.0bpw`, as
  `qwen3.8-27b-dflash2-exl3-5bpw/`.
- llama.cpp target: `Qwen3.8-27B-UD-Q4_K_M.gguf`.
- llama.cpp draft: `Qwen3.5-0.8B-Q8_0.gguf`.

Then write the EXL3 target's weights manifest beside it, once per deployed
snapshot (see "Launch identity"):

```sh
sudo python3 deploy/house-model/weights_manifest.py prepare \
  /var/lib/oneiron-house/models/qwen3.8-27b-exl3-4bpw \
  /var/lib/oneiron-house/models/qwen3.8-27b-exl3-4bpw.weights.json
```

The repository holds no real weights hashes: the operator, or the
Orchestrator when it deploys, writes this manifest from the installed bytes.

## Install

```sh
sudo useradd --system --home /var/lib/oneiron-house oneiron-house
sudo python3 -m venv /opt/oneiron-house/.venv
# a CUDA PyTorch wheel matching the driver first, then:
sudo /opt/oneiron-house/.venv/bin/pip install -r deploy/house-model/requirements.txt
# llama.cpp at the pinned commit with CUDA and request decoding, at
# /opt/oneiron-house/llama.cpp/build/bin/llama-server, with its build record
sudo apt-get install libzstd-dev zlib1g-dev
sudo deploy/house-model/build-llama.sh
sudo cp deploy/house-model/house.env.example /etc/oneiron-house.env
sudo cp deploy/systemd/oneiron-house-exl3.service deploy/systemd/oneiron-house-llama.service /etc/systemd/system/
sudo systemctl enable --now oneiron-house-exl3 oneiron-house-llama
```

Both units are templates: they expect the repo at `/opt/oneiron`. Each server
listens on loopback only and loads its weights before it answers; a request
never downloads or starts a model. Then merge `models.toml` into
`oneiron.toml`, and `GET /v1/ai/status` lists both rungs of each seat.

## Launch identity

Each reply's cache evidence names what answered it (FIX 7895). Identity
never stops a server: whatever fails below, the server starts and serves,
with the digests it could not take left out and one warning on stderr.

**llama.cpp.** The pin is llama.cpp
`d81235049384534c167caea52b85a694f6103d14`: `build-llama.sh` checks out
exactly that commit (a checkout with changes to tracked files is refused),
builds it, and writes `llama-server.build.json` beside the binary: the
commit, the CMake flags and the binary's SHA-256. Before each launch,
`serve-llama.sh` runs `llama_identity.py prepare`, which:

- mints a random 128-bit epoch for this launch;
- hashes every GGUF part the launch loads (target and draft, each part of a
  split GGUF), in full, at every launch, and the binary;
- reads the target's typed tokenizer metadata and its chat templates;
- records the launch's arguments, every `LLAMA_ARG_*` variable by name and
  value (one that may hold a credential, by its SHA-256) and any llama.cpp
  `config.ini` by its SHA-256 (with one present, the `model`, `tokenizer`
  and `template` digests are left out: the file could change them);
- writes the manifest, named by the SHA-256 of its exact bytes, into the
  manifests-only `ONEIRON_HOUSE_LLAMA_IDENTITY_DIR`
  (`/var/cache/oneiron-house/llama-identity`, inside the unit's cache
  directory). Manifests are kept, so an old launch's late answers still
  resolve.

llama-server then starts with `--alias oneiron-llama/<epoch>/<digest>`, its
only alias (`LLAMA_ARG_ALIAS` is unset), and `--path` on that directory with
`--ui`, since llama.cpp mounts `--path` only with its web UI on. The static
directory replaces the embedded web UI on this loopback port: the house
server has no browser UI. llama.cpp returns the alias as the `model` of
every chat, stream and native answer and as its `/v1/models` id, and serves
the manifest at `GET /<digest>.json`. The engine maps the alias to the
provider's configured model (`ONEIRON_HOUSE_LLAMA_MODEL_ID`, `qwen3.8-27b`,
which the manifest is bound to), fetches each manifest once, checks its
digest, epoch and configured model, and puts its digests into the record.
A launch whose identity cannot be prepared (an unwritable directory, an
unreadable file, a `config.ini` that sets an alias) starts as before: no
alias, no manifest, and its records name only the reported build.

**EXL3.** `weights_manifest.py prepare` lists every `*.safetensors` shard of
the target with its size and SHA-256 (above). At each launch the server
hashes the installed shards against it before any weights load; when they
match, the manifest's digest is the identity's `model`. A missing manifest
or a changed, missing or unlisted shard leaves `model` out, with a warning,
and the server serves. The `model` it returns and its `/v1/models` id stay
`qwen3.8-27b`.

**Deploying.** The operator, or the Orchestrator, rebuilds llama.cpp with
`build-llama.sh` (or records an existing build of the pin with
`llama_identity.py record-build BIN COMMIT -- FLAGS...`) and writes the EXL3
weights manifest whenever the weights change. A manifest attests a launch,
not a call: a request's own template arguments, samplers, reasoning or cache
options are not in it, so no record's `execution_mode` comes from it.

## The EXL3 server's wire

`POST /v1/chat/completions`, plain or streamed, `GET /v1/models` and
`GET /health`. It renders the target's chat template with the request's
`chat_template_kwargs`, so the engine's reasoning level reaches the model. A
thinking reply comes back split, as llama.cpp's `--reasoning-format deepseek`
splits it: the thought in `reasoning_content`, the answer in `content`.
`reasoning_budget_tokens` caps the thought: at the cap the server closes it
and the answer gets the rest of `max_tokens`. A `response_format` schema
constrains the answer only. A prompt that fills the context is refused with
`400` and `code = "context_length_exceeded"`. By default up to four
requests run at once; one that sets `"oneiron_solo": true` runs alone (see
"Solo admission").

## The EXL3 scheduler

One scheduler thread owns the exllamav3 generator (INF 1, FIX 6566). An HTTP
handler renders and tokenizes its request, submits it, and streams from its own
queue. Handlers never call the generator. The scheduler admits requests, starts
their jobs, iterates the generator and routes every event to the request it
belongs to. The same code runs one request at a time and up to four.

- **Queue.** Up to 4 submitted requests wait for admission in arrival order
  (`INGRESS_CAPACITY`). When those places are full, a further request waits
  in its own handler for one to free. No request is refused for load.
- **Admission.** A request is admitted when all four hold:
  - fewer than `--max-in-flight` requests are in flight;
  - no admitted answer pass is waiting for pages;
  - its pages fit in the shared pool beside the pages the admitted requests
    hold;
  - no solo request is in flight, and for a solo request, nothing is.

  Its pages are the generator's own count: prompt plus output cap plus 1 plus
  the draft depth, rounded up to 256-token pages. A thinking request also
  holds `CLOSE_ROOM_TOKENS` (16) for the closed thought and the answer's
  re-encode. A request that does not fit waits; its context is never shrunk,
  its size never refused, and no running job is evicted for it. Admission is
  strict arrival order, so a long request is never starved by short ones
  behind it. The `context_length_exceeded` 400 is unchanged.
- **Thinking.** A thinking request keeps one place and its pages through both
  passes. The reasoning job ends, then the answer job starts with what is
  left of `max_tokens`; the two never run at once. If the answer's re-encode
  needs more pages than were held, it waits for them before any new admission.
- **Cancellation.** A client that disconnects is noticed while its request
  waits for admission, while it waits for a token, and on any failed write.
  The scheduler then drops the queued request, or cancels its job in the
  generator, and frees its place. Other requests are untouched.
- **Errors.** A job's own error fails only its request. A failure of the
  generator's iteration fails every request that had a job in it. Neither is
  ever reported as a finished reply.
- **Timings.** Each reply's `timings` sums both passes into the six keys it
  always had. It adds:
  - `admission_wait_ms`: submit to admission;
  - `enqueue_wait_ms`: each job's enqueue to start, plus an answer's wait for
    pages;
  - `draft_depth` and `max_in_flight`: what the server ran with;
  - `peak_in_flight`: the most requests in flight while this one was (1
    for a solo request).

  Prefill and decode times are per-job intervals, which contain other jobs'
  work when several are in flight. They are not exclusive GPU time.

Two knobs, set in `/etc/oneiron-house.env`:

| Variable | Flag | Default | What it sets |
|---|---|---|---|
| `ONEIRON_HOUSE_EXL3_IN_FLIGHT` | `--max-in-flight` | 4 | requests in flight at once, 1 to 4 (`MAX_IN_FLIGHT`); the cache's recurrent slots and the generator's batch follow it |
| `ONEIRON_HOUSE_EXL3_CACHE_TOKENS` | `--cache-tokens` | `DEFAULT_CACHE_TOKENS` (40192), or one full request when that is larger: the context + 1 + the draft depth + 16, rounded up to 256 (33024 at the defaults) | the KV pool all requests in flight share, target and draft alike; a multiple of 256 and at least that floor |

The defaults are four in flight (Engine ruling 10-21, INF 1) over the pool
`DEFAULT_CACHE_TOKENS` names, the one place `exl3_server.py` sets it: 40192,
the largest of the pools INF 1 measured at four in flight (33024, 37120,
40192) whose peak leaves 2 GiB of the card's 24564 MiB (22488 MiB; FIX 6974).
The pool never drops below one full-context request with its draft and close
room (Engine ruling 10-20, FIX 6723; the context alone left a full request
one page short): 33024 at the default context and depth, so the default pool
holds one full request and about 7000 tokens beside it. Four in flight over
that pool admits beside a long call only what fits in the pages it leaves.

### Solo admission

A request body that sets top-level `"oneiron_solo": true` runs alone. When it
reaches the head of the queue, the scheduler stops admitting, lets every
request in flight finish, runs the solo request by itself (both passes of a
thinking one), then admits again. Arrival order holds: a solo request waits
behind the ones before it, and the ones behind it wait for it. A value other
than `true` or `false` is a `400`. The server logs one `SOLO_ADMIT` line per
solo admission, with the request id and its wait in ms, never the prompt.

The engine sets it, not an operator. `oneiron::llm::mark_solo` marks a call
whose answer is compared with another's: the Coach's exact replay, the
shadow runner's arms, the Coach's matched contribution forks, and
`oneiron-bench infer --solo on`. The OpenAI-compatible wire sends the field to
a `local-openai-compat` provider only; no other provider sees it. Batch
invariance does not hold at four in flight for a long or multi-turn request:
the same request can answer differently batched than alone. So identity
checks run solo, and every other call shares the batch.

## Cache evidence in `usage`

Every EXL3 reply's `usage`, plain or streamed, says what each Job of the
request read from the prompt cache (FIX 6567; `cache_usage.py` builds it):

- `prompt_tokens`, `completion_tokens` and `total_tokens` keep their meaning:
  `prompt_tokens` is the request's own prompt.
- `prompt_tokens_details.cached_tokens` is what the FIRST Job read from the
  cache, given only when that Job ran over the request's own prompt (a
  thinking request's reasoning pass, or the one pass of any other request)
  and its counts agree. `prompt_tokens` less it is what that pass computed.
  A zero thinking budget's first Job is already the answer's re-encode, so
  its reply has none.
- `inference_calls` holds one receipt, in the form the engine puts on the
  call's run receipt (`RunEvent::Settled.inference_calls`, FIX 8314):
  `worker` (`kind` `exl3`, `identity`, and `build_evidence`
  `reported_version`), `logical_prompt_tokens`, `passes` and `queue_wait`.
  - `queue_wait` has `worker_us`, submission to admission, and `engine_us`,
    each Job's enqueue-to-start with the answer pass's wait for pages, in
    whole microseconds. First-token time, end, output count and drafts are
    left out; the engine stamps the receipt's `model`.
  - `passes` has one entry per Job, in order: `reasoning`, `answer` (the
    re-encode of prompt, thought and close) or `prompt`. Each has the Job's
    own `input_tokens`, `cache_read_tokens` (exllamav3's `cached_tokens`,
    whole pages included), `cached_pages`, `computed_input_tokens` (input
    less read: logical work, not a kernel's tensor count), `prefill_us`,
    `generate_us` (per-Job intervals, not exclusive GPU time),
    `counter_source` `exl3_job`, and `outcome`: `hit`, `recompute`, or
    `unknown` when a count is missing or the read exceeds the input. A count
    the Job did not report is left out, never written as zero.
  - `worker.identity` holds SHA-256 digests of what answered: `template`, the chat
    template's bytes; `tokenizer`, the target directory's tokenizer files
    and `config.json`; `runtime`, the installed exllamav3, torch and Python
    versions as reported; `cache_mode`, the caches' settings; and
    `execution_mode`, the server's settings with the request's
    `chat_template_kwargs` and solo flag. `backend_epoch` is 32 hex digits
    minted once when the Generator is built, so a restart is a new epoch.
    `model` is the weights manifest's digest, given only when the installed
    shards matched it at launch. Nothing in it reads the `model` a request
    names.

`timings` keeps its meaning: `prompt_n` is still the logical prompt.

`llama-server` reports its own counts: what it read as
`usage.prompt_tokens_details.cached_tokens` and `timings.cache_n`, what it
computed as `timings.prompt_n`. The engine builds
the same receipt from them (`kind` `llama_cpp`, one `prompt` pass; an answer
that names its launch alias but reports no timings gets a receipt with no
pass), and a read is `unknown` when those counts disagree. Its
`build_evidence` is `verified_artifacts` only when the launch's manifest
verified and lists its build, else `unknown`. Its identity is what the
answer's own alias names: `backend_epoch` from the alias, and from the
launch's verified manifest `model`, `tokenizer`, `runtime` (the build),
`template` and `cache_mode`. A manifest that did not verify leaves those
out, and a reply without an alias has no epoch either; a chat record then
names its `runtime` as a digest of the reply's `system_fingerprint` (a build,
not an incarnation). `tokens_cached` is the slot's occupancy, which
counts generated tokens, and is never read as cache hits. Each decision-read
answer gets a `label_read` record the same way, from its native
`tokens_evaluated`, `timings` and `model`, each answer and each retry with
its own alias's identity; a native record never names a `template`, since
the host's recipe renders its prompt. No llama record names an
`execution_mode`.

## Compressed requests

Both servers decode a request body sent gzip- or zstd-encoded (OF-604), so
both entries in `models.toml` set `request_compression = "zstd"`: the engine
sends a body of 16 KiB or more in zstd level 3 when that is smaller.
`exl3_server.py` decodes with `body_codec.py` (zstd needs Python 3.14 or the
`zstandard` package in `requirements.txt`); `llama-server` decodes when
`build-llama.sh` built it, with cpp-httplib's zstd and zlib support on. A
server that cannot read the codec answers 415 (an older `llama-server` may
answer 400); the engine then sends that request again, plain, and sends that
provider plain bodies until it restarts.

A vLLM server decodes through the same module as an ASGI middleware:

```sh
PYTHONPATH=/opt/oneiron/deploy/house-model \
  vllm serve <model> --middleware body_codec.DecodeContentEncoding
```

Then its entry may set `request_compression = "zstd"` too.

## Reasoning history probe

An offer may declare `reasoning_content_history` (FIX 8307) only when its
server reads an assistant's earlier reasoning back from the chat
`reasoning_content` field. With it, the engine sends an assistant message's
reasoning in that field instead of as ordinary content. No house offer
declares it yet, so `models.toml` sends reasoning as content on both.

`probe_reasoning_history.py` collects the evidence for one offer. It is an
ops tool, not a test, and it needs only Python's standard library. It runs on
the GPU host (Linux only) against the server already running there, on its
loopback port. It never starts, restarts or loads anything, and it never
retries or repairs a reply. It holds two conversations, one plain and one
streamed, of three real turns each:

1. With one tool offered, the reply must carry nonempty reasoning, a short
   ordinary preamble and exactly one tool call with JSON-string arguments.
2. That assistant goes back unchanged (reasoning, content and the call's id),
   with a tool result under the same id. Its value is minted only after turn 1,
   and the answer must be exactly `RESULT=<value>`.
3. The answer goes back with its reasoning, and the model must repeat the
   same line with no tool call.

The operator runs it once per offer, with a new evidence path each time:

```sh
# llama.cpp: save the template the running server renders
curl -s http://127.0.0.1:18134/props \
  | python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["chat_template"])' \
  > /tmp/llama-template.jinja
python3 /opt/oneiron/deploy/house-model/probe_reasoning_history.py \
  --base-url http://127.0.0.1:18134 --backend llama \
  --offer 'llama/qwen3.8-27b@qwen3.8-27b-q4km' \
  --server-revision <llama.cpp commit> --weights-revision <GGUF revision> \
  --template /tmp/llama-template.jinja \
  --runtime-file /opt/oneiron-house/llama.cpp/build/bin/llama-server \
  --booking-ref <fleet booking> --evidence /tmp/reasoning-history-llama-<run>.json

# EXL3: the target's own template and the server's source
python3 /opt/oneiron/deploy/house-model/probe_reasoning_history.py \
  --base-url http://127.0.0.1:18091 --backend exl3 \
  --offer 'exl3/qwen3.8-27b@qwen3.8-27b-exl3-4bpw-dflash2-d7' \
  --server-revision <oneiron commit> --weights-revision <EXL3 revision> \
  --template /var/lib/oneiron-house/models/qwen3.8-27b-exl3-4bpw/chat_template.jinja \
  --runtime-file /opt/oneiron/deploy/house-model/exl3_server.py \
  --booking-ref <fleet booking> --evidence /tmp/reasoning-history-exl3-<run>.json
```

`--wire-id` is the offer's configured wire model (default `qwen3.8-27b`);
every request names it. EXL3 must advertise and answer with exactly that id.
A llama launch advertises and answers under its launch alias instead
(`oneiron-llama/<epoch>/<manifest digest>`, "Launch identity" above), which
stands for the wire id. One run must see one alias: a second one means the
server restarted mid-run, and the run fails. The evidence keeps the raw ids
(`advertised_model_ids`, `served_model_ids`, `llama_alias`).

`--offer`, `--server-revision`, `--weights-revision` and `--booking-ref` are
the operator's own labels, kept as given. Pair the JSON with the booking's log
and the service's launch recipe. The JSON also keeps every request and raw
reply, each named check, and the SHA-256 of the probe, template, runtime and
any `--tokenizer-file`. The file is created exclusively, so it is written even
when the run fails and is never overwritten. The probe exits 0 only when its
`declaration_ready` is `true`. Its fixed settings are temperature 0, seed 8307
and the EXL3 solo marker. `--max-tokens` (2048), `--reasoning-budget` (512),
`--effort` (`medium`) and `--timeout` (180 s) can be changed.

Today's `exl3_server.py` passes no request tools to its template and returns
no `tool_calls`, so the EXL3 run fails at turn 1. Keep that JSON too.

**A pass is what allows the declaration.** After the lead accepts a pass for
that exact server, weights, template and wire id, one line goes inside that
provider's own block, with a comment pointing at the evidence:

```toml
model_capabilities."qwen3.8-27b" = ["streaming", "json_response", "reasoning", "reasoning_content_history", "tool_calling", "tool_results"]
```

The list replaces the provider's default (`streaming`, `json_response`,
`reasoning`), so it names those three again. A pass on one backend says
nothing about the other. The installed `oneiron.toml` needs the same line:
this file is not deployed by itself.
