# The house model (OF-129)

The house model is Qwen3.8-27B on two GPUs of the owner's own machine. It
serves every generative seat and the local reasoner, with no cloud rung. The
engine names no model: these files are the deployment, and `models.toml` is
the `[models]` data that binds it.

| Server | GPU | Port | What it is | Seats |
|---|---|---|---|---|
| `serve-exl3.sh` | 0 | 18091 | `exl3_server.py`: EXL3 4 bpw target with the DFlash2 5 bpw draft at depth 7, Q8 caches, one request in flight (see "The EXL3 scheduler") | first rung of `generative_reasoner`, `checker`, `dreamer_current` |
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

## Install

```sh
sudo useradd --system --home /var/lib/oneiron-house oneiron-house
sudo python3 -m venv /opt/oneiron-house/.venv
# a CUDA PyTorch wheel matching the driver first, then:
sudo /opt/oneiron-house/.venv/bin/pip install -r deploy/house-model/requirements.txt
# llama.cpp with CUDA and request decoding, at /opt/oneiron-house/llama.cpp/build/bin/llama-server
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

## The EXL3 server's wire

`POST /v1/chat/completions`, plain or streamed, `GET /v1/models` and
`GET /health`. It renders the target's chat template with the request's
`chat_template_kwargs`, so the engine's reasoning level reaches the model. A
thinking reply comes back split, as llama.cpp's `--reasoning-format deepseek`
splits it: the thought in `reasoning_content`, the answer in `content`.
`reasoning_budget_tokens` caps the thought: at the cap the server closes it
and the answer gets the rest of `max_tokens`. A `response_format` schema
constrains the answer only. A prompt that fills the context is refused with
`400` and `code = "context_length_exceeded"`. By default requests take
turns: one runs at a time, as the measured recipe ran.

## The EXL3 scheduler

One scheduler thread owns the exllamav3 generator (INF 1, FIX 6566). An HTTP
handler renders and tokenizes its request, submits it, and streams from its own
queue. Handlers never call the generator. The scheduler admits requests, starts
their jobs, iterates the generator and routes every event to the request it
belongs to. The same code runs one request at a time and up to four.

- **Queue.** Up to 4 submitted requests wait for admission in arrival order
  (`INGRESS_CAPACITY`). When those places are full, a further request waits
  in its own handler for one to free. No request is refused for load.
- **Admission.** A request is admitted when all three hold:
  - fewer than `--max-in-flight` requests are in flight;
  - no admitted answer pass is waiting for pages;
  - its pages fit in the shared pool beside the pages the admitted requests
    hold.

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
  - `peak_in_flight`: the most requests in flight while this one was.

  Prefill and decode times are per-job intervals, which contain other jobs'
  work when several are in flight. They are not exclusive GPU time.

Two knobs, set in `/etc/oneiron-house.env`:

| Variable | Flag | Default | What it sets |
|---|---|---|---|
| `ONEIRON_HOUSE_EXL3_IN_FLIGHT` | `--max-in-flight` | 1 | requests in flight at once, 1 to 4 (`MAX_IN_FLIGHT`); the cache's recurrent slots and the generator's batch follow it |
| `ONEIRON_HOUSE_EXL3_CACHE_TOKENS` | `--cache-tokens` | one full request: the context + 1 + the draft depth + 16, rounded up to 256 (33024 at the defaults) | the KV pool all requests in flight share, target and draft alike; a multiple of 256 and at least that floor |

The defaults are today's server: one request at a time, over a pool that
holds one full-context request with its draft and close room (Engine ruling
10-20, FIX 6723; the context alone left a full request one page short). Four
in flight is gated. It ships only after both runs pass
on INFER-BENCH (FIX 6559): E5, batch invariance (the same request gives the
same output alone and batched, at the same draft depth), and E1 (short calls
beside one long Dreamer-like call, one in flight against four, over the same
pool). Until then no deploy raises either knob. Four in flight over the
default pool admits beside a long call only what fits in the pages it leaves.

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
