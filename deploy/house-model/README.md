# The house model (OF-129)

The house model is Qwen3.8-27B on two GPUs of the owner's own machine. It
serves every generative seat and the local reasoner, with no cloud rung. The
engine names no model: these files are the deployment, and `models.toml` is
the `[models]` data that binds it.

| Server | GPU | Port | What it is | Seats |
|---|---|---|---|---|
| `serve-exl3.sh` | 0 | 18091 | `exl3_server.py`: EXL3 4 bpw target with the DFlash2 5 bpw draft at depth 7, Q8 caches, batch 1 | first rung of `generative_reasoner`, `checker`, `dreamer_current` |
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
`400` and `code = "context_length_exceeded"`. Requests take turns: one runs
at a time, as the measured recipe ran.

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
