# Local speech-recognition worker (FIX 8318)

`worker.py` serves Whisper through transformers on one CUDA device, as a
worker the engine's own supervisor installs, launches, qualifies, restarts
and stops. It is not started by hand: it takes its weights directory, the
weights manifest the supervisor verified it against and the supervisor's
launch manifest, and checks the launch and hashes every pinned file again
before the weights load. Nothing is downloaded, no code from the weights'
repository runs, and it never serves from the CPU.

It speaks the OpenAI-compatible transcription wire the engine's media
client sends, `POST /v1/audio/transcriptions` (multipart `model`, `file`,
`response_format = "json"` and an optional `language`; any other field is
refused). The file is a PCM16 WAV, mono or stereo, at any rate from 8 to
192 kHz; it is downmixed to mono, resampled to 16 kHz and transcribed whole,
however long (Whisper's long-form decoding, greedy, in the language it
detects unless the call names one). MP3 and other codecs are not read. The
answer is `{"text", "duration", "model", "usage"}`; `usage` holds one
inference receipt naming the worker's verified identity and its epoch, and
the launch manifest's digest. One transcription runs at a time; a request
past it waits. `GET /health` is liveness only, `GET /stats` (bearer) the
queued and active requests and the CUDA allocator's reservation.

## The row

No house pin exists for a speech-recognition model. The operator writes
the weights manifest: the repository, its full commit, and every file the
worker loads (`config.json`, `generation_config.json`,
`preprocessor_config.json`, the tokenizer files and each `*.safetensors`
shard, plus any index) with its size and SHA-256, and the licence evidence
file. The documented default is `openai/whisper-large-v3`, whose card
declares MIT; the licence is admitted as for any model. Build the
environment lock from `requirements-asr.txt` with the command in its
header.

```toml
[models.providers.hearing]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:8770"
key_env = "ONEIRON_ASR_TOKEN"

[models.workers.hearing]
model = "hearing:whisper-large-v3"
kind = "asr"
weights_manifest = "/home/lexi/oneiron-manifests/whisper-large-v3.json"
env_lock = "/home/lexi/oneiron-locks/whisper-py312.lock"
# device = "0"
# idle_stop_secs = 300          # left out: the worker stays up

[models.media.transcribe]
rungs = ["hearing:whisper-large-v3"]
```

A managed row needs its provider's `key_env` (a credential of 32 or more
characters, passed to the worker under that name alone) and its `env_lock`,
and names no `args`, `env`, `draft` or `server`. The supervisor counts the
worker ready only after one actual transcription of a synthetic silent clip
names this launch. `mode = "external"` keeps an ASR server you run yourself:
it is probed with the same one transcription and never started or stopped,
and an `openai-compat` provider may serve it when its `locality` is
`own_server`. A deployment that already serves ASR keeps its endpoint and
model: a provider with no worker row is called as it always was.
