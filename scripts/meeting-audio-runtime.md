# Offline native meeting-audio runtime profile

This is an optional host adapter, not model acquisition or qualification.
`scripts/meeting-audio-native.py` keeps its decode/VAD/text probe without a profile.
The three artifact ports refuse unless the host provides existing dependencies,
local model files, and the profile below. No UV launcher, installer, hub identifier
fallback, network model fetch or guessed alignment runs. HF/Transformers offline
mode and pyannote telemetry opt-out are set in the child process.

The Rust host uses `CommandMeetingAudioHost::with_runtime_profile(path, sha256)`.
The equivalent Python flags are `--runtime-profile /absolute/profile.json`
and `--runtime-profile-sha256 <sha256-of-exact-profile-bytes>`. Both are required.
The Rust adapter rechecks the profile before every port call; Python checks it
again. Capability data binds the profile and the helper's source digest, but is
not a licence, consent, E1/E3 result, or an OF-133 default-selection act.

## Version 1 shape

Top-level keys are exactly `version` (integer 1), `packages`, `asr`, `alignment`,
`diarization`, and `cleanup`. Each port entry may be `null` (unavailable).
`packages` maps distribution names to exact installed versions. No version is
invented here. Required names for configured entries are:

- ASR: `mlx-audio`, `mlx`, `silero-vad`, `onnxruntime`.
- Alignment: `qwen-asr`, `torch`.
- Diarization: `pyannote.audio`, `torch` (community-1's exclusive-output API is 4.x).
- Cleanup: `mlx-lm`, `mlx`.

Each non-null entry has exactly these fields:

- `model_id`: ASR is `mlx-community/Qwen3-ASR-1.7B-8bit`; alignment is
  `Qwen/Qwen3-ForcedAligner-0.6B`; diarization is
  `pyannote/speaker-diarization-community-1`. Cleanup names the chosen local model.
- `snapshot`: an absolute, already provisioned local directory. The ASR path must
  equal the Rust host's `model_snapshot` path.
- `files`: every relative file name in that directory mapped to its lowercase
  SHA-256. Missing, additional, changed and unsafe paths refuse. Regular file
  links into the existing HF cache are hashed by actual bytes; directory links
  refuse. The directory must remain immutable during inference.
- `access_ref`: the operator's legal-access record reference. This is data, not
  an engine-issued licence or verification that the record exists.

Cleanup additionally requires `instructions`, `instructions_sha256`,
`max_input_tokens` (1..32768) and `max_tokens` (1..8192). `instructions` is an
absolute UTF-8 file from the host's admitted adapter skill, at most 64 KiB. Its
exact bytes must hash to the supplied digest and contain exactly one
`{{TRANSCRIPT_JSON}}` placeholder. Instruction/persona text does not live in the
engine. The declared model must return strict JSON `{"texts":[...]}` with one
nonblank string per supplied turn and no other keys. Contiguous whole-turn groups
are bounded by the input token budget; a single oversized turn refuses. No
truncation or identity cleanup is reported as successful inference. The engine's
fix-don't-invent validator still checks the returned text against aligned words.

## Native calls and boundaries

- Qwen alignment calls `Qwen3ForcedAligner.from_pretrained(local_path,
  dtype=torch.float32, device_map="cpu")`, then `align(audio=(pcm,16000), text=...,
  language=...)`. Returned `text/start_time/end_time` words are validated and
  converted from seconds to milliseconds. No ASR chunk times become word times.
- An explicit supported `AudioFile.language_hint` is required. The documented
  11 languages are Chinese, English, Cantonese, French, German, Italian,
  Japanese, Korean, Portuguese, Russian and Spanish. `None`, Ukrainian and
  unknown labels refuse; Ukrainian is never silently relabelled as Russian.
  A UK-capable alignment/ASR-timing backend remains a separate provisioning and
  qualification requirement for that part of the cohort.
- Community-1 loads its local directory through `Pipeline.from_pretrained` and
  is called exactly once on the full decoded waveform. Only
  `exclusive_speaker_diarization.itertracks(yield_label=True)` is accepted.
  Provider speaker labels are retained; overlapping/invalid tracks refuse.
- MLX cleanup loads the local model with remote tokenizer code disabled. The
  pinned external instruction file is applied to each bounded group. The output
  must be complete, ordered and strict JSON; the core validates lexical changes.

The Qwen and pyannote API lookup was documentation research, not native execution
against provisioned models. Seven standard-library synthetic tests exercise the
pins, SDK call shapes, output conversion, language refusal, global-pass rule and
cleanup grouping. No test package is a real model or an E1/E3 benchmark.

## Exact remaining qualification inputs

Use the existing MacBook interpreter recorded in `impl-notes/W7-C02.md`; do not
run an inline launcher. The owner must provision compatible licensed runtimes,
full immutable snapshot/file hashes and access records for alignment, community-1
and cleanup. MOSS comparison needs its own pinned runtime/snapshot and genuine
full-file output. The recorded-output evaluation interface accepts those outputs
but does not run MOSS or turn synthetic outputs into E3 evidence. E1 additionally
needs the consented JP/EN/UK corpus, reference/tokenization policy and arm pins.
E3 needs real word/time/two-speaker labels. A completed E1 report still does not
change the ASR default: the caller must supply the authenticated OF-133 act.
