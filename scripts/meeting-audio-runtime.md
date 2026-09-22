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

Required top-level keys are `version` (integer 1), `packages`, `asr`, `alignment`,
`diarization`, and `cleanup`. Optional `moss` enables the E3 comparison port. Each port entry may be `null` (unavailable).
`packages` maps distribution names to exact installed versions. No version is
invented here. Required names for configured entries are:

- ASR: `mlx-audio`, `mlx`, `silero-vad`, `onnxruntime`.
- Alignment: `qwen-asr`, `torch`.
- Diarization: `pyannote.audio`, `torch` (community-1's exclusive-output API is 4.x).
- Cleanup: `mlx-lm`, `mlx`.
- MOSS comparison: `mlx-audio`, `mlx`, `mlx-lm`.

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
against provisioned models. Eight standard-library synthetic runtime tests exercise the
pins, SDK call shapes, output conversion, language refusal, global-pass rule and
cleanup grouping. Five harness tests cover output-bound enrollment mapping and
separate setup/failure/capture/scoring states. No test package is a real model or an E1/E3 benchmark.

## Exact remaining qualification inputs

Use the existing MacBook interpreter recorded in `impl-notes/W7-C02.md`; do not
run an inline launcher. The owner must provision compatible licensed runtimes,
full immutable snapshot/file hashes and access records for alignment, community-1
and cleanup. MOSS comparison needs its own pinned snapshot and genuine full-file output.
The new E3 capture CLI below runs its native port, but no such inference has been
claimed here. Synthetic outputs never become E3 evidence. E1 additionally
needs the consented JP/EN/UK corpus, reference/tokenization policy and arm pins.
ARCH-0061 §8 fixes its comparison to Qwen3-ASR-1.7B versus Soniox async; the Soniox
arm is not optional and MOSS is not a substitute. Soniox needs approved hosted
processing/region, the existing credential-custody path and a real role-bound call.
E3 needs real word/time/two-speaker labels. A completed E1 report still does not
change the ASR default: the caller must supply the authenticated OF-133 act.

## MOSS and the live E3 harness

A `moss` descriptor has the same four common fields plus `max_tokens` (1..65536).
Its `model_id` is `OpenMOSS-Team/MOSS-Transcribe-Diarize`. Local MLX weights must
be separately provisioned and pinned. The installed MacBook `mlx-audio 0.4.7`
source was read without importing a model: its parsed segments use **speaker_id**,
not `speaker`; the no-parse fallback lacks that field and must refuse. The adapter
checks the MOSS implementation class and 16 kHz rate, sends the full waveform to
one `generate` call and refuses token-budget exhaustion. SDK encoder-feature
chunks feed that one decode; the bridge never reclusters by ASR pack. Segment
times and speaker IDs stay segment data, never fabricated word timestamps.

`meeting-audio-e3.py capture` takes `--workspace`, `--ffmpeg`, `--model-snapshot`,
`--runtime-profile`, `--runtime-profile-sha256`, `--cohort` and `--output` (new
private directory). Run with the existing interpreter itself. Each model port
gets a separate bounded framed process. Capture writes setup first, then actual
per-arm start/completion events, and only after both arms on every file writes
`completion.json` with `phase: capture_complete`. Failure is `phase: failed`.
An existing output directory is never overwritten. Capture is not named-identity
scoring or qualification.

The cohort JSON has `schema: oneiron.audio.e3.cohort.v1`, `corpus_id`, and `files`.
Each file has `file_id`, `audio_path`, `audio_sha256`, `reference_path`,
`reference_sha256`, and `consent_ref`. Paths are relative to the cohort file unless
absolute. Audio and exact reference bytes are hashed before inference. References
have `language`, `tokenizer`, and `words`; each word has `word_id`, integer
`start_ms`/`end_ms` and `principal_id`. IDs must be unique, durations valid and each
file must contain at least two labelled principals. These are supplied ground
truth, not generated labels.

After approved enrollment/centroid matching, run `meeting-audio-e3.py score
--capture <directory> --matches <receipts.json>`. Matching JSON has:

- `schema: oneiron.audio.e3.enrollment_matches.v1`;
- `enrollment_sha256`, `enrollment_consent_ref`, `matcher_model_sha256`,
  `matcher_runtime_sha256`;
- `matches`: one entry per file/arm with `file_id`, `arm` (`community1` or `moss`),
  `audio_sha256`, `tracks_sha256`, `receipt_ref` and `cluster_to_principal`.

Mappings must name clusters that the bound output actually contains. They are
host-supplied matching receipts, not proof the engine performed enrollment. No
truth-fitted permutation or invented speaker identity is allowed. Timestamp-IoU
selects each reference word's predicted cluster; missing and wrong principals
are counted. Scoring verifies captured bytes and output bindings. Its report is
still evidence for human qualification, never a self-issued pass or a default
selection. The harness writes no voice-identity claim or consent grant.

## Isolated model ports (current provisioning contract)

`qwen-asr==0.0.6` requires `transformers==4.57.6`. The existing MLX environment
requires Transformers >=5.14. Do not downgrade it or install with `--no-deps`.
The main profile's `alignment` and/or `diarization` field may instead be an
explicit process descriptor:

```json
{
  "backend": "process",
  "interpreter": "/absolute/provisioned/venv/bin/python",
  "python_version": "exact.provisioned.version",
  "script": "/absolute/engine/scripts/meeting-audio-worker.py",
  "code_sha256": {
    "meeting-audio-worker.py": "64-lowercase-hex",
    "meeting-audio-native.py": "64-lowercase-hex",
    "meeting_audio_runtime.py": "64-lowercase-hex",
    "meeting_audio_process.py": "64-lowercase-hex",
    "meeting_audio_ctc.py": "64-lowercase-hex"
  },
  "profile": "/absolute/worker-profile.json",
  "profile_sha256": "64-lowercase-hex",
  "timeout_seconds": 600
}
```

These are placeholders, not usable pins. The provisioner emits actual path,
interpreter/version, code hashes, dependency lock and model file hashes. The
worker gets its own version-1 profile with only its local model stages enabled;
its package pins belong to its isolated interpreter, not the parent MLX process.
A worker cannot delegate to another process. Missing models produce a capability
refusal, not invented words or a ready runtime. Calls use isolated Python (`-I`),
offline Hub/Transformers flags, exact PCM16, a bounded request/response protocol
and a process-group deadline. Neither process installs or resolves dependencies.
The capability receipt is `model_execution=false`; measured provenance is emitted
only after the invoked model returns. The parent rechecks code/profile/runtime,
audio, transcript, language, output bounds and monotone word/track clocks.

Alignment workers accept `align_words`; diarization workers accept one
`diarize_full_file` request containing the full decoded file. E3 capture now binds
the worker's actual model-file digest rather than assuming a model lives inside
the main interpreter. Source component hashes travel with native provenance.

## Explicit Ukrainian CTC timing candidate

The optional `uk_alignment` field has the same local snapshot/file/access shape
as `alignment`, but its model ID is `Yehor/w2v-xls-r-uk` and its required packages
are `torch` and `transformers`. It can coexist with the Qwen aligner inside the
separate worker, or run in its own compatible worker. Preserve the provisioner's
researched immutable revision `55b6dc09dc1d43fe655018e24e6ff77305ff0879`; newer main
`e3ced4def0d70be3aab0f2db598a59961fe9ab3b` is not an automatic upgrade.

This port calls local `Wav2Vec2Processor`/`Wav2Vec2ForCTC` safetensors and CPU
float32 acoustic emissions. A bounded standard CTC recurrence aligns the exact
transcript; repeated letters require distinct states separated by blank. No
WhisperX, language model decoder, NLTK download or English sentence splitter is
required. The LM files in that model repository are not needed for CTC alignment.

Input language is explicitly `uk`/`Ukrainian`. Output keeps original word text;
case/apostrophe normalization affects acoustic tokens only, and attached unspoken
punctuation receives no independent acoustic boundary. Digits, Latin/mixed-script
words, punctuation-only words, unknown characters and impossible/over-budget
paths refuse. No wildcard or interpolated time is accepted. Frame coordinates
map to the exact PCM sample interval; these are candidate acoustic boundaries,
not measured meeting timing quality. The real consented timed cohort is still
required for qualification.

The pinned Qwen ASR family itself does not declare Ukrainian support. Its native
port now explicitly refuses Ukrainian hints rather than letting a timing backend
masquerade as ASR coverage or silently using Russian. E1 must record an unsupported
arm honestly and/or use an explicitly eligible OF-133 ASR route. Soniox access,
cohort consent and the post-measurement default-selection act remain separate.
