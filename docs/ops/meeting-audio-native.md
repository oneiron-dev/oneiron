# Native meeting-audio model bindings

The core meeting-audio producer can use `CommandMeetingAudioHost` to drive an
operator-provisioned, offline Python runtime. It does not install packages,
download models, or import recording bytes into a vault by itself. The owner
CLI builds this host and its admission seats; there is no server configuration
section for it. The host API still needs an authenticated OF-133 ASR route
receipt; a model name or evidence reference is not that receipt.

## Owner command

`oneiron meeting-transcript <recording> --native-config <host-json> --language <language>` produces the
native meeting-transcript artifact. It reads the ordinary `serve` configuration
and accepts the same flattened configuration flags, including `--config` and
`--vault-path`. The vault must already exist and be stopped. The existing owner
command writer lease admits this local host act; a remote bearer credential does
not supply this configuration.

Output is JSON on stdout, or an owner-only new file with `--out`. An existing
output file is never overwritten. `--capture-started-at` supplies the recording's
start in Unix milliseconds when known. `--language` is required: it supplies the
recording's language for both native ASR and forced alignment. The configured
runtime must support that language; the command chooses no language default.
No recording is imported, no voiceprint is enrolled, and no claims are admitted.
A later import still needs the existing complete-artifact bulk consent.

The host JSON has these fields:

- `runtime`: the absolute `python`, `bridge`, `ffmpeg`, `workspace`, and
  `model_snapshot` paths from `CommandAudioConfig`. The interpreter, scripts,
  packages, model files, and prompts must already be provisioned.
- `runtime_profile`: an optional object with the absolute profile `path` and its
  `sha256`. Full artifact production needs the existing configured native ports.
- `asr_tier`: the tier this actual native ASR binding serves.
- `asr_override`: an optional explicit purpose row with `tier` and `locality`.
  Selection reads the current vault ASR-batch row and its existing
  `voice_precedence`. This native command only offers `on_device`; it never
  silently relabels an `own_server` or `third_party` selection. Configure the
  vault row or an allowed explicit override for the actual native binding.
- `budget`: the run's `limit_units`, `reserve_units`, and named `unit`.
- `call_class`: the ordinary call class supplied by the host.
- `rates`: a `NativeRate` for each of `vad`, `diarization`, `asr`,
  `alignment_window`, and `cleanup_group`. Each rate supplies `unit`, `per`, and
  `tokens`; the four audio kinds count `audio_second`, and cleanup counts
  `token`. A denominator must be positive. The command chooses no prices.
- `line_rates`: token-to-budget-unit `UnitRate` rows (`unit`, `per`, `cost`), or
  an empty list for a token-denominated line.
- `glossary`: optional immutable terms, empty when omitted.
- `cleanup_policy`: an optional existing acoustic correction policy.

Every seat is built from the inspected actual model-file identity. All native
alignment bindings are retained. The same owner-initiated `RunAdmission` serves
the VAD, ASR, full-file diarization, alignment windows, and cleanup groups. Each
unit still starts and settles its own `WireSeat` permit. These are genuine
keyless local offers; existing on-device admission is unmetered, not a fabricated
zero price or a host allocation.

`producer.route_receipt` carries the full host selection record: the actual
owner and local vault, optional rooted vault identity, run instance, live vault
policy and precedence, explicit override, selected backend, native route, and
checked model-file bindings. `producer.route.route_receipt_ref` is `sha256:` plus
the SHA-256 of that record's `canonical_json_bytes` encoding (recursively sorted
JSON object keys). The hash names the carried record, not an absent lookup row.
`producer.run_receipts` carries the actual admission, dispatch, and settlement
records collected during successful production. Selection and usage records are
host reports, not signatures, durable vault records, physical execution
attestations, E1 evidence, or import permission. The batch default remains
provisional; the command does not claim a bake-off ran.

## Admission protocol

The bundled bridge, subprocess ports, and Rust adapter use
`oneiron.meeting_audio.host.v3`. A physical model call emits a `unit` frame with
`kind`, `index`, `audio_ms`, and `model`. The bridge waits for the Rust host's
admission answer before running that unit. The existing progress, failure,
usage, and process-containment behavior is unchanged.

`model` is the actual model ID followed by `@` and the SHA-256 of its model-file
manifest. Profile-backed models use the existing checked `files` manifest;
this is a content revision, not an assumed Hugging Face commit or the snapshot
directory's name. The VAD binding identifies the installed ONNX asset bundle.
A subprocess port carries its own checked model identities through the parent
bridge without relabeling them as the parent's model.

`CommandAudioConfig::inspect_capabilities` reads these bindings before seats
are built. Pass the optional runtime profile's path and SHA-256; inspection
accepts metadata and progress only, never an inference-unit request. The bound
host's `inspect_capabilities` uses the same process path and then checks its
route and seats.

Capabilities expose the bindings in `unit_models`, keyed by `vad`, `asr`,
`diarization`, `alignment_window`, and `cleanup_group`. This is model metadata,
not an inference result, bake-off qualification, or proof of physical locality.
Capabilities do not run inference. The existing runtime/profile/code checks
still apply.

`MeetingAudioSeats` has one `WireSeat` for VAD, diarization, ASR, and cleanup.
Its `alignment` field is a vector of seats: the default forced aligner and an
optional language-specific aligner have different model IDs and file manifests.
Construct the vector from all of the configured runtime's alignment bindings;
do not charge a Ukrainian alignment window to the default Qwen model.

The Rust adapter compares the configured seat IDs with the capability bindings.
It then resolves every unit by both kind and exact model ID before admitting it.
The four audio unit kinds still use `AiOperation::Transcribe`; cleanup groups
still use `AiOperation::Text`. Each physical unit retains its own permit and
settlement on its configured rates. No new operation, budget, deadline, or
model rate is selected by this protocol.

## Provisioning after an update

Deploy the matching Rust adapter and all five bundled Python files together:

- `scripts/meeting-audio-native.py`
- `scripts/meeting_audio_runtime.py`
- `scripts/meeting_audio_ctc.py`
- `scripts/meeting_audio_process.py`
- `scripts/meeting-audio-worker.py`

The operator must re-provision runtime profiles whose code manifests pin the
old files. Keep the existing model, prompt, profile, interpreter, and code hash
checks. Do not repair those hashes by editing pinned fixtures. There is no
old-protocol reader or automatic profile migration.

An existing no-profile ASR text call remains a local snapshot call. Its model
binding comes from that snapshot's actual files; it must not receive a
placeholder revision. Full meeting-transcript production still requires the
existing alignment, diarization, cleanup, ASR policy, and import-consent inputs.


## Artifact revisions and speaker labels

A produced artifact keeps `raw_turns`, the exact aligned turns before cleanup,
alongside the cleaned `turns` and the existing word and correction provenance.
The raw text remains part of the exported artifact and its import-consent hash;
cleanup does not remove it. The producer itself retains this in memory. The
owner-selected storage doors below use native blob versions; neither API is a
SESSION revision history or a separate erase-lifetime implementation.

`ProducedMeetingTranscript::with_speaker_labels` returns a separate artifact.
Its map keys are the existing anonymous speaker clusters. Its values are explicit
source labels, not authenticated PERSON identities or biometric enrollment.
Only matching clusters change; unmentioned clusters and existing labels remain.
A map that changes nothing returns the original artifact bytes. The original
artifact is never mutated. A changed artifact must obtain import consent for its
own exact bytes through the existing `authorize_import` method. Imported/Proposed
admission and all downstream Gate checks remain unchanged.

## Owner-selected native artifact storage

`Vault::persist_meeting_transcript_as_owner` accepts a real `AuthenticatedOwner`,
an exact retained source-audio version pin, the produced artifact, and an explicit
name. It revalidates the owner in its committing writer. The actual source bytes
must match both `recording.source_sha256` and `recording_id`; the native version
claim and BLAKE3 pin are checked in that same snapshot. This binds the selected
recording bytes, not proof that the host ran ASR or used the named model.

Each explicit save creates a fresh `application/json` blob artifact and stores
the exact JSON bytes as its first native version in the same transaction. The
artifact inherits the source artifact's secret-taint references. Its native
`made_by` inputs include the exact source-audio version's ledger claim. No second
revision table or consent ledger is added. `StoredMeetingTranscript` returns the
source and transcript version pins; those data fields are not credentials.

`Vault::label_meeting_transcript_as_owner` reads the selected stored version and
its source audio again in one owner-bound writer. It checks the persisted
source-version relationship and derives labels from those exact JSON bytes.
An unchanged map returns the original pin. A changed map appends when the base
is the current head, or explicitly forks from the selected base when a newer
head exists. The newer version and all existing history remain retained; the
new version becomes the native head. This is not a pre-read followed by an
unchecked latest-head append.

The version ledger records the owner's upload or label action as `UserUpload`;
its `Auto` status does not confirm the generated transcript's facts. Original
inference receipts remain in the immutable artifact. Storage does not import
observations or spend a bulk-consent receipt. Import still requires consent for
the selected exact artifact bytes and uses Imported/Proposed admission and the
existing Gate. Speaker labels grant no PERSON, biometric, or send authority.

These doors use ordinary blob version, ASSET, high-water, erase, hold and archive
machinery. They add no separate lifetime system or global-erasure guarantee.
Typed SESSION projection, revision-to-SESSION links, served owner routes and host
receipt retention remain separate work. No text-flattening adapter or duplicate
SESSION lifecycle is installed, and no voiceprint consent is implied.

## Typed SESSION input and selected-artifact reads

`Vault::read_meeting_transcript_as_owner` retrieves the exact selected stored
artifact under a current native owner proof. One read transaction checks the
transcript and audio versions, hashes, ledger relationship and actual audio
bytes. The returned artifact still needs its own fresh, exact-byte bulk import
consent; reading or labeling it grants neither import nor factual approval.

`ProducedMeetingTranscript::session_input` projects its validated structured
turns into the native `ParsedTranscript` shape. It keeps source turn ids in the
same order, the recording's source thread id and the normalized NOTE fallback.
Capture time is in seconds. Absolute turn claims use checked capture time times
1,000 plus the exact start/end millisecond offsets. Without capture time those
absolute claims stay absent. Source labels remain strings, never PERSON ids or
TURN roles. This method does not run the FileDrop line parser, mint/close a
SESSION, or queue either extraction path. The connected meeting SESSION caller
still needs the native import-source and review propagation in both MESO and
CHAT before activation; ordinary FileDrop behavior is unchanged.

### CHAT source provenance

The native CHAT writer now reads the actual cited SESSION/TURN evidence in the
committing writer before native head lookup. Imported evidence yields an inert
Imported/Proposed candidate with its full evidence and birth. It neither returns
nor supersedes a native active head. Task/amendment writes and ordinary native
CHAT claims keep their existing path.

The CHAT brief carries each TURN's actual import-source and source speaker
label separately from speaker identity. Only the new meeting-transcript source
has unknown speaker identity in this brief: its stored `user` role remains a
MESO admissibility role, not proof that the storage owner spoke. Existing
FileDrop, live chat and history speaker resolution stay unchanged. The host
keeps the source fields beside the original speaker/text values; it does not
turn a source label, raw hex string or SESSION owner into a verified speaker.
This is not activation of the meeting SESSION caller or a new approval door.
