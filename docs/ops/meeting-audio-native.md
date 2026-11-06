# Native meeting-audio model bindings

The core meeting-audio producer can use `CommandMeetingAudioHost` to drive an
operator-provisioned, offline Python runtime. It does not install packages,
download models, or import recording bytes into a vault by itself. There is not
yet a server configuration section or production ingest command that builds
this host and its admission seats. The host API still needs an authenticated
OF-133 ASR route receipt; a model name or evidence reference is not that receipt.

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
cleanup does not remove it. This is in-memory artifact retention, not vault
persistence, a SESSION revision history, or an erase-lifetime implementation.

`ProducedMeetingTranscript::with_speaker_labels` returns a separate artifact.
Its map keys are the existing anonymous speaker clusters. Its values are explicit
source labels, not authenticated PERSON identities or biometric enrollment.
Only matching clusters change; unmentioned clusters and existing labels remain.
A map that changes nothing returns the original artifact bytes. The original
artifact is never mutated. A changed artifact must obtain import consent for its
own exact bytes through the existing `authorize_import` method. Imported/Proposed
admission and all downstream Gate checks remain unchanged.

The authenticated owner speaker-resolution door, durable raw/corrected versions,
and their SESSION links are still separate, unimplemented work. This API does
not stand in for those doors or for voiceprint consent.
