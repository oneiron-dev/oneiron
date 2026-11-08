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
Storage alone does not import a SESSION or NOTE; the separate owner import
action below performs that step. No text-flattening adapter or duplicate
SESSION lifecycle is installed, and no voiceprint consent is implied.

### Owner HTTP storage and selected reads

The existing owner door authenticates each request before reading its JSON body.
All three actions are POSTs under `/v1/owner/meeting-transcripts`:

- `/persist` takes `source_audio`, `artifact_json` and `name`. Upload the source
  audio through the ordinary blob-artifact API first. `artifact_json` is the
  exact structured `oneiron.meeting_transcript.v1` JSON string. The native save
  checks the selected audio bytes and records their version claim in `made_by`.
- `/label` takes `stored` and `labels`, a speaker-cluster-to-source-label map.
  It returns the native unchanged, appended or forked selection; it does not
  relabel an unrelated newer revision or identify a PERSON.
- `/read` takes `stored` and returns `stored`, the exact `artifact_json` string,
  its `recording_id` and the complete `import_binding`. The native read validates
  both selected versions and their ledger relationship, not a caller-supplied
  association. The binding describes the artifact; reading it approves nothing.

`source_audio` is a pin with `artifact` (32 hex characters), `version` (u64)
and `content_hash` (64 hex characters of BLAKE3). `stored` contains both
`source_audio` and `transcript` pins. Hex inputs accept either case; returned
pins use lowercase hex. Persist and label return this same `stored` shape.
Pins are selections, never owner credentials or bulk import consent. Bodies
use the existing owner JSON spool and listener policy, with no new length cap.
These storage actions do not start ASR, import observations, answer hooks or
consume bulk consent. The separate import actions below use an explicit owner
approval of the complete binding.

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
SESSION, or queue either extraction path. The owner-bound import door below
connects those turns to the native lifecycle; ordinary FileDrop behavior is
unchanged.

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
These CHAT changes neither infer speaker identity nor add an approval door.


## Owner-bound SESSION import

`Vault::import_meeting_transcript_as_owner` reads the selected native artifact
under a live owner proof, then calls the existing bulk authorizer outside the
LMDB writer. Each invocation needs fresh consent for those exact bytes. In the
committing writer it revalidates the owner, both native version pins, the source
audio relationship and the artifact bytes before landing anything.

The door reuses the native mint/turn/close/wake path with the owner's actual
SESSION key and the native machine id. Arrival comes from that writer's clock;
source capture claims keep their exact projected millisecond offsets. It writes
`import_source = "meeting-transcript"` on both the CONVERSATION and its TURNs at
birth. Each TURN retains its native source record/thread ids and version/hash
pin. The CONVERSATION retains the complete bulk receipt and both selected native
pins once, rather than copying the whole batch into every TURN. These fields
record provenance, not a grant, ASR execution proof or factual confirmation.

The existing MESO evidence read derives Imported trust from the native stamp.
Its promotions remain Imported/Proposed and wait in the actual MESO run's pending
review group through the existing run-group fallback. No `HistorySource` variant,
history ledger entry, new review namespace or second consent ledger is added.
CHAT keeps the imported floor and unknown meeting speaker behavior above.

An already-open sitting returns the native `RetryOpenSession` result. The door
does not mint another SESSION or silently reuse this receipt for a later call.
The exact stored artifact and bulk receipt remain in the returned outcome.
The served import actions use the caller-bound continuation below, not this
hookless direct API. No host-only MACHINE take or owner-authored truth is
substituted for the actual caller.

## Native Imported NOTE fallback

The same owner-bound writer also lands the normalizer's whole-batch NOTE
fallback, including when turns land. An artifact with no turns can land that
NOTE without a synthetic SESSION. `note_fallback` reports the native NOTE id
and whether it landed now or was retained from an earlier import. It does not
claim an approve-once receipt from `notes.import.review`: the original fresh,
exact-byte bulk consent authorizes this import without a second prompt.

The fallback uses the shipped `observation` kind, selected by
`MEETING_TRANSCRIPT_NOTE_KIND`. Its namespace is the meeting source id plus the
selected transcript artifact id, version and importing owner. The normalized
source record id names the NOTE within that namespace. A retry does not
replace existing edits, and a deleted or archived NOTE is not resurrected;
the result reports its native Unchanged, Changed or Removed standing. A label
revision has a distinct native version and therefore a distinct NOTE identity.

The native notes importer writes the NOTE as its source MACHINE, not as the
owner's own prose. That MACHINE's registry-derived trust is Imported. Its birth
names the real importer. Its body retains both selected version pins and the
original bulk receipt once as source provenance. The NOTE uses its source artifact's
world and native title, secret-scan, document and authorship paths, with
DerivedFrom edges to the transcript and source-audio artifacts. Its valid time
uses capture time when present, otherwise the committing writer's arrival time.
No duplicate artifact-byte store, import ledger or new approval group is added.
The ordinary markdown and attached-folder importer paths keep their existing
source, identities, births, title and secret handling.

The SESSION and new NOTE commit together, or the native write error rolls back
both. A busy SESSION outcome can still accompany a landed or retained NOTE.
These SESSION and NOTE import doors remain library APIs beneath the served
adapter below. No physical ASR execution, end-to-end runtime result or
global-erasure guarantee is claimed here.

## Caller-bound prepared SESSION import

`Memory::prepare_meeting_transcript_import_as_owner` borrows the actual caller
and its separate `AuthenticatedOwner` proof. The handle must be that owner's
Human caller, as on the other native owner facade doors. Both selected native
versions are read through this handle before the existing bulk authorizer sees
the artifact. Owner proof alone does not substitute for its reader. The direct
`Vault::import_meeting_transcript_as_owner` API and ordinary FileDrop paths are
unchanged.

The returned `MeetingTranscriptImportAttempt` is an opaque in-memory object,
not a serialized credential or durable queue. The host retains it and calls
`resume`. One fresh exact-byte bulk consent covers that attempt and its hook
continuations. The native preparation writer selects its arrival time once;
its SESSION id, capture hints and arrival time remain stable across hook waits.
The original owner-only import still selects arrival in its landing writer.

A pending session-open hook returns `HookPending` with the actual ask and
prepared SESSION id, without landing a SESSION or NOTE. Resume the same object
after answering it. An unavailable saved invocation returns an error; it does
not start a fresh hook chain. Dropping the object abandons this in-memory
continuation. A new preparation needs fresh bulk consent. This API installs
no background retry, durable scheduling or served route.

Both pre-hook readers come from the borrowed `Memory`. Pre-hooks and a saved
ask's wait-status probe share that caller's currently held task-work turn;
sharing the turn does not replace the ask's saved author or its authority.
The committing audited writer revalidates its actor and reader, the live owner
proof, both selected
pins and sighted bytes, the source-audio relationship and the exact authorized
JSON. It calls the existing shared prepared mint/turn/close/wake path with the
meeting provenance and lands the native Imported NOTE in that same transaction.
An empty transcript can land its NOTE without hooks or a synthetic SESSION.
A busy SESSION result can still accompany a landed or retained NOTE.

Storage or map-full failures rearm consumed hook answers. A committed busy
result rearms both pre-hooks. Posts run only after commit with the actual native
`EndedSession`; no post runs for a rolled-back landing. Once committed, the
attempt is complete, including a busy SESSION result, and cannot be resumed to
mint another SESSION. This source API does not prove ASR execution, caller-route
activation, hook runtime behavior, privacy or global erasure.

## Served owner import and continuation

After reviewing `/read`'s artifact and full `import_binding`, the owner explicitly
POSTs `/v1/owner/meeting-transcripts/import` with `stored` and that `binding`.
The existing owner door authenticates the action before reading its body. This
is approval of the whole selected artifact, not a boolean inside a transcript,
voiceprint enrollment, a pin used as a grant or a second per-turn prompt.

The host authorizer supplies the actual vault-key id as its scope and allocates
a receipt reference from the vault's native id source. The native callback
independently derives the complete binding, including the exact artifact SHA-256
and every source record id, and requires full equality with what the owner
reviewed. A mismatched version, artifact or scope grants nothing. The existing
native owner, read-lane, source-audio, hash and committing-writer checks remain.
The receipt records the authenticated import act; this contract does not add a
separate receipt signature requirement or a persisted consent ledger.

`Vault::prepare_owned_meeting_transcript_import_as_owner` keeps the actual
`AuthorizedMeetingImport`, projected input, source pins, receipt, arrival, hint
and saved ask in one private execution state shared with the borrowed API.
Its opaque, nonserialized `OwnedMeetingTranscriptImportAttempt` keeps an
`Arc<Vault>` and the original retained reader and owner actor. Every resume
needs a current live proof of that same owner. It restores the original reader
and its live guards, never replacing it with the later request's wider reader.
Held room narrowing is kept even after a pending result or an error. Only the
current operation's task-work turn is shared; no turn is kept between requests.
This is the reader and author context this import consumes, not a full clone
of every request field on `Memory`.

`hook_pending` returns the native `session_ref` and `ask`. Answer the actual
hook ask, then POST `/v1/owner/meeting-transcripts/import/resume` with that
`session_ref`. The per-server runtime retains the same native attempt; resume
does not repeat bulk consent or mint a fresh hook identity. `imported` returns
the native SESSION result, NOTE result, selected pins and original bulk receipt.
An empty-turn NOTE completes without a synthetic SESSION or map entry. A
committed busy-session result is complete, as on the borrowed API.

POST `/v1/owner/meeting-transcripts/import/discard` with `session_ref` to forget
a retained continuation. It does not undo committed work, revoke an ask or
cancel a resume already running. The runtime is per server, not global; dropping
the server drops its pending objects. There is no background worker, durable
retry, new timer or new numeric cap. These are served source paths, not proof
of a successful runtime import, physical ASR, privacy or global erasure.
