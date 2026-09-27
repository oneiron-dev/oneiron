---
name: meeting-audio-import
version: 1
source_id: meeting-transcript
adapter_skill: builtin.ingest.meeting-transcript
schema: oneiron.meeting_transcript.v1
---

# Meeting audio → imported transcript

This is the host-side ARCH-0027 adapter-skill for ARCH-0061 §3 R4 / [VOX-00].
It packages the existing `MeetingTranscriptSource` and `produce_meeting_transcript`;
it does not reimplement the engine pipeline. The runnable entry point is
`crates/oneiron/examples/meeting_audio_import.rs`. A host runs this once per
file after it has resolved capture permission, the audio-processing setting,
the OF-133 role routes and runtime access. A decoded mp4 is **not** itself proof
that ASR, alignment, diarization or cleanup ran.

## Host policy (supply at run time)

An agent asked in chat writes a versioned **glossary JSON array** and a versioned
**cleanup instruction file** in the host's admitted adapter-skill workspace.
Keep names and domain terms in the glossary, not previous transcript windows.
Use the same immutable glossary on *each* pack. The cleanup instruction file
must have exactly one `{{TRANSCRIPT_JSON}}` placeholder. It asks for one JSON
`{"texts":[...]}` array, one nonblank correction per turn, with punctuation
and ASR-only fixes; no invented words, changed speaker IDs or facts. The
engine permits a one-for-one word correction only when the ASR port supplies
an acoustic candidate from the hash-bound speech pack **and** a permitted
source/target spelling pair in the selected language's cleanup policy. The
policy also names protected polarity tokens and suffixes (including
contractions and negative forms); either side of a protected pair refuses.
An unknown language or unlisted pair refuses lexical edits, while cosmetic
punctuation remains available. Raw words, clocks and speaker IDs remain
unchanged. The host pins exact prompt bytes and hash in its runtime profile
(`scripts/meeting-audio-runtime.md`); no fixed product prompt lives in Rust.

The resident agent also chooses policy for E1/E3 experiments and the
speaker-enrollment match threshold τ. It must not call a fixture result
"measured", infer biometric consent from import approval, or silently pick a
batch default. Keep a policy revision and approval reference outside the
recording and outside engine code. The E1 bake-off and winner choice are a
**separate owner ticket**, not an adapter precondition. When a measured receipt
is supplied, it needs a consented cohort, two or more actual arms, a winner
in those arms, and a separate authenticated OF-133 role-selection act. The host resolves the role's route by description, not a named model or
locality tier; the ids below are the resulting selections, not routing policy.

## Setup and run

Provision an *existing* native Python interpreter, ffmpeg, immutable local
snapshots for the routed ASR, acoustic aligner, diarizer and cleanup models,
licenses/access records, exact hashes and a private workspace. The runtime
profile format and its helper/worker pins are in
`scripts/meeting-audio-runtime.md`. Do not install packages, fetch weights,
run `uv` inline launchers, or substitute word times from chunk boundaries.
The native adapter preflights every required port and refuses absent ones.
Each role carries a host-supplied OF-133 `route_receipt_ref`, model id and
model revision. The example cannot authenticate or create a selection act.
Its native host is one implementation, not the router: it checks each selected
id/revision against the pinned runtime profile (including worker profiles).
Here `model_revision` is the last path component of the native model snapshot.
A remote selection stops before inference and needs a different
`MeetingAudioHost` implementation; the native bridge cannot pretend to run it.

Write a *private*, host-owned JSON config with absolute paths (not a checked-in
secret). For example, replace **every** placeholder:

```json
{
  "python": "/absolute/existing/bin/python",
  "bridge": "/absolute/oneiron/scripts/meeting-audio-native.py",
  "ffmpeg": "/absolute/bin/ffmpeg",
  "workspace": "/absolute/private/workspace",
  "model_snapshot": "/absolute/pinned/asr-snapshot-revision",
  "runtime_profile": "/absolute/private/profile.json",
  "runtime_profile_sha256": "64-lowercase-hex-of-exact-profile",
  "audio": "/absolute/private/meeting.mp4",
  "output": "/absolute/private/new-meeting-transcript.json",
  "language_hint": "English",
  "capture_started_at": null,
  "glossary": "/absolute/private/glossary-v1.json",
  "policy_manifest": null,
  "routes": {
    "asr": {"model_id": "host-selected-asr", "model_revision": "asr-snapshot-revision", "route_receipt_ref": "host-asr-selection", "execution": "native"},
    "aligner": {"model_id": "host-selected-aligner", "model_revision": "aligner-snapshot-revision", "route_receipt_ref": "host-alignment-selection", "execution": "native"},
    "diarization": {"model_id": "host-selected-diarizer", "model_revision": "diarizer-snapshot-revision", "route_receipt_ref": "host-diarization-selection", "execution": "native"},
    "cleanup": {"model_id": "host-selected-cleanup", "model_revision": "cleanup-snapshot-revision", "route_receipt_ref": "host-cleanup-selection", "execution": "native"}
  },
  "measured_e1": null
}
```

`policy_manifest` can point to a host-owned JSON object with `vault`,
`holder` and optional `precedence` rows. The shipped precedence is
`{"layers":["shipped","vault","holder"],"mode":"nested_narrowing","holder_cap":"vault"}`.
The host may select `{"layers":["shipped","vault"],...}` to disable holder
participation; a supplied holder row then refuses. The resolver evaluates the
selected layers in order. Each override may set `glossary_max_bytes`,
`glossary_max_terms`, `glossary_max_term_bytes`, `stage_timeout_seconds`, or a
complete `cleanup` object with `max_candidates_per_word`,
`max_candidate_bytes` and `language_rules`. A language rule has
`protected_tokens`, `protected_suffixes`, and `allowed_pairs` of `{from,to}`.
The vault may adjust shipped defaults within protocol ceilings. A holder may
only lower bounds, remove permitted pairs/languages, or add protections;
widening a vault right refuses. Absent rows inherit
`scripts/meeting-audio-adapter/policy-defaults.json`. The agent writes
language-specific correction policy and glossary, not Rust constants.

Run from the repository root, with an owned target and a timeout:

```sh
cargo run -p oneiron --example meeting_audio_import -- /absolute/private/adapter-config.json
```

`measured_e1` may instead be `{ "cohort": "/absolute/cohort.json",
"selection": "/absolute/e1-selection.json", "evidence_ref": "host-evidence-ref" }`.
The CLI checks the cohort binding, at least two arms, and that the routed ASR
model id and revision are the winner named by the selection receipt. It **does not** validate consent, score actual model output,
or authenticate the OF-133 act. The host must do that separately. No E1 claim
is made when `measured_e1` is null (the routed model remains provisional).

The CLI fails closed on invalid profile/model/route or missing port. It writes
one new file only after `ProducedMeetingTranscript` has passed the real ingest
normalizer and its registry/skill parity check. It refuses to overwrite a
previous artifact; retain the source recording and immutable JSON together.
Import is a **separate** host action: an authenticated owner-facing host calls
`ProducedMeetingTranscript::from_json` on the exact saved bytes, then
`authorize_import` with its `BulkImportAuthorizer` for that exact artifact hash, vault and all turn IDs. Pending or denied consent
cannot ingest. Normalized evidence enters `ClaimSource::Imported` /
`ClaimApprovalStatus::Proposed`; import is no authority to auto-approve claims
or enroll voices. The consumer's SESSION-first / NOTE-fallback mapping remains
the existing [CAL-08] seam, not a new parser in this skill.

## Verification and remaining qualification

- Run `cargo test -p oneiron --example meeting_audio_import` and the ingest
  featureless/all-features test tiers. `scripts/codemap/check.sh` pins the map.
- The shipped public MP4 fixture test uses hash-bound retained decoded PCM and
  fixture-only model ports to prove the complete adapter path without a model.
  Its execution marker is `fixture`, never an E1/E3 accuracy claim.
- A native mp4 import proof must retain the exact media hash, output artifact,
  normalizer result, host-profile hashes, invocation receipts and bulk-import
  approval receipt. A fixture-only run may prove plumbing, never model quality.
- E1 requires a consented cohort and at least two actual arms. Qualification
  and the model winner belong to the separate owner bake-off ticket. See
  `scripts/meeting-audio-runtime.md` for native port gaps and the separate
  E3 arm; no threshold τ or named model is baked into this adapter.
