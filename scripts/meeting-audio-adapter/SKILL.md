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
the OF-133 ASR route and runtime access. A decoded mp4 is **not** itself proof
that ASR, alignment, community-1 or cleanup ran.

## Host policy (supply at run time)

An agent asked in chat writes a versioned **glossary JSON array** and a versioned
**cleanup instruction file** in the host's admitted adapter-skill workspace.
Keep names and domain terms in the glossary, not previous transcript windows.
Use the same immutable glossary on *each* pack. The cleanup instruction file
must have exactly one `{{TRANSCRIPT_JSON}}` placeholder. It asks for one JSON
`{"texts":[...]}` array, one nonblank correction per turn, with punctuation
and ASR-only fixes; no invented words, changed speaker IDs or facts. The
engine's lexical validator enforces this narrower behavior even if the prompt
asks for more. The host pins exact prompt bytes and hash in its runtime profile
(`scripts/meeting-audio-runtime.md`); no fixed product prompt lives in Rust.

The resident agent also chooses policy for E1/E3 experiments and the
speaker-enrollment match threshold τ. It must not call a fixture result
"measured", infer biometric consent from import approval, or silently pick a
batch default. Keep a policy revision and approval reference outside the
recording and outside engine code. E1 needs consented real JP/EN/UK meetings,
Qwen3-ASR and Soniox async on the same corpus, language-specific WER and
proper-noun/timing review. UK Qwen support is currently refused; record that
as an unsupported arm, not a fabricated score. A measured selection receipt
still needs a separate authenticated OF-133 ASR-role selection act. If Soniox
wins, use a Soniox-capable host; this local Qwen bridge refuses it.

## Setup and run

Provision an *existing* native Python interpreter, ffmpeg, immutable local
snapshots (Qwen ASR, acoustic word aligner, community-1 and cleanup model),
licenses/access records, exact hashes and a private workspace. The runtime
profile format and its helper/worker pins are in
`scripts/meeting-audio-runtime.md`. Do not install packages, fetch weights,
run `uv` inline launchers, or substitute word times from chunk boundaries.
The native adapter preflights every required port and refuses absent ones.
The supplied `route_receipt_ref` is an opaque host-supplied OF-133 reference;
this diagnostic CLI cannot authenticate or create a selection act.

Write a *private*, host-owned JSON config with absolute paths (not a checked-in
secret). For example, replace **every** placeholder:

```json
{
  "python": "/absolute/existing/bin/python",
  "bridge": "/absolute/oneiron/scripts/meeting-audio-native.py",
  "ffmpeg": "/absolute/bin/ffmpeg",
  "workspace": "/absolute/private/workspace",
  "model_snapshot": "/absolute/pinned/qwen-snapshot",
  "runtime_profile": "/absolute/private/profile.json",
  "runtime_profile_sha256": "64-lowercase-hex-of-exact-profile",
  "audio": "/absolute/private/meeting.mp4",
  "output": "/absolute/private/new-meeting-transcript.json",
  "language_hint": "English",
  "capture_started_at": null,
  "glossary": "/absolute/private/glossary-v1.json",
  "route_receipt_ref": "authenticated-host-route-reference",
  "measured_e1": null
}
```

Run from the repository root, with an owned target and a timeout:

```sh
cargo run -p oneiron --example meeting_audio_import -- /absolute/private/adapter-config.json
```

`measured_e1` may instead be `{ "cohort": "/absolute/cohort.json",
"selection": "/absolute/e1-selection.json", "evidence_ref": "host-evidence-ref" }`.
The CLI checks that both receipts bind the same cohort and Qwen won over a
Soniox async arm. It **does not** validate consent, score actual model output,
or authenticate the OF-133 act. The host must do that separately. No E1 claim
is made when `measured_e1` is null (the default is provisional).

The CLI fails closed on invalid profile/model/route or missing port. It writes
one new file only after `ProducedMeetingTranscript` has passed the real ingest
normalizer and its registry/skill parity check. It refuses to overwrite a
previous artifact; retain the source recording and immutable JSON together.
Import is a **separate** host action: an authenticated owner-facing host calls
`ProducedMeetingTranscript::authorize_import` with its `BulkImportAuthorizer`
for that exact artifact hash, vault and all turn IDs. Pending or denied consent
cannot ingest. Normalized evidence enters `ClaimSource::Imported` /
`ClaimApprovalStatus::Proposed`; import is no authority to auto-approve claims
or enroll voices. The consumer's SESSION-first / NOTE-fallback mapping remains
the existing [CAL-08] seam, not a new parser in this skill.

## Verification and remaining qualification

- Run `cargo test -p oneiron --example meeting_audio_import` and the ingest
  featureless/all-features test tiers. `scripts/codemap/check.sh` pins the map.
- A native mp4 import proof must retain the exact media hash, output artifact,
  normalizer result, host-profile hashes, invocation receipts and bulk-import
  approval receipt. A fixture-only run may prove plumbing, never model quality.
- E1 requires consented cohort and both actual arms. No such E1 default is
  bundled here. See `scripts/meeting-audio-runtime.md` for the current native
  port gaps and the separate E3 arm; no threshold τ is baked into this adapter.
