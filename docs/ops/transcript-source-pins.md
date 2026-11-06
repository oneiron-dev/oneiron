# Transcript source pins

Caller-bound transcript TURNs optionally retain the exact source version
they were built from. Each TURN body may carry:

- `source_blob_version`: the source `BlobArtifactVersion.version` (`u64`)
- `source_blob_content_hash`: the full hex of that version's 32-byte native
  blake3 `content_hash` (`blake3::Hash::from_bytes(content_hash).to_hex()`)

Both keys come from the SAME writer-verified `current` the caller-bound
door already matched to head and stored bytes in its write txn
(`current != head || stored != decoded` still refuses first). The door
passes `Some(&current)` to the shared landing only after that proof; the
landing threads it into `persist_turns`. No new head lookup, refusal,
default, or validation was added.

The direct host id/text path (`ingest_file_drop_transcript_inner`) passes
`None`: its TURNs keep the old fields unchanged and carry no pin. Missing
keys mean unknown, not a legacy reader and not a fallback pin.

Pending retries inherit a pin only through the same door proof at land;
`pending.rs` is unchanged. The pin is metadata: it is not auth, permission,
actor, a new provisional/corrected revision, or a whole-erase proof.

No public `TranscriptFileDropRequest`/`TranscriptFileDropInput` field, no
timing, SDK, generated-surface, default, migration, or compat change. Old
TURN fields and values are byte-identical; the two keys sit outside the
`speaker|spkr` alias set. Full FIX4235 stays PART: host-direct imports
remain unpinned and transcript revisions are unbuilt.

Open owner-overridable call `L10-W-S18-FIX4235-pin` records this key
spelling as a proposal, not canon law.
