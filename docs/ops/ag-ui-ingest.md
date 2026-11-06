# AG-UI event-dump ingest

The opt-in registry source `ag-ui` normalizes newline-delimited AG-UI event
objects. It is a file-framing choice for an event dump, not an SSE client or a
live capture connector. It does not start itself or select a vault from app data.

## Native entry points

`INGEST_SOURCE_REGISTRY.normalize` with source ID `ag-ui` returns the ordinary
`NormalizedIngestBatch`. The registered format is `IngestSourceFormat::AgUi`.
`AgUiSource::decode` exposes each event's parsed JSON, original event line,
input line number, import record ID, and an optional in-batch `repeat_of` ordinal.
`AgUiDecodedEvent::links` projects direct protocol IDs from recognized event types.
These types are exported from `oneiron::ingest`.

The protocol vocabulary and ID carriers follow `ag-ui-protocol/ag-ui` commit
`08eae9dc13546e91272efb2d0ef863e21acc6ee3`, `spec/1.0/schema.json`.
This is an evidence decoder, not a complete schema, event-order, JSON Patch,
argument, or chunk-reassembly validator. Missing or non-string `type` values
stay opaque, as do unknown types, `RAW`, and unregistered `CUSTOM` payloads.
Opaque events project no links. All their fields remain available as evidence;
none is interpreted as an instruction.

## What normalization preserves

- Every nonblank event line becomes a record, in order. The event line retains
  its whitespace and JSON spelling, but not the line terminator. Invalid JSON
  or a non-object line returns the existing line-numbered ingest error.
- The record ID is `agui:<full blake3 digest of input bytes>:<zero-based event
  ordinal>`. This is import bookkeeping, not a protocol identity or a join key.
- `repeat_of` names the first event ordinal with identical line bytes in this
  input. Every occurrence remains present. A repeated value alone does not prove
  duplicate delivery, a gap, a reconnect, or a repair. Cross-input completeness
  and deduplication are not implemented here.
- Only a directly recorded `threadId` on `RUN_STARTED` or `RUN_FINISHED` supplies
  a normalized thread. Other events do not inherit thread or run IDs from stream
  position. Message, tool, parent, and subagent links remain direct ID fields.
- Timestamp values remain in the event JSON. The schema does not normatively
  define their unit, so normalization leaves `occurred_at` unset. App roles stay
  in the payload; no role is assigned as an engine actor or principal.
- `RUN_FINISHED` is not classified as success. No success label, repair triple,
  or training/off-device consent is inferred from completion or candidate text.

The batch is records-only: claims and entities are empty, with no fallback note.
Its registry policy matches existing imported sources: imported trust and
proposed admission. Normalization does not write rows or grant authority.
Consumers must still use ordinary authenticated import/admission, entity
resolution, source-trust, secret, and write gates. Those doors can refuse data;
this source does not bypass them or promise byte-preserving persistence.

## Owner-selected file capture and scoped observations

`vault.ingest.ag_ui.import` is an explicit owner door. It captures an app ID,
a live project, the complete JSONL bytes, and the app's CUSTOM mappings in one
fresh `ingest.ag_ui.file` CLAIM. The authenticated owner is the real capture
actor and principal; no event field selects either. The owner proof and project
are checked in the same actor-content writer as the Imported/Proposed claim.
Normal secret masking still runs. The import rechecks the finalized capture in
that same writer and aborts if admission changed any captured bytes or context;
it never bypasses masking or returns an original fingerprint for changed data.
This is file import, not a live connector or an agent-principal setup API.

Each CUSTOM mapping names the exact event `name`, its reported kind (`action`,
`failure`, `repair`, or `outcome`), and JSON pointers into the whole event for
its ID, thread, run, tool, failure/repair references, and observed outcome.
For example, `/value/runId` is an explicit app mapping, not an AG-UI standard
field. Missing or non-string IDs stay missing. Unregistered CUSTOM events,
RAW, unknown events, whitespace and line terminators remain in the captured
JSONL. The original registry normalizer and generic imported-claim doors are
unchanged. Capture does not approve the observations or permit training or
sending data off-device.

The import receipt returns the claim ID and a full BLAKE3 fingerprint over the
captured bytes and context. `vault.ingest.ag_ui.read` requires both. It reads
through the caller's normal scoped, receipted lane, including its credential,
destination and room ceiling. A missing or withheld claim exposes no source
metadata. A changed capture fails the exact fingerprint check; the reader does
not substitute a current file, another claim or an older fingerprint. The
underlying CLAIM retains its ordinary lifecycle, history and erasure rules.
This is a content pin, not a new immutable blob-version store.

The typed reader also proves, in its same read snapshot, that the authenticated
capture author is a live vault owner. A Human actor alone, or a generic imported
claim shaped like a capture, does not attest an owner-registered mapping. Generic
imports remain available without gaining that typed-source status.

The typed reader returns the original JSONL and the registered app observations.
Each reported outcome's repair link names occurrence ordinals only when the
repair explicitly names a failure and the outcome explicitly names that repair.
Thread and run must be present and equal; tool IDs must also match, including
absence. Repeated matching target IDs stay ambiguous, even for byte-identical
occurrences. Missing references, cross-namespace targets and missing outcome
values are reported separately. A linked result is sourced app evidence, not a
success verdict, a checked Oneiron action or a complete training/eval task.

## Remaining feature work

This is a partial delivery of OF-582 / FIX3720. Live connector setup and
transport, choosing a non-owner principal, links across separately captured
files, and completeness tracking across reconnects remain open. OF-578's
Repair nomination, world/initial-state/intent/tools/grader, family split,
reuse, digest and cut-audit consumer are separate. Existing typed Repair case
storage is unchanged. The file path adds no table, family ledger, migration,
old-format reader, default cap or timer.
