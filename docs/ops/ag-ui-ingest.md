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

## Remaining feature work

This is a partial delivery of OF-582 / FIX3720. Authenticated owner/principal/
project-scoped connector setup, live transport, app-registered action/outcome
interpretation, durable linked failure/repair/outcome exposure, completeness
tracking across reconnects, and the typed persisted triple reader remain open.
OF-578's Repair nomination, reuse, digest, and cut-audit consumer is separate.
Existing structured claim admission and typed Repair case storage can be reused;
this source adds no predicate, table, family ledger, migration, or old reader.
