# Migration Notes

## M0-1 / ONE-1078: EdgeKind discriminant order

`EdgeKind` u8 values now match the pinned ARCH-0034 `edgeKinds` order. This
changes the persisted edge-kind byte in `edges_out` and `edges_in` LMDB keys,
as well as EdgeRef/CRDT edge-key encodings.

Existing vaults written with the pre-M0-1 order must not be read as-is under
the new order. They need the schema-version migration planned for M0-4
(ONE-1081). This change intentionally adds no migration tooling; the engine is
pre-launch and no production vaults are expected.

## M0-2 / ONE-1079: Selective edge value layouts

Edge VALUE bytes are no longer a uniform 24-byte buffer. ARCH-0034 now writes
edge values by layout class: structural edges are 12 B, semantic-bare edges are
24 B, and semantic-provenanced edges are 26 B. This is another edge ABI change
on top of M0-1. Existing vaults must fail closed under the open-time gate
planned for M0-4 (ONE-1081); no migration tooling is added here.

## M0-3 / ONE-1080: Entity type-byte registry

Entity type bytes now match the pinned ARCH-0002 registry. Productivity
records move from `TASK_LIST=60`, `TASK=61`, `MACHINE=62` to
`TASK_LIST=80`, `TASK=81`, `MACHINE=82`, and the core band adds
`ASSET=15` and `NOTIFICATION=16`.

This changes persisted `type_index` keys and the type byte at offset 0 in the
25-byte entity value header. Existing vaults written with the old productivity
bytes must fail closed under the open-time gate planned for M0-4 (ONE-1081);
no migration tooling is added here.

## M0-4 / ONE-1081: Storage ABI version gate

`STORAGE_ABI_VERSION=1` is now written to `vault_meta` when a vault is created.
It covers the M0-1 EdgeKind discriminant order, the M0-2 12/24/26 B edge value
layouts, and the M0-3 entity type-byte registry.

`Vault::open` fails closed when the storage ABI marker is missing or differs
from the current build before any edge or entity bytes are decoded. Pre-M0
vaults are rejected under v1 behavior. A `schema_version` marker and migration
plan seam were added for future work, but this release intentionally ships no
migration runner.

## M0-6 / ONE-1083: ARCH-0038 deletion/redaction rows

`REDACTION_AUDIT` receipts are now stored as normal entity-envelope records in
`entities` with type byte `120` and MessagePack bodies containing only opaque
IDs, reason values, timestamps, and verification placeholders. They deliberately
have no short ID and must not contain erased names, content, predicates, or
payload bytes.

Hard-delete reasons also enqueue bounded historical-carrier sweep jobs in the
existing `sync_queue` DB using the reserved `h:{seq:8BE}` key family. The row
value is scope plus retry state (`attempt_count`, `next_attempt_at`,
`last_error_code`, `queued_at`, `deadline_at`), with `deadline_at` capped to
30 days from the delete request. This adds no new named LMDB database and is
covered by the existing M0-4 storage ABI gate.

## M1 / ONE-1093: Feature-independent 25-DB manifest

`STORAGE_ABI_VERSION=2` makes the on-disk named LMDB database set
feature-independent. Every vault now materializes all 25 ARCH-0019 manifest
databases, including `sync_state` and `sync_queue`, regardless of whether the
`sync` Cargo feature is enabled. The feature gates sync behavior only, not the
physical database set.

Pre-fix development vaults created by a non-sync build may have only 24 named
databases because `sync_state` was not created. Those vaults are rejected by
the storage ABI gate under v2. Oneiron is pre-launch, so no migration runner is
provided; recreate affected development vaults.

## M2-5 / ONE-1102: short_ids / short_ids_reverse direction swap + counter relocation

`STORAGE_ABI_VERSION=3`. The two short-id databases now match the pinned
ARCH-0019 manifest rows byte-for-byte:

* `short_ids` (row n3) is keyed `(short_id bytes ‖ content_hash u8)` with the
  16-byte entity id as the value.
* `short_ids_reverse` (row n4) is keyed by the 16-byte entity id with
  `(short_id bytes ‖ content_hash u8)` as the value.

Both directions were previously swapped, and the old short-id-keyed direction
carried no content hash. The content hash stays `xxh32(data, 0) % 256` (u8);
because it is now part of the forward KEY, content updates delete the stale
forward row and write a refreshed one (the short id itself remains stable).

Per-type short-id counters no longer live as `[type_byte, 0xFF x15]` sentinel
rows inside `short_ids`. They move to `vault_meta` under the documented key
scheme `b"sid_counter:" ‖ type_byte` (13 bytes) with the last issued counter
as a u64 LE value.

Vaults written under ABI v2 are rejected fail-closed at open with
`StorageAbiVersionChanged` before any short-id bytes are decoded. Oneiron is
pre-launch; per the M0-4 precedent no migration runner is provided — recreate
affected development vaults.

## OF-326 / ONE-1732: off-record branch store (storage ABI v15 → v16)

`STORAGE_ABI_VERSION` advances from **15** to **16**.

ARCH-0052 replaced the off-record mechanism: **off-record fence families
removed; off-record state session-ephemeral; older vaults rebuild.**

A session's content is written into that session's own in-memory overlay and
never into base, so nothing off-record is durable — no fence rows in
`vault_meta`, no session registry rows, no per-entity visibility state. ABI v11
had made off-record fence state a supported vault contract; v16 withdraws it.
This engine carries no code that reads those rows, which is why a v15 stamp
cannot be accepted: the gate has no honest way to interpret what such a vault
holds.

**There is no migration pass.** No fence decoder, no cleanup sweep, no
compatibility flag, and no accept-the-previous-stamp branch: `gate_storage_abi_value`
stays a strict-equality handshake, so a v15 vault and a v16 engine fail closed
in both directions before a usable `Vault` exists. **No production vaults
exist** — Oneiron is pre-launch, so there is no deployed vault population to
preserve. Recreate affected development vaults.

## ARCH-0058 / ONE-1754: byte-space v3 type-byte re-key (storage ABI v16 → v17)

`STORAGE_ABI_VERSION` advances from **16** to **17**.

This is a **persisted-byte** change, and the first one that ships a migration
rather than a rebuild. The owner-ratified BYTE-SPACE REDESIGN v3 relocates
every system/maintenance kind down into the 64–99 system zone and every
compiled-in product kind up into 100–125:

| kind | old byte | new byte |
|---|---|---|
| REDACTION_AUDIT | 120 | 64 |
| MODEL | 121 | 65 |
| AUTHORITY_LOG | 122 | 66 |
| POLICY_MANIFEST | 123 | 67 |
| FEDERATION_GRANT | 124 | 68 |
| CONNECTOR_KEY | 135 | 70 |
| PSYCH_PROFILE | 129 | 71 |
| ACCESS_GRANT | 128 | 73 |
| COMPANION_REGISTER | 64 | 78 |
| CHANNEL_IDENTITY | 131 | 79 |
| COUNTERPARTY_CONTACT | 132 | 80 |
| OUTBOUND_GRANT | 133 | 81 |
| PERSONA_SNAPSHOT_EXPORT | 134 | 82 |
| COMM_RECORD | 136 | 83 |
| SKILL_CONTENT_ANCHOR | 138 | 84 |
| TASK_LIST | 80 | 100 |
| TASK | 81 | 101 |
| MACHINE | 82 | 102 |
| CODE_ARTIFACT | 83 | 103 |
| CODE_SYMBOL | 84 | 104 |
| BLOB_ARTIFACT | 85 | 105 |
| NOTE | 86 | 106 |

`IDENTITY_TOPOLOGY_EVENT` (76) and `SECRET_CUSTODY` (77) already sat at their
canon bytes and do not move.

### Why this one migrates instead of rebuilding

The strict-equality gate would refuse every pre-1754 vault *before* the re-key
that makes it current could run, so "rebuild" would be the only reachable
outcome for a change whose entire purpose is to move bytes in place. The
panel-adjudicated carve-out is therefore ONE sanctioned branch, exactly one
stamp wide: a vault stamped at exactly **16** is opened, the re-key runs inside
the open-path write transaction, and **17** is stamped only after the per-kind
count and id-set assertions pass. Every other stamp still fails closed with
`StorageAbiVersionChanged`. A compile-time assert pins the branch to ABI 17, so
the next bump must delete it rather than inherit a stale predecessor door.

### What moves, and what deliberately does not

Only persisted TYPE-BYTE fields move: byte 0 of each `entities` envelope, the
leading byte of each `type_index` key, the `sid_counter:<byte>` keys, and any
structural-kind registry record whose own byte is in the map (its zone code is
re-derived from the destination, never carried). Entity ids are the `entities`
keys and encode no type byte, so those rows are patched in place — ids,
timestamps, hashes, MessagePack bodies, vectors and CRDT payloads are never
rewritten. Edge keys and values carry entity ids and edge data, never endpoint
type bytes, so `edges_out` / `edges_in` are untouched and their totals are
asserted unchanged across the pass.

### Atomicity

Sources and destinations OVERLAP on bytes 64 and 80–84 — COMPANION_REGISTER
vacates 64 into REDACTION_AUDIT's destination, and TASK_LIST/TASK/MACHINE/
CODE_ARTIFACT/CODE_SYMBOL vacate 80–84 into the incoming system kinds. The pass
therefore stages every source row in memory, deletes all source keys, and only
then writes destinations. A per-kind migration would clobber live rows halfway
through.

Any anomaly — a destination byte already holding rows this map does not vacate,
a duplicate source or destination, an envelope too short to carry a type byte,
an entity/type-index count or id-set mismatch, or a short-id-counter collision
— aborts the whole transaction. The old bytes and the **16** stamp both survive,
so a failed re-key leaves the vault openable by the predecessor engine.

### The structural-kind registry moves wholesale, not selectively

A pre-1754 vault could dynamically register a pack anywhere in the old
companion (64–79), productivity (80–99) or CRM (100–119) bands, so registry rows
outside the migration map are legitimate and common. Those rows cannot simply be
left alone: their record carried the six-band ordinal in byte 2, and v3 reads
that same byte off the eight-zone table, where old Productivity (3) reads as
CompiledProduct and old CRM (4) as EngineExperimental. Leaving such a row
untouched would not preserve it — it would silently redefine it, and the row
would then fail the loader's zone-consistency check.

So the record version advances to **2** alongside the table it describes, and
the re-key rewrites EVERY surviving registry row at the current version with its
zone re-derived from its byte. A version-1 record is readable only by the re-key
itself, which never interprets its byte 2.

The pass then runs the loader's own rules over the registry it is about to
commit. The runtime registry is otherwise built *after* the open transaction
commits, so a row the loader rejects would be rejected against a vault already
stamped at **17** — unopenable by this engine and by its predecessor alike.
Proving the migrated registry loads before stamping turns that dead end into an
ordinary abort with the old bytes and the old stamp intact.
