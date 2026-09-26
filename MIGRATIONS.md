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

## Pre-GA ABI v4–v15 catch-up (ONE-1938)

**Ruling for each row: no-op.** Each row names the discarded predecessor
population. These were unshipped development vaults, wiped/recreated as debris;
no deployed vault exists to justify a legacy decoder or a migration. The
strict ABI gate rejects their stamps before the new shape is read. The one
exception to *rebuild-only* history is the later v16→v17 re-key below.

| Change | Persisted break | Discarded population |
|---|---|---|
| v3→v4 (ONE-299) | `text_postings` became DUP_SORT; `text_forward` dropped `tf` | ABI-3 development vaults with old text-index rows |
| v4→v5 (ONE-1293) | Maintenance kind bytes realigned for AUTHORITY_LOG, POLICY_MANIFEST, FEDERATION_GRANT | ABI-4 development vaults with old type-byte keys and envelopes |
| v5→v6 (ONE-1204) | PSYCH_PROFILE registered at byte 129 | ABI-5 development vaults without this persistent-kind contract |
| v6→v7 (ONE-1206) | Three attempt-queue named DBs added | ABI-6 development vaults with the old manifest |
| v7→v8 (ONE-1213) | Queue terminal states and retry metadata added | ABI-7 development vaults with old queue rows |
| v8→v9 (ONE-1530) | OUTBOUND_GRANT registered at byte 133 | ABI-8 development vaults without this persistent-kind contract |
| v9→v10 (ONE-1443) | AGENT_DEF registered at byte 17 | ABI-9 development vaults without this persistent-kind contract |
| v10→v11 (ONE-1576) | Off-record fence state became durable | ABI-10 development vaults without the fence contract |
| v11→v12 (receipt-family pin) | Receipt-family storage ABI advanced with versioned markers | ABI-11 development vaults with old receipt-family markers |
| v12→v13 (ONE-1387) | CLAIM body gained optional session `sess` | ABI-12 development vaults whose readers reject the new key |
| v13→v14 (ONE-1741) | SKILL_CONTENT_ANCHOR registered at byte 138 | ABI-13 development vaults without this persistent-kind contract |
| v14→v15 (ONE-1743) | IDENTITY_TOPOLOGY_EVENT registered at byte 76 | ABI-14 development vaults without this protected-kind contract |

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

## GA preflight / ONE-1938: pre-release in-place breaks (ABI v20 baseline)

This is the expiry register for the pre-release exception in `REVIEW.md`. Each
ruling names the affected population; none licenses a compatibility decoder for
an older vault. The current open gate accepts **only ABI 20** (and stamps a
new vault). The historical 16→17 and 17→18 re-keys are not current open paths.
These rulings cover the four Wave-4 findings and later unregistered ABI moves;
new in-place breaks before GA must be appended here before they ship.

### ONE-1645: promote-receipt initiator (v0 key and body)

**Ruling: no-op. Discarded population:** development vaults holding the old
`offrecord_promote:v0:` receipts with `initiator` instead of required
`initiator_ref` and `initiator_kind`. Wipe/recreate them as pre-release debris;
there are no deployed vaults to migrate. The old decoder would authenticate no
initiator and is not an acceptable GA fallback. The *later* ARCH-0052 / ONE-1732
replacement removed that receipt shape altogether: its current v0 receipt is a
session/turn/outcome retry receipt, still under the same prefix, but every vault
carrying the older shape is rejected at the ABI gate (v15→v16 and subsequent
bumps) before receipt decoding. Do not infer compatibility from the reused
prefix. No receipt-version or prefix bump for a shape that will not ship.

### ONE-1631: AUTHORITY_LOG content-derived store key

**Ruling: no-op. Discarded population:** development vaults with signed authority
rows keyed by caller-chosen ids (including the original type-122 rows). Wipe
and recreate; there are no deployed rows requiring the proposed S-AUTH1 §B6
sidecar-marked re-key. The current write and sync-admission doors derive the
store id from the canonical signed body hash and reject an id mismatch with
`AuthorityLogStoreKeyMismatch`. Re-reading a predecessor vault is not a recovery
path: the current strict ABI gate refuses it before rematerialization, and the
historical type-byte re-key must not be mistaken for an authority-id re-key.

### ONE-1637: ABI-15 gate-decision claim-index completeness flag

**Ruling: no-op. Discarded population:** development ABI-15 vaults opened by a
claim-index reader and subsequently written by a different ABI-15 binary
without the index writer. Such a writer could append decisions after the
empty-ledger completeness flag was set, making indexed claim lookup miss them.
No mixed ABI-15 binary/vault population ships: the off-record change bumped
ABI 15→16, and the current ABI is 20. A current reader refuses a v15 vault at
open; an old ABI-15 reader refuses a v20 vault. Current writes maintain the
index in the ledger transaction. No backfill or old-binary compatibility arm is
needed for the discarded dev vaults.

### ONE-1633: actor-binding first-seen observation fold

**Ruling: existing bounded migration within the current ABI, not a new legacy
vault decoder.** For a current-ABI authority row lacking a local first-seen
sidecar, the first write-path `authority_fold()` scans stored rows, writes only
missing sidecars at this vault's local observation time, and marks the one-shot
backfill complete in the same transaction. It never trusts peer-controlled
`learned_at`. A genuinely old pending widen serves a full delay after this
observation. A transaction-bound *read-only* authorization fold cannot mutate:
when a missing sidecar would decide a delayed widen it refuses owner verbs
until the write-path fold records the observation; a missing sidecar after the
backfill marker is corruption, not an excuse to reset the delay. New authority
writes create their own first-seen sidecar. **Discarded population at the ABI
boundary:** all predecessor-stamped development vaults; this in-version repair
does not make them openable by ABI 20. No additional open-time migration.

### ONE-1103: REDACTION_AUDIT temporal point index

**Ruling: no-op. Discarded population:** pre-ONE-1103 development vaults
holding REDACTION_AUDIT receipts without `temporal_occurred_start` point rows.
The version was intentionally not advanced; a time-range query over those old
receipts could miss them. Wipe/recreate those dev vaults rather than silently
claim that an index without a backfill is complete. Current receipts are
indexed as point events at write/rematerialization; there is no deployed
population needing a retroactive index pass.

### ONE-1122: local hard-delete `dt:` gate marker

**Ruling: no-op. Discarded population:** pre-ONE-1122 development vaults and
single-version dev peers that hard-deleted an entity before the permanent
`dt:{entity_id_hex}` local marker and observer-B replay gate existed. Older
engines ignored the additive marker family, and missing old markers cannot
prove a historical hard delete. Wipe/recreate that dev population rather than
pretend it has the new resurrection guard. Current hard-delete paths write the
marker in the purge transaction; read/replay gates use its presence. It is a
local sync-state safety addition, not a claim that old vaults can be repaired
by scanning their remaining bodies.

## Pre-GA ABI history not previously recorded here (v17→v20)

### OF-494: byte-space v3.1 family reflow (v17→v18)

**Ruling: historical one-version migration.** ABI 17 was accepted by the ABI 18
engine for a single atomic re-key of entity envelope bytes, type-index keys,
short-id counter keys, and structural-kind registry rows. This moved the
v3.1 family set without treating a changed type byte as a new entity. The v18
exception is gone in the current v20 engine; a v17 or v18 development vault
is now discarded/rebuilt, not migrated across intermediate releases. The
legacy migration is history, not a GA compatibility promise.

### Wave 7 stored meanings and facets (v18→v19)

**Ruling: no-op. Discarded population:** ABI-18 development vaults with older
SlipMint, esign reseal, conversation summary/room-thread, NOTE/ASSET facet,
head-pointer, and SESSION/ASSET/SUMMARY index meanings. Rebuild; no old-row
interpretation or backfill is offered. The v19 bump prevents same-stamp readers
from silently accepting the changed stored meanings. The v18 re-key path was
deleted before v19 shipped.

### Pairing and proof replay rows (v19→v20)

**Ruling: no-op. Discarded population:** ABI-19 development vaults with the
64-hex pairing ticket or count-bounded proof replay rows. Rebuild; v20 stores
an eight-character pairing code hashed with origin and intended holder, and
bounds proof replay by request-time window. A v19 vault fails closed at the
current ABI gate, so neither old row shape needs a decoder.
