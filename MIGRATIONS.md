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
