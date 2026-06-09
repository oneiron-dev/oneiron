# Migration Notes

## M0-1 / ONE-1078: EdgeKind discriminant order

`EdgeKind` u8 values now match the pinned ARCH-0034 `edgeKinds` order. This
changes the persisted edge-kind byte in `edges_out` and `edges_in` LMDB keys,
as well as EdgeRef/CRDT edge-key encodings.

Existing vaults written with the pre-M0-1 order must not be read as-is under
the new order. They need the schema-version migration planned for M0-4
(ONE-1081). This change intentionally adds no migration tooling; the engine is
pre-launch and no production vaults are expected.
