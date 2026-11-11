//! The side tables `snapshot_read` keeps (core split slice 1): each row declares one, and the
//! crate's build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One open snapshot handle of primitive A (slice 6.4b): its kinds, its read filter, when it
    /// opened and ends, and the rows it served. This node's working state: no image carries it,
    /// and an erased actor's handles go with it. Key: id16 (actor) + id16 (handle).
    SNAPSHOT_READ_HANDLE: VaultMeta b"snapshot_read:handle:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime]
        => crate::snapshot_read::erase_snapshot_handles_of_actor_in_txn;
}
