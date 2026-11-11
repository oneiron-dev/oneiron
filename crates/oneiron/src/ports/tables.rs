//! The side tables `ports` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Archived claim-less shell marker. Key: hex32.
    DELETION_ARCHIVE_MARKER: SyncState b"ac:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// The current row's applied-deletion fence: written with every soft erase and with a peer
    /// tombstone accepted but not yet applied; lifted only by a local recreation, never by a peer.
    /// Presence-only, empty value. Key: hex32 (entity id).
    DELETION_ROW_FENCE: SyncState b"df:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Local hard-delete marker. Key: hex32.
    DELETION_HARD_DELETE_MARKER: SyncState b"dt:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Local evidence that a soft delete was applied; outlives the `pt:` propagation intent so an
    /// out-of-order proposal cancellation never settles against a live entity. Presence-only,
    /// empty value. Key: hex32 (entity id).
    DELETION_IDENTITY_SOFT_DELETE_MARKER: SyncState b"it:deleted:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// The world-month window label a deleted world claim was addressed under, kept past its purge
    /// so every reader still finds its tombstone. Key: hex32 (entity id).
    DELETION_WINDOW_LABEL: SyncState b"m:dw:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Monotonic counter allocating the next u:e: sequence number for one entity's text document.
    /// Key: hex32 (entity id).
    SYNC_M_U_SEQ_E: SyncState b"m:u_seq:e:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// An entity document's shallow-since version vector (document family). Key: hex32 (NOTE head
    /// id).
    DOCUMENT_SHALLOW_SINCE: SyncState b"ssv:e:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Change-log record. Key: id16.
    PORTS_CHANGE: VaultMeta b"ports:change:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::ports::erase_change_log_actor_in_txn;
    /// Change-log by actor index. Key: id16 + u64be + id16.
    PORTS_CHANGE_BY_ACTOR: VaultMeta b"ports:change_actor:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Change-log by entity index. Key: id16 + u64be + id16.
    PORTS_CHANGE_BY_ENTITY: VaultMeta b"ports:change_entity:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    PORTS_CLAIM_ROW_FLOOR: VaultMeta b"ports:claim_row_floor:v1" Raw
        [restore: live] [family: structure] [tier: canonical];
    /// Derived entity dependency. Key: id16 + u64be + id16.
    PORTS_DEPENDENCY: VaultMeta b"ports:dependency:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Reverse dependency index. Key: id16 + id16 + u64be.
    PORTS_DEPENDENCY_REVERSE: VaultMeta b"ports:dependency_reverse:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// What is left of one source's dependent walk: door, walked count, the last row walked, the
    /// last row it covers, and the worlds its words sat in. Key: id16.
    PORTS_DEPENDENT_WALK: VaultMeta b"ports:dependent_walk:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The OF-520 check a source's dependent walk raised past its threshold, once. Key: id16.
    PORTS_DEPENDENT_WALK_CHECK: VaultMeta b"ports:dependent_walk_check:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Device-local dependent walk batch and check threshold. Key: ().
    PORTS_DEPENDENT_WALK_POLICY: VaultMeta b"ports:dependent_walk_policy:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// A dependency row its source's pending walk passes by: admitted after the mark, or withdrawn
    /// early before a put rewrote its dependent. Key: id16 + u64be + id16.
    PORTS_DEPENDENT_WALK_SETTLED: VaultMeta b"ports:dependent_walk_settled:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Stale derived entity marker. Key: id16.
    PORTS_STALE: VaultMeta b"ports:stale:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Deletion-intent tombstone. Key: id16.
    PORTS_TOMBSTONE: VaultMeta b"ports:tombstone:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Worlds a deletion withdrew an epoch summary for: unknown flag + id16s. Key: id16.
    PORTS_WITHDRAWN: VaultMeta b"ports:withdrawn:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
