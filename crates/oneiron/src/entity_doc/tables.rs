//! The side tables `entity_doc` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The history one derived record quotes of an entity document: the incarnation-qualified
    /// frontiers it cites, or the birth state when the entity had no document yet. Floors owner
    /// purges while the citer is live. Key: hex32 (entity) ":" hex32 (citer).
    ENTITY_DOC_CITATION_FLOOR: SyncState b"entity_doc:v1:citation_floor:" Named
        [restore: content] [family: owner EntityDoc] [tier: canonical];
    /// Durable identity/provenance/status of one open or settled document fork. Key: hex32.
    ENTITY_DOC_FORK: SyncState b"entity_doc:v1:fork:" Named
        [restore: content] [family: owner EntityDoc] [tier: canonical]
        => crate::entity_doc::erase_fork_actor_in_txn;
    /// Shallow Loro snapshot of a fork's diverged content at its opening base. Key: hex32.
    ENTITY_DOC_FORK_SNAPSHOT: SyncState b"entity_doc:v1:fork_snapshot:" Raw
        [restore: content] [family: owner EntityDoc] [tier: canonical];
    /// Immutable citation pin binding a quoted span to its exact causal frontier, keyed by entity
    /// then citation id. Key: hex32 ":" hex32.
    ENTITY_DOC_PIN: SyncState b"entity_doc:v1:pin:" Named
        [restore: content] [family: owner EntityDoc] [tier: canonical]
        => crate::entity_doc::erase_pin_actor_in_txn;
    /// Review bundle of every fork opened under one text-edit proposal. Key: hex32.
    ENTITY_DOC_PROPOSAL_BUNDLE: SyncState b"entity_doc:v1:proposal:" Named
        [restore: content] [family: owner EntityDoc] [tier: canonical]
        => crate::entity_doc::erase_proposal_actor_in_txn;
    /// Durable proof of one owner-authorized shallow history purge, keyed by entity then receipt id.
    /// Key: hex32 ":" hex32.
    ENTITY_DOC_PURGE_RECEIPT: SyncState b"entity_doc:v1:purge:" Named
        [restore: content] [family: owner EntityDoc] [tier: canonical]
        => crate::entity_doc::erase_purge_actor_in_txn;
    /// Durable settlement receipt (before/after causal frontier) for one fork's merge/switch/reject
    /// verdict, keyed by entity then receipt id. Key: hex32 ":" hex32.
    ENTITY_DOC_RECEIPT: SyncState b"entity_doc:v1:receipt:" Named
        [restore: content] [family: owner EntityDoc] [tier: canonical]
        => crate::entity_doc::erase_receipt_actor_in_txn;
    /// Marker: one row per head document a NOTE's text plane ever held (for erasure completeness).
    /// Key: id16 + id16.
    NOTE_HEAD_DOC: VaultMeta b"note_head_doc:v1:" Raw
        [restore: content] [family: owner Note] [tier: canonical];
}
