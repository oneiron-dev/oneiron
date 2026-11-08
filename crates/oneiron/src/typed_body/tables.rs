//! The side tables `typed_body` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Work on a typed body away from its head: opener, base frontier and state. Key: id16
    /// (entity) + id16 (fork).
    TYPED_BODY_FORK: VaultMeta b"typed_body:fork:v1:" Named
        [restore: content] [family: owner TypedBody] [tier: canonical]
        => crate::typed_body::erase_fork_actor_in_txn;
    /// An entity's typed body: its schema tag, birth and head frontiers and commit count. Key:
    /// id16 (entity).
    TYPED_BODY_HEAD: VaultMeta b"typed_body:head:v1:" Named
        [restore: content] [family: owner TypedBody] [tier: canonical];
    /// Who made one typed-body commit: its actor and MadeBy, or its time alone once that actor
    /// was erased; the commit's message names no one. Key: id16 (entity) + u64be (commit peer).
    TYPED_BODY_RECEIPT: VaultMeta b"typed_body:receipt:v1:" Named
        [restore: content] [family: owner TypedBody] [tier: canonical]
        => crate::typed_body::erase_receipt_actor_in_txn;
}
