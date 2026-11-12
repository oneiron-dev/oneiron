//! The side tables `derive` keeps (untangle 6.7a): each row declares one, and the crate's build
//! script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One derivation batch as it committed: its actor and run, its time and policy frontier, and
    /// each item's outcome with the rows it landed. Key: id16 (batch).
    DERIVE_BATCH: VaultMeta b"derive:batch:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each actor's batches in commit order. Key: id16 (actor) + u64be (commit time, Unix
    /// seconds) + id16 (batch).
    DERIVE_BATCH_BY_ACTOR: VaultMeta b"derive:batch_by_actor:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
