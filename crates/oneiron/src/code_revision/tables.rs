//! The side tables `code_revision` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The checked Baseline a tested queue revision's parent chain ends at (value = id16),
    /// written when its seal is finalized, so a read finds the root by key, never by walking
    /// the chain (FIX 7390, 7391). Key: id16.
    CODE_REVISION_QUEUE_ROOT: VaultMeta b"code_revision:queue_root:v1:" Raw
        // Payload family: A tested queue revision's kept chain root: two ids, no payload (FIX 7390,
        // 7391).
        [restore: content] [family: structure] [tier: canonical];
}
