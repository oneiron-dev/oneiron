//! The side tables `affect` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Blake3 digest stamp of the last claim body that produced a subject's composite state-index
    /// claim, used to detect out-of-band claim edits. Key: id16.
    AFFECT_STATE_COMPOSITE_PRODUCER: VaultMeta b"state:composite:producer:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
