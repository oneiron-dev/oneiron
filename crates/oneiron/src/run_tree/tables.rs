//! The side tables `run_tree` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Durable wait binding for a run-branch ask. Key: attempt id16 + handle hash32 + step hash32.
    RUN_TREE_ASK_WAIT: VaultMeta b"run.ask.wait.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
