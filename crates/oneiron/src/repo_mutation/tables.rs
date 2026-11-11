//! The side tables `repo_mutation` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Pointer from one repo's (repo key hash, oplog seq) to the proposal id it is bound to. Key:
    /// hex64 ":" u64be.
    REPO_MUTATION_PROPOSAL_OP: VaultMeta b"repo_mutation:proposal_op:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Reviewed-stack batch state for one repo identity/batch pair. Key: string ":" string.
    REPO_MUTATION_REVIEWED_STACK: VaultMeta b"repo_mutation:reviewed_stack:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Monotonic oplog sequence counter for one repo, keyed by a hash of its canonical repo key. Key:
    /// hex64.
    REPO_MUTATION_SEQ: VaultMeta b"repo_mutation:seq:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Captured pre-action repo-tree snapshot, keyed by its fork hash. Key: hex64.
    REPO_MUTATION_SNAPSHOT: VaultMeta b"repo_mutation:snapshot:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
