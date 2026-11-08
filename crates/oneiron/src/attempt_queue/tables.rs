//! The side tables `attempt_queue` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Attempts paused for an annotation hold, empty markers. Key: id16.
    ATTEMPT_ANNOTATION_HOLD: VaultMeta b"job:annotation_hold:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Attempt kind to attempt ids, empty markers. Key: u64be len + kind + id16.
    ATTEMPT_KIND_INDEX: VaultMeta b"job:kind_index:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A row's run-tree parent to the row, empty markers. Key: parent id16 + child id16.
    ATTEMPT_PARENT_CHILD_INDEX: VaultMeta b"job:parent_child:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Retried attempt to its retries, empty markers. Key: parent id16 + child id16.
    ATTEMPT_RETRY_CHILD_INDEX: VaultMeta b"job:retry_child:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Attempt task ref to attempt ids, empty markers. Key: u64be len + task ref + id16.
    ATTEMPT_TASK_INDEX: VaultMeta b"job:task_index:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
