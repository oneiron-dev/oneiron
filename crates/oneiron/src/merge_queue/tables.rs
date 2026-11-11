//! The side tables `merge_queue` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One merge batch's proposals, worktree paths, and lifecycle state. Key: hex(repo identity) ":"
    /// hex64(batch id).
    MERGE_QUEUE_BATCH: VaultMeta b"merge_queue:batch:v1:" Named Authored [accepts: crate::merge_queue::merge_queue_batch_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// One merge batch filed under a proposal, run work or run declaration it names, so a run's
    /// enqueue, stage and observe read its own batches by key (FIX 7067). Key: hex(repo
    /// identity) ":" kind ":" id ":" hex64(batch id).
    MERGE_QUEUE_BATCH_INDEX: VaultMeta b"merge_queue:batch_index:v1:" Named Engine
        // Restore class: Derived beside each batch, restored with it (FIX 7067).
        [restore: content] [family: unclassified] [tier: canonical];
    /// One object store's checked queue configuration: the approved baseline, the plan frozen
    /// from it and the owner's queued check approval (FIX 6868). Key: hex(repo identity).
    MERGE_QUEUE_CHECK_CONFIG: VaultMeta b"merge_queue:check_config:v1:" Named Authored [accepts: crate::merge_queue::merge_queue_check_config_accepts_masked]
        // Restore class: A restore never revives a revoked approval: the live one stands.
        [restore: live] [family: unclassified] [tier: canonical];
    /// One requested queue init, check or diagnosis: its attempt, generation, status and
    /// receipts (FIX 6868). Key: hex(repo identity) ":" hex64(request digest).
    MERGE_QUEUE_CHECK_WORK: VaultMeta b"merge_queue:check_work:v1:" Named Authored [accepts: crate::merge_queue::merge_queue_check_work_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// One checker receipt filed under its inputs digest and verdict, so a reused, bound or
    /// sealed receipt is read by key (FIX 7349). Key: hex(repo identity) ":" inputs digest ":"
    /// verdict ref (empty for none) ":" hex64(request digest).
    MERGE_QUEUE_RECEIPT_INDEX: VaultMeta b"merge_queue:receipt_index:v1:" Named Engine
        // Restore class: Derived beside each work row's receipts, restored with it (FIX 7349).
        [restore: content] [family: unclassified] [tier: canonical];
    /// The vault's one opt-in review policy for merge queue work; no row lands on green (FIX
    /// 8268). Key: (). FIX 8519: this entry's scrub takes an erased setter's id out of it.
    MERGE_QUEUE_REVIEW_POLICY: VaultMeta b"merge_queue:review_policy:v1" Named Authored [accepts: crate::merge_queue::merge_queue_review_policy_accepts_masked]
        // Restore class: A restore never revives a cleared review policy: the live one stands.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::merge_queue::erase_review_policy_actor_in_txn;
    /// Repo-scoped merge-queue pointers, workspace graph, and in-flight intent state. Key: hex(repo
    /// identity).
    MERGE_QUEUE_STATE: VaultMeta b"merge_queue:state:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
