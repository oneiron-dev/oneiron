//! The side tables `attempt_queue` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Attempts paused for an annotation hold, empty markers. Key: id16.
    ATTEMPT_ANNOTATION_HOLD: VaultMeta b"job:annotation_hold:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// What a workflow step try's retry chain has spent (units), kept for the retry that follows
    /// it, so a retry after a restart replays it exactly (ARCH-0053 #paid-leg-built). A retry
    /// moves its parent's row to itself as it reads it. Key: id16 (the try carrying the chain's
    /// spend: a failed try, or the retry that inherited it).
    ATTEMPT_CARRIED_SPEND: VaultMeta b"job:carried_spend:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// RUN-HOLD: an engine hold a generic Resume released on one attempt (the hold, the actor,
    /// the instant), so a later claim does not pause the row again. Key: id16.
    ATTEMPT_HOLD_OVERRIDE: VaultMeta b"job:hold_override:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::attempt_queue::erase_hold_override_actor_in_txn;
    /// One override of an engine hold, as the receipt family reads it (`RunHoldOverride`, Engine
    /// call S65-B-R3): the hold, the run, the actor and the time, written in the override's own
    /// transaction. Key: string (the receipt id, `run_hold_override:` + 32 hex + `:` + event
    /// sequence).
    ATTEMPT_HOLD_OVERRIDE_RECEIPT: VaultMeta b"job:hold_override_receipt:v1:" Named
        // Restore class: the attested record of who released a hold, like the task lifecycle
        // receipts: not authority.
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::attempt_queue::erase_hold_override_receipt_actor_in_txn;
    /// Every hold override receipt by time, written with the receipt, so a query reads the newest
    /// first. Empty marker. Key: u64be (occurred_at) + string (receipt id).
    ATTEMPT_HOLD_OVERRIDE_RECEIPT_BY_TIME: VaultMeta b"job:hold_override_receipt_by_time:v1:" Raw
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
