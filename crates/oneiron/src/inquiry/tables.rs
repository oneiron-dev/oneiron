//! The side tables `inquiry` keeps (INQUIRE-1): each row declares one, and the crate's build
//! script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// "Asked about you" (federation.md #inquiry-keep), on the member's vault: one inquiry a
    /// company sent over one inquiry edge, its current answer and who decided it. Key: id16 (the
    /// inquiry edge's grant) + id16 (the inquiry).
    INQUIRY_LOG: VaultMeta b"inquiry:log:v1:" Named
        // Restore class: live, as a pending check-in is: the row records answers that already
        // left the vault, and a restore must not reopen one.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::inquiry::erase_inquiry_log_actor_in_txn;
    /// Every log row by the time it was received, written with the row, so "Asked about you"
    /// reads the newest first. Empty marker. Key: u64be (received_at) + id16 (edge) + id16
    /// (inquiry).
    INQUIRY_LOG_BY_TIME: VaultMeta b"inquiry:log_by_time:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One send of an inquiry, on the asking vault, as the receipt family reads it (`inquiry`):
    /// the asker, the task, the question, the time and the outcome, never answer text. Key:
    /// string (the receipt id, `inquiry:` + 32 hex + `:` + six-digit send sequence).
    INQUIRY_RECEIPT: VaultMeta b"inquiry:receipt:v1:" Named
        // Restore class: the attested record of who asked what and when, like the check-in and
        // hold override receipts: not authority.
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::inquiry::erase_inquiry_receipt_actor_in_txn;
    /// Every inquiry receipt by time, written with the receipt, so a query reads the newest
    /// first. Empty marker. Key: u64be (occurred_at) + string (receipt id).
    INQUIRY_RECEIPT_BY_TIME: VaultMeta b"inquiry:receipt_by_time:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
