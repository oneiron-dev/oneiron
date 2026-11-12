//! The side tables `check_in` keeps (ROLES-CHECKIN P2.2): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A pending check-in: an act that waits for a proof from the ladder, its asker, grant, act
    /// class, scope, effect digest, rungs and state. Stays on the node that opened it, as
    /// shared-act records do (Engine ruling P22-SHAPE Q1 = A). Key: id16 (the pending check-in).
    CHECK_IN_PENDING: VaultMeta b"check_in:pending:v1:" Named
        // Restore class: live, as the verb hook's stopped call is: a restore must not reopen an
        // ask a holder already answered, or settle one nobody answered.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::check_in::erase_pending_check_in_actor_in_txn;
    /// One transition of a pending check-in, as the receipt family reads it (`check_in`): opened,
    /// climbed, skipped, extended, answered, let go, held, proceeded with an undo, window passed
    /// or objection held, written in the transition's own transaction. Key: string (the receipt
    /// id, `check_in:` + 32 hex + `:` + six-digit sequence).
    CHECK_IN_RECEIPT: VaultMeta b"check_in:receipt:v1:" Named
        // Restore class: the attested record of who answered and when, like the hold override
        // receipts: not authority.
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::check_in::erase_check_in_receipt_actor_in_txn;
    /// Every check-in receipt by time, written with the receipt, so a query reads the newest
    /// first. Empty marker. Key: u64be (occurred_at) + string (receipt id).
    CHECK_IN_RECEIPT_BY_TIME: VaultMeta b"check_in:receipt_by_time:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
