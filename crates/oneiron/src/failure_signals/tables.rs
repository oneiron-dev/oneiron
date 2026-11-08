//! The side tables `failure_signals` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One sealed FIX6 code-fix export (an invented example or a candidate fix's result) waiting
    /// for the host to drain it, with the worlds it touched; never real chat text. Key: id16.
    FAILURE_SIGNALS_CODE_FIX: VaultMeta b"failure_signals:code_fix:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The one failure-signal batch this vault's delivery staged before its send, or the owner
    /// holds (FIX 6679): its exact body, endpoint, batch id and digest, the count quantities and
    /// code-fix records it froze with their worlds, and where it stands. Custody only, never
    /// approval authority. Key: ().
    FAILURE_SIGNALS_HELD_BATCH: VaultMeta b"failure_signals:held_batch:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::failure_signals::erase_held_batch_actor_in_txn;
    /// A diagnostic already counted into the tier-1 failure aggregate, and when it observed; a
    /// later capture of the same diagnostic counts nothing (OF-380). Key: id16 (diagnostic id).
    FAILURE_SIGNALS_TIER1_COUNTED: VaultMeta b"failure_signals:tier1_counted:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One tier-1 failure count not yet delivered to the publisher, kept across restarts: the
    /// count (u64be), then its content-free dimensions as JSON. Key: bytes32 (blake3 of that
    /// JSON).
    FAILURE_SIGNALS_TIER1_COUNTS: VaultMeta b"failure_signals:tier1_counts:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
