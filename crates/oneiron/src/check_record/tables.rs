//! The side tables `check_record` keeps: the native check records, one row a
//! check, and the two reuse indexes beside them.

crate::side_table::side_tables! {
    /// One native check a run recorded in its own checkout (ARCH-0068 RC5), minted by the engine. Key: AttemptId, then id16 (the check).
    ATTEMPT_CHECK_RECORD: VaultMeta b"attempt_check:record:v1:" Named Engine
        // Restore class: an attempt's own records come back with its image.
        [restore: content] [family: unclassified] [tier: canonical];
    /// One reusable native check (passed, stable, not world, on a pinned tree) filed under its reuse key, so a receiver finds it by one prefix read. Key: the 32-byte reuse key, then AttemptId, then id16 (the check).
    ATTEMPT_CHECK_BY_INPUTS: VaultMeta b"attempt_check:by_inputs:v1:" Named Engine
        // Restore class: Derived beside each record, restored with it.
        [restore: content] [family: unclassified] [tier: canonical];
    /// One reused native check filed under the checkout it was reused on, so the checkout's publication checks it again. Key: CheckoutId, then AttemptId, then id16 (the check).
    ATTEMPT_CHECK_REUSE_ON_CHECKOUT: VaultMeta b"attempt_check:reuse_on_checkout:v1:" Named Engine
        // Restore class: Derived beside each record, restored with it.
        [restore: content] [family: unclassified] [tier: canonical];
}
