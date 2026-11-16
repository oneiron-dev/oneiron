//! The side table `check_record` keeps: the native check records, one row a check.

crate::side_table::side_tables! {
    /// One native check a run recorded in its own checkout (ARCH-0068 RC5), minted by the engine. Key: AttemptId, then id16 (the check).
    ATTEMPT_CHECK_RECORD: VaultMeta b"attempt_check:record:v1:" Named Engine
        // Restore class: an attempt's own records come back with its image.
        [restore: content] [family: unclassified] [tier: canonical];
}
