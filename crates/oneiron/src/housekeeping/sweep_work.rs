//! The counts the erasure and lift sweeps report in their `SweepWork` row.

use serde::Serialize;

/// The erasure sweep's counts (ARCH-0038 historical carriers).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HardEraseWork {
    /// Obligations discharged: receipts finalized and the obligation removed.
    pub jobs_processed: u64,
    /// Obligations left for a later run without an attempt (not yet due, a
    /// live window, an unreadable row).
    pub jobs_deferred: u64,
    /// Of those, the ones whose receipt waits for this install's signer to load (FIX 2597).
    pub jobs_deferred_signer_unavailable: u64,
    /// Windows no caller held, written down and closed so their carriers
    /// could be compacted.
    pub windows_unloaded: u64,
    /// Obligations whose attempt failed; each keeps its row with a retry time.
    pub jobs_failed: u64,
    pub windows_compacted: u64,
    pub windows_deferred_live: u64,
    pub windows_deferred_raced: u64,
    /// Windows whose cut was not proved to root at their tip (FIX 6520).
    pub windows_deferred_unproved: u64,
    /// Windows and documents a legal hold keeps as they are (OF-470).
    pub windows_deferred_held: u64,
    pub receipts_finalized: u64,
    /// Obligations past their 30-day deadline.
    pub deadline_breaches: u64,
    pub quarantine_rows_expired: u64,
    /// Receipts queued for a sweep that no obligation covers.
    pub obligations_missing: u64,
    pub obligations_undecodable: u64,
}

/// The lift sweep's counts for one housekeeping run (OF-067). The run's own
/// receipt counts the whole run, by family.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SecretLiftWork {
    /// Rows the census read.
    pub rows_read: u64,
    /// Rows rewritten with their handles.
    pub masked: u64,
    /// Lift proposals filed.
    pub proposals: u64,
    /// Rows that failed again when retried.
    pub failed: u64,
    /// A run waits for the owner's switch to come back on.
    pub paused: bool,
    /// The run ended and wrote its receipt.
    pub finished: bool,
}
