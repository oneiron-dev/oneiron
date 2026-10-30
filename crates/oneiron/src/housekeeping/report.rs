//! What a housekeeping pass reports: one row per sweep, and the counts each
//! sweep run reports.

use serde::Serialize;

use super::{HostOnlyReason, HousekeepingSweep};
use crate::error::ErrorKind;

/// What one pass did, one row per sweep in [`HousekeepingSweep::ALL`] order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HousekeepingReport {
    /// The vault clock when the pass began, in seconds.
    pub started_at: u64,
    pub sweeps: Vec<SweepReport>,
}

impl HousekeepingReport {
    /// Sweeps that ran this pass.
    pub fn ran(&self) -> usize {
        self.count(|outcome| matches!(outcome, SweepOutcome::Ran { .. }))
    }

    /// Sweeps that failed or panicked this pass, or ran but could not finish
    /// some of their items.
    pub fn failed(&self) -> usize {
        self.count(|outcome| match outcome {
            SweepOutcome::Failed { .. } | SweepOutcome::Panicked => true,
            SweepOutcome::Ran { work, .. } => work.items_failed() > 0,
            _ => false,
        })
    }

    /// Due sweeps the budget left for a later pass.
    pub fn out_of_budget(&self) -> usize {
        self.count(|outcome| matches!(outcome, SweepOutcome::OutOfBudget))
    }

    /// The row of one sweep.
    pub fn sweep(&self, sweep: HousekeepingSweep) -> Option<&SweepOutcome> {
        self.sweeps
            .iter()
            .find(|row| row.sweep == sweep)
            .map(|row| &row.outcome)
    }

    fn count(&self, matches: impl Fn(&SweepOutcome) -> bool) -> usize {
        self.sweeps
            .iter()
            .filter(|row| matches(&row.outcome))
            .count()
    }
}

/// One sweep's row in a [`HousekeepingReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SweepReport {
    pub sweep: HousekeepingSweep,
    #[serde(flatten)]
    pub outcome: SweepOutcome,
}

/// What became of one sweep in one pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SweepOutcome {
    /// The sweep ran. `complete` is false when it stopped at its bound with
    /// work left; it is due again on the next pass.
    Ran { work: SweepWork, complete: bool },
    /// Not due before `due_at` (vault clock, seconds).
    NotDue { due_at: u64 },
    /// Due, but the pass's budget was spent; it runs on a later pass, ahead
    /// of sweeps that fell due after it.
    OutOfBudget,
    /// The sweep returned an error. It is retried on a later pass.
    Failed {
        #[serde(serialize_with = "serialize_error_kind")]
        kind: ErrorKind,
    },
    /// The sweep panicked. It is retried on a later pass.
    Panicked,
    /// The engine does not run this sweep.
    HostOnly { reason: HostOnlyReason },
}

/// The counts one sweep run reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SweepWork {
    SecretLeases {
        expired: u64,
        /// Files a revoke or an expiry had kept that this run removed.
        files_removed: u64,
        /// Files still kept: not removable yet, or not the file the vault
        /// wrote. Retried on later runs; never a failed item, so they hold
        /// no other lease's expiry back.
        files_kept: u64,
    },
    CriticalConfirms {
        demoted: u64,
        pages: u64,
    },
    SymbolLeases {
        released: u64,
    },
    VoicePrints {
        pruned: u64,
    },
    EsignExpiry {
        documents: u64,
        expired: u64,
        failed: u64,
    },
    EsignSeals {
        documents: u64,
        enqueued: u64,
        failed: u64,
    },
    Commitments {
        lapsed: u64,
        close_hooks_repaired: u64,
    },
    GateDecisions {
        removed: u64,
    },
    HardErase(HardEraseWork),
    PprCache {
        evicted: u64,
        deps_cleaned: u64,
    },
    SharedActs {
        /// Matured-act notices written to live Owners.
        noticed: u64,
    },
    SecretLift(SecretLiftWork),
    ClaimVadDebt {
        /// Owed consolidations that committed, or that owed nothing any more.
        settled: u64,
        /// Owed consolidations that failed; each keeps its debt.
        failed: u64,
    },
    FoundKeyNotices {
        /// Due records whose notices were raised.
        records: u64,
    },
}

impl SweepWork {
    /// Items the run could not finish: each is retried on a later pass, after
    /// the backoff.
    pub fn items_failed(&self) -> u64 {
        match *self {
            Self::EsignExpiry { failed, .. } | Self::EsignSeals { failed, .. } => failed,
            Self::HardErase(work) => work
                .jobs_failed
                .saturating_add(work.obligations_undecodable),
            Self::SecretLift(work) => work.failed,
            Self::ClaimVadDebt { failed, .. } => failed,
            _ => 0,
        }
    }

    /// Whether the run found nothing to do.
    pub fn is_idle(&self) -> bool {
        match *self {
            Self::SecretLeases {
                expired,
                files_removed,
                files_kept,
            } => expired == 0 && files_removed == 0 && files_kept == 0,
            Self::CriticalConfirms { demoted, .. } => demoted == 0,
            Self::SymbolLeases { released } => released == 0,
            Self::VoicePrints { pruned } => pruned == 0,
            Self::EsignExpiry {
                expired, failed, ..
            } => expired == 0 && failed == 0,
            Self::EsignSeals {
                enqueued, failed, ..
            } => enqueued == 0 && failed == 0,
            Self::Commitments {
                lapsed,
                close_hooks_repaired,
            } => lapsed == 0 && close_hooks_repaired == 0,
            Self::GateDecisions { removed } => removed == 0,
            Self::HardErase(work) => work == HardEraseWork::default(),
            Self::PprCache {
                evicted,
                deps_cleaned,
            } => evicted == 0 && deps_cleaned == 0,
            Self::SharedActs { noticed } => noticed == 0,
            Self::SecretLift(work) => work == SecretLiftWork::default(),
            Self::ClaimVadDebt { settled, failed } => settled == 0 && failed == 0,
            Self::FoundKeyNotices { records } => records == 0,
        }
    }
}

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

fn serialize_error_kind<S: serde::Serializer>(
    kind: &ErrorKind,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{kind:?}"))
}
