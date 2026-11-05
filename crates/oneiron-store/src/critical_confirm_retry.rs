//! The expiry walk's backoff state for a timeout demotion that keeps failing
//! (FIX 12079): a row whose demotion failed waits before the walk tries it
//! again, the wait doubling with each failure in a row up to a cap. The walk
//! always tries the row again once its wait ends: nothing is dropped. In
//! memory only. The engine files the healer item and logs each failure.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The wait after a timeout demotion's first failure; each further failure
/// in a row doubles it.
pub const CONFIRM_DEMOTION_RETRY_BASE_SECS: u64 = 120;
/// The longest wait between two tries of a failing timeout demotion.
pub const CONFIRM_DEMOTION_RETRY_CAP_SECS: u64 = 3_600;
/// One failing row's retry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmDemotionRetry {
    /// Failures in a row.
    pub failures: u32,
    /// The walk tries the row again at or after this time.
    pub retry_at: u64,
    /// Whether the row's healer item is stored.
    pub filed: bool,
}

/// What one page of the walk learned of a row it tried, by its confirm id:
/// `None` once it demoted or had nothing to demote, else its retry state.
pub type ConfirmDemotionOutcome = ([u8; 32], Option<ConfirmDemotionRetry>);

/// Each failing timeout demotion's retry state, by its confirm id, and the
/// confirms the running expiry walk has read still in the tray (FIX 12288).
#[derive(Debug, Default)]
pub struct ConfirmDemotionRetries {
    retries: Mutex<BTreeMap<[u8; 32], ConfirmDemotionRetry>>,
    seen: Mutex<BTreeSet<[u8; 32]>>,
}

impl ConfirmDemotionRetries {
    fn rows(&self) -> MutexGuard<'_, BTreeMap<[u8; 32], ConfirmDemotionRetry>> {
        self.retries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn walked(&self) -> MutexGuard<'_, BTreeSet<[u8; 32]>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the walk tries the row `confirm` at `now`: one with no failure
    /// on record, or one whose wait has ended.
    #[must_use]
    pub fn due(&self, confirm: &[u8; 32], now: u64) -> bool {
        self.rows()
            .get(confirm)
            .is_none_or(|retry| retry.retry_at <= now)
    }

    /// The row `confirm`'s retry state after one more failure at `now`.
    #[must_use]
    pub fn after_failure(&self, confirm: &[u8; 32], now: u64) -> ConfirmDemotionRetry {
        let prior = self.rows().get(confirm).copied();
        let failures = prior.map_or(0, |retry| retry.failures).saturating_add(1);
        ConfirmDemotionRetry {
            failures,
            retry_at: now.saturating_add(retry_wait(failures)),
            filed: prior.is_some_and(|retry| retry.filed),
        }
    }

    /// Keeps what a committed page learned: a row it settled leaves the map,
    /// a row that failed takes its new state. Every confirm the page read is
    /// noted as still in the tray; once the walk ends, every entry whose row
    /// left the tray another way (owner settle, replicated overwrite) is
    /// dropped (FIX 12288). Rows still in the tray keep their state.
    pub fn record(
        &self,
        outcomes: Vec<ConfirmDemotionOutcome>,
        seen: Vec<[u8; 32]>,
        complete: bool,
    ) {
        let mut rows = self.rows();
        for (confirm, retry) in outcomes {
            match retry {
                Some(retry) => {
                    rows.insert(confirm, retry);
                }
                None => {
                    rows.remove(&confirm);
                }
            }
        }
        let mut walked = self.walked();
        walked.extend(seen);
        if complete {
            rows.retain(|confirm, _| walked.contains(confirm));
            walked.clear();
        }
    }
}

/// The wait after `failures` failures in a row: the base, doubled per
/// failure after the first, at most the cap.
fn retry_wait(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(u64::BITS - 1);
    CONFIRM_DEMOTION_RETRY_BASE_SECS
        .saturating_mul(1_u64 << doublings)
        .min(CONFIRM_DEMOTION_RETRY_CAP_SECS)
}
