//! How long a Retry park waits before a later wake pass resumes it (FIX
//! 8716): the vault's own `dreamer_retry_park_seconds` policy row, else the
//! shipped 900 seconds, resolved in the reader's own snapshot. The deadline
//! lane's projection and the resume writer read the same resolved value, so
//! an owner's pacing moves both together. Pacing, never a cap: the work
//! always resumes, as the same try, once its pause passed.

use crate::Vault;
use crate::error::Result;

use super::{DreamerParkCause, DreamerParkedAttemptRecord};

impl Vault {
    /// The vault's Retry-park pause at `txn`'s revision, in store-clock
    /// seconds.
    pub(crate) fn dreamer_retry_park_secs_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<u64> {
        Ok(crate::gate::resolve_policy_manifest(&self.store, txn)?.dreamer_retry_park_seconds())
    }
}

impl DreamerParkCause {
    /// Whether a later wake pass resumes a park of this cause as the same
    /// try (DOOR-144): a Checkpoint, a Paused or a Retry park.
    #[must_use]
    pub const fn resumes_on_later_pass(self) -> bool {
        matches!(self, Self::Checkpoint | Self::Paused | Self::Retry)
    }

    /// How long after it parked a later wake pass resumes a park of this
    /// cause: a Checkpoint or a Paused park at once, a Retry after
    /// `retry_secs`, the vault's resolved pause. `None` for a park no later
    /// pass resumes.
    #[must_use]
    pub const fn later_pass_resume_delay(self, retry_secs: u64) -> Option<u64> {
        match self {
            Self::Checkpoint | Self::Paused => Some(0),
            Self::Retry => Some(retry_secs),
            _ => None,
        }
    }
}

impl DreamerParkedAttemptRecord {
    /// When a later wake pass may resume this park as the same try, in
    /// store-clock seconds, under the vault's resolved Retry pause
    /// `retry_secs`; `None` for a park no later pass resumes.
    #[must_use]
    pub fn later_pass_due_at(&self, retry_secs: u64) -> Option<u64> {
        self.cause
            .later_pass_resume_delay(retry_secs)
            .map(|delay| self.parked_at.saturating_add(delay))
    }
}
