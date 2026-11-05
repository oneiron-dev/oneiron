//! A step's checkpoint in a code run's replay record. It records where the
//! step's calls end in the run's bridge log (FIX 6354), so a later row of
//! the run still proves an older step's end.

use super::super::support::validate_label;
use super::CODE_RUN_REPLAY_HASH_LEN;
use crate::Result;

/// Deterministic checkpoint marker between bridge calls.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeRunStepCheckpoint {
    pub seq: u64,
    pub label: String,
    pub state_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
    pub created_at_ms: u64,
    /// The run-global bridge position the step's calls end at, exclusive:
    /// the run's bridge log length once the step's calls, nested ones
    /// included, joined it (FIX 6354). A step with no call ends where it
    /// started.
    pub bridge_end: u64,
}

impl CodeRunStepCheckpoint {
    /// A checkpoint whose step ends at bridge position zero; a writer names
    /// its step's end with [`Self::ending_at`].
    pub fn new(
        seq: u64,
        label: impl Into<String>,
        state_hash: [u8; CODE_RUN_REPLAY_HASH_LEN],
        created_at_ms: u64,
    ) -> Result<Self> {
        let checkpoint = Self {
            seq,
            label: label.into(),
            state_hash,
            created_at_ms,
            bridge_end: 0,
        };
        validate_label(&checkpoint.label, "checkpoint label")?;
        Ok(checkpoint)
    }

    /// This checkpoint, its step's calls ending at `bridge_end` (FIX 6354).
    #[must_use]
    pub fn ending_at(mut self, bridge_end: u64) -> Self {
        self.bridge_end = bridge_end;
        self
    }
}
