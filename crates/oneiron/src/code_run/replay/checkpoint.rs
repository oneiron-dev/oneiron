//! A step's checkpoint in a code run's replay record. It records where the
//! step's calls end in the run's bridge log (FIX 6354), so a later row of
//! the run still proves an older step's end, and the range of the step's
//! own calls a program fold keeps (FIX 14541).

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
    /// started. Required on every checkpoint: it says where the step's
    /// calls end; the range of the step's own calls is
    /// [`Self::bridge_calls`].
    pub bridge_end: u64,
    /// The bridge calls this step made, `bridge_calls[start..end]` of its
    /// record: what a fold of its program keeps of what it said (FIX
    /// 14541). A call made between two steps lies in neither. `None` where
    /// its writer did not record it. It is the step's own range; where the
    /// step's calls end in the run's log is [`Self::bridge_end`].
    pub bridge_calls: Option<(u64, u64)>,
}

impl CodeRunStepCheckpoint {
    /// A checkpoint whose step ends at bridge position zero, with no
    /// recorded calls; a writer names its step's end with
    /// [`Self::ending_at`] and its calls with [`Self::with_bridge_calls`].
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
            bridge_calls: None,
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

    /// The checkpoint with the bridge calls its step made:
    /// `bridge_calls[start..end]`.
    #[must_use]
    pub fn with_bridge_calls(mut self, start: usize, end: usize) -> Self {
        self.bridge_calls = Some((start as u64, end.max(start) as u64));
        self
    }

    /// The step's bridge calls as indices into its record's `bridge_calls`.
    #[must_use]
    pub fn bridge_range(&self) -> Option<std::ops::Range<usize>> {
        let (start, end) = self.bridge_calls?;
        Some(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
    }
}
