//! Moved from `crates/oneiron/src/dreamer_consolidation/strength.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_consolidation::selection::SelectionConfig;
use crate::dreamer_consolidation::selection::StrengthSignals;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStrengthPolicy {
    /// Only a score strictly below this row can archive a quiet claim.
    pub archive_below: f64,
    /// Minimum time without newly observed independent evidence, in milliseconds.
    pub quiet_ms: u64,
}

impl Default for ConsolidationStrengthPolicy {
    fn default() -> Self {
        serde_json::from_str(include_str!("strength_defaults.json"))
            .expect("checked consolidation strength defaults")
    }
}

impl ConsolidationStrengthPolicy {
    fn validate(&self) -> Result<()> {
        if !self.archive_below.is_finite()
            || !(0.0..=1.0).contains(&self.archive_below)
            || self.quiet_ms == 0
        {
            return Err(Error::InvalidConfig(
                "invalid consolidation strength policy".into(),
            ));
        }
        Ok(())
    }
}

/// The pre-archive revision and policy, co-committed with the local marker.
/// The revision's complete bytes and indexes remain in the entity store; no
/// second copy of claim text is put beyond the ordinary erase doors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStrengthSnapshot {
    pub attempt: AttemptId,
    pub at_ms: u64,
    pub revision: [u8; 32],
    pub signals: StrengthSignals,
    pub score: f64,
    pub selection: SelectionConfig,
    pub policy: ConsolidationStrengthPolicy,
}
