//! A step's checkpoint in a code run's replay record.

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
}

impl CodeRunStepCheckpoint {
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
        };
        validate_label(&checkpoint.label, "checkpoint label")?;
        Ok(checkpoint)
    }
}
