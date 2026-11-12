//! Moved from `crates/oneiron/src/training_pack/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::training_pack::types::*;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Serialize;

impl ExportCheck {
    pub fn passed(&self) -> bool {
        self.hash_mismatches.is_empty()
            && self.probe_coverage_matches
            && self.probe_checkpoints_match
            && self.settings_match
            && self.harness_matches
            && self.argmax_flips == 0
            && self.max_logit_difference <= self.tolerance
            && self
                .question_check
                .is_none_or(|check| check.finite && check.tokens_match && check.passed)
            // A question head serves only once the host reproduced its
            // receipt (FIX 7568); a missing check is a failed one.
            && (self.question_check.is_none()
                || self
                    .candle_parity
                    .as_ref()
                    .is_some_and(CandleParityCheck::passed))
    }
}
pub mod types;
