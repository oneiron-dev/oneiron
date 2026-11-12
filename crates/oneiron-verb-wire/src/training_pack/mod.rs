//! Moved from `crates/oneiron/src/training_pack/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::training_pack::types::*;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

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
