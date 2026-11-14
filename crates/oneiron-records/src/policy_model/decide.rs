//! Moved from `crates/oneiron/src/policy_model/decide.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::verdict::PolicyConfidence;
use crate::policy_model::verdict::PolicyHedgeBucket;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// The default time the safeguard read has, from its call's start to its
/// answer, its notes included, when the host's
/// [`PolicyModelConfig::safeguard_read_budget`] names none (FIX 1203).
/// Generous: a reasoning safeguard model thinks before it answers, and a reply
/// after it is no answer. One call's clock spends it once, across its retries
/// ([`PolicyCallClock`]).
pub const SAFEGUARD_READ_BUDGET: Duration = Duration::from_secs(600);

/// The confidence a decided probability carries, in its hedge bucket.
pub fn decided_confidence(probability: f64) -> PolicyConfidence {
    PolicyConfidence {
        calibrated: probability as f32,
        hedge_bucket: if probability >= f64::from(PolicyConfidence::HIGH.calibrated) {
            PolicyHedgeBucket::High
        } else if probability >= f64::from(PolicyConfidence::MEDIUM.calibrated) {
            PolicyHedgeBucket::Medium
        } else {
            PolicyHedgeBucket::Low
        },
    }
}
