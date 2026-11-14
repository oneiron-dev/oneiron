//! Typed failure vocabulary and classifier (class, verdict, tier, evidence).

use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

/// Consecutive transient failures a scope tolerates before escalating.
pub const DEFAULT_MAX_CONSECUTIVE_TRANSIENTS: NonZeroU16 =
    NonZeroU16::new(3).expect("three is non-zero");

#[doc(hidden)]
pub use oneiron_records::failure_ladder::classify::{
    DetectorTier, FailureClass, TypedFailureEvidence, TypedFailureVerdict,
};

/// Maps typed detector output onto the routing class, ambiguity-biased.
///
/// `(Retryable, None)` is Ambiguous even though validated production input
/// cannot reach that combination: the bias must hold for direct/unit use too.
#[must_use]
pub const fn classify_failure(evidence: &TypedFailureEvidence) -> FailureClass {
    match (evidence.verdict, evidence.tier) {
        (TypedFailureVerdict::Retryable, Some(DetectorTier::T1Tripwire)) => FailureClass::Transient,
        (
            TypedFailureVerdict::Retryable,
            Some(DetectorTier::T2Classifier | DetectorTier::T3Judge) | None,
        )
        | (TypedFailureVerdict::Indeterminate, _) => FailureClass::Ambiguous,
        (TypedFailureVerdict::NonRetryable, _) => FailureClass::Permanent,
    }
}
