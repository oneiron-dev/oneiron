//! Typed failure vocabulary and classifier (class, verdict, tier, evidence).

use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

/// Consecutive transient failures a scope tolerates before escalating.
pub const DEFAULT_MAX_CONSECUTIVE_TRANSIENTS: NonZeroU16 =
    NonZeroU16::new(3).expect("three is non-zero");

/// The canonical three-value routing class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    Transient,
    Permanent,
    Ambiguous,
}

/// Typed output of the upstream tripwire/classifier stack. This module carries
/// the producer tier but does not implement any detector. Missing evidence is
/// represented as Indeterminate and therefore classifies Ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedFailureVerdict {
    Retryable,
    NonRetryable,
    Indeterminate,
}

/// Which ARCH-0066 detector tier produced the verdict. Only T1 tripwire
/// evidence is trusted enough to spend an automatic retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorTier {
    T1Tripwire,
    T2Classifier,
    T3Judge,
}

/// The typed detector evidence one failure input carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedFailureEvidence {
    /// Lowercase-hex EntityId spelling when evidence exists.
    #[serde(default)]
    pub evidence_ref: Option<String>,
    pub verdict: TypedFailureVerdict,
    #[serde(default)]
    pub tier: Option<DetectorTier>,
    /// Stable typed failure code supplied by the producer. It is persisted as
    /// the queue's human-readable terminal/retry reason, but never parsed to
    /// recover retryability.
    pub stable_reason: String,
}

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
