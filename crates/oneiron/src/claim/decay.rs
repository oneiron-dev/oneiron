//! Read-side memory decay: the pure aging-class `access_factor` contract.
//!
//! Retrieval multiplies a candidate's access factor onto its fused score
//! exactly once, AFTER the z-normalized multi-channel blend, so decay
//! changes surfacing probability and rank only — never claim value,
//! confidence, evidence, lifecycle history, or edge truth, and never
//! survival (deletion stays explicit and consent-gated). Nothing here
//! touches storage: the caller supplies the decoded body, the entity's
//! `learned_at`, and the run's resolved clock, so retrieval writes no
//! access timestamp and no bump counter, and a frozen clock replays
//! bit-identically.
//!
//! Class policy is pinned engine-level, not manifest data or per-predicate
//! configuration: the aging class comes from the predicate root
//! ([`predicate_root`], "drop the leaf" — DESIGN-PIN A0) and each class
//! carries exactly one half-life. Confidence is deliberately NOT an input:
//! it records how sure the system was that a claim is true, not how easy
//! that claim should be to surface later.

use crate::error::{Error, Result};

use super::{ClaimBody, ClaimLifecycleStatus, predicate_root};

/// Lower bound of the read-side access factor: an aged claim keeps a small
/// surfacing chance instead of becoming unreachable.
pub const ACCESS_FACTOR_FLOOR: f32 = 0.05;

/// Half-life of the [`ClaimAgingClass::Durable`] class, in days.
pub const DURABLE_ACCESS_HALF_LIFE_DAYS: f32 = 365.0;

/// Half-life of the [`ClaimAgingClass::Standard`] class, in days.
pub const STANDARD_ACCESS_HALF_LIFE_DAYS: f32 = 90.0;

/// Half-life of the [`ClaimAgingClass::Ephemeral`] class, in days.
pub const EPHEMERAL_ACCESS_HALF_LIFE_DAYS: f32 = 14.0;

const ACCESS_FACTOR_SECONDS_PER_DAY: f64 = 86_400.0;

/// How fast a claim's retrievability decays, keyed by predicate root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimAgingClass {
    /// Slow-aging facts about who someone is: roots `identity`,
    /// `preference`, `relationship`, and the engine-authored federation
    /// root `core.relationship`.
    Durable,
    /// Every other well-formed predicate root.
    Standard,
    /// Fast-aging situational facts: roots `status`, `availability`,
    /// `location`.
    Ephemeral,
}

impl ClaimAgingClass {
    /// The pinned policy of this class.
    #[must_use]
    pub fn policy(self) -> AccessFactorPolicy {
        let half_life_days = match self {
            Self::Durable => DURABLE_ACCESS_HALF_LIFE_DAYS,
            Self::Standard => STANDARD_ACCESS_HALF_LIFE_DAYS,
            Self::Ephemeral => EPHEMERAL_ACCESS_HALF_LIFE_DAYS,
        };
        AccessFactorPolicy {
            half_life_secs: f64::from(half_life_days) * ACCESS_FACTOR_SECONDS_PER_DAY,
            floor: ACCESS_FACTOR_FLOOR,
        }
    }
}

/// Decay policy of one aging class.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AccessFactorPolicy {
    /// Half-life of the exponential factor, in seconds.
    pub half_life_secs: f64,
    /// Lower bound applied to the decayed factor.
    pub floor: f32,
}

/// One claim's read-side retrievability under the decay contract.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClaimRetrievability {
    /// Post-fusion surfacing multiplier in `[0, 1]`.
    pub access_factor: f32,
    /// The class the factor was derived from.
    pub aging_class: ClaimAgingClass,
}

/// Classifies a predicate into its aging class by predicate ROOT, so the
/// contract stays class-level: the 2-segment predicate `location.current`
/// has root `location` and is therefore [`ClaimAgingClass::Ephemeral`].
/// Every unlisted (including unknown, wild-namespace) root is
/// [`ClaimAgingClass::Standard`] — the crate stays predicate-agnostic.
///
/// `core.relationship` is a literal member of the Durable list, NOT a
/// namespace rule: it is the root the engine's own federation predicates
/// (`core.relationship.person_ref`, `core.relationship.label`) resolve to
/// after dropping the leaf, and a person-link is exactly as slow-aging as
/// the bare `relationship` root beside it. Membership stays by EXACT root,
/// never by suffix or by product layer: a wild `user.relationship.note`
/// (root `user.relationship`) and a three-segment
/// `relationship.<mid>.<leaf>` still classify Standard.
///
/// Deliberately not a `PREDICATE_LAYER_NAMESPACES` strip: [`predicate_root`]
/// is layer-agnostic by design ("no registry or layer-list lookup"), and
/// stripping every product layer would silently reclassify whole families
/// that ship no predicates — a policy change wearing a bug fix's clothes.
/// When the ONE-252 per-predicate family field lands it supersedes this
/// list outright.
#[must_use]
pub fn claim_aging_class(predicate: &str) -> ClaimAgingClass {
    match predicate_root(predicate) {
        "identity" | "preference" | "relationship" | "core.relationship" => {
            ClaimAgingClass::Durable
        }
        "status" | "availability" | "location" => ClaimAgingClass::Ephemeral,
        _ => ClaimAgingClass::Standard,
    }
}

/// Whether a caller-supplied per-entity override is admissible: finite and
/// within `[0, 1]`. Callers validate at their input boundary and fail
/// closed; [`claim_access_factor`] re-validates.
#[must_use]
pub fn access_factor_override_valid(factor: f32) -> bool {
    factor.is_finite() && (0.0..=1.0).contains(&factor)
}

/// Computes the read-side access factor of one claim under an injected
/// clock: `max(floor, 2^(-age_secs / half_life_secs))` for a live claim,
/// where `age_secs` is `now - learned_at` clamped at zero (a claim learned
/// "in the future" is not aged).
///
/// A claim whose lifecycle is `Superseded` or `Retracted`, or whose
/// `valid_to <= now`, has factor `0.0`: its retrievability drops while its
/// stored bytes stay exactly as written. That zero is unconditional — an
/// `override_factor` is a retrievability knob on live claims, never a
/// door that resurfaces a closed one.
///
/// `override_factor` is a caller-supplied per-entity input seam, never a
/// stored field: when present and admissible it replaces the class-derived
/// factor for a live claim (downward or upward within `[0, 1]`). An
/// inadmissible value is a caller bug and fails closed with
/// [`Error::InvalidConfig`].
pub fn claim_access_factor(
    body: &ClaimBody,
    learned_at: u64,
    now: u64,
    override_factor: Option<f32>,
) -> Result<ClaimRetrievability> {
    if let Some(factor) = override_factor
        && !access_factor_override_valid(factor)
    {
        return Err(Error::InvalidConfig(format!(
            "access factor override must be finite and within [0, 1], got {factor}"
        )));
    }

    let aging_class = claim_aging_class(&body.predicate);
    let closed = matches!(
        body.lifecycle,
        ClaimLifecycleStatus::Superseded | ClaimLifecycleStatus::Retracted
    ) || body.valid_to.is_some_and(|valid_to| valid_to <= now);

    let access_factor = if closed {
        0.0
    } else {
        override_factor.unwrap_or_else(|| decayed_access_factor(aging_class, learned_at, now))
    };

    Ok(ClaimRetrievability {
        access_factor,
        aging_class,
    })
}

fn decayed_access_factor(aging_class: ClaimAgingClass, learned_at: u64, now: u64) -> f32 {
    let policy = aging_class.policy();
    let age_secs = now.saturating_sub(learned_at) as f64;
    let decayed = 2.0_f64.powf(-age_secs / policy.half_life_secs) as f32;
    decayed.max(policy.floor)
}
