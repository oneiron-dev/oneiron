//! Moved from `crates/oneiron/src/claim/decay.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Lower bound of the read-side access factor: an aged claim keeps a small
/// surfacing chance instead of becoming unreachable.
pub const ACCESS_FACTOR_FLOOR: f32 = 0.05;

/// Half-life of the [`ClaimAgingClass::Durable`] class, in days.
pub const DURABLE_ACCESS_HALF_LIFE_DAYS: f32 = 365.0;

/// Half-life of the [`ClaimAgingClass::Standard`] class, in days.
pub const STANDARD_ACCESS_HALF_LIFE_DAYS: f32 = 90.0;

/// Half-life of the [`ClaimAgingClass::Ephemeral`] class, in days.
pub const EPHEMERAL_ACCESS_HALF_LIFE_DAYS: f32 = 14.0;

pub const ACCESS_FACTOR_SECONDS_PER_DAY: f64 = 86_400.0;

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
#[derive(
    Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct AccessFactorPolicy {
    /// Half-life of the exponential factor, in seconds.
    pub half_life_secs: f64,
    /// Lower bound applied to the decayed factor.
    pub floor: f32,
}

/// Whether a caller-supplied per-entity override is admissible: finite and
/// within `[0, 1]`. Callers validate at their input boundary and fail
/// closed; [`claim_access_factor`] re-validates.
#[must_use]
pub fn access_factor_override_valid(factor: f32) -> bool {
    factor.is_finite() && (0.0..=1.0).contains(&factor)
}
