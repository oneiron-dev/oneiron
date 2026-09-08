//! The Beta(α, β) posterior over a skill’s success rate and the provenance classes its prior is keyed by.

use rmpv::Value;

use crate::error::Result;

use super::codec::{invalid, map_f32};

/// One-sided 95% normal quantile, for the posterior lower bound.
const LOWER_BOUND_Z: f64 = 1.645;

/// Exploration weight of the selection bonus.
///
/// Derived, not tuned by feel: the bonus is `c · σ · sqrt(2 ln N)`, so a 2-pull
/// arm outranks a 100-pull arm exactly when `c · (σ_new − σ_old) · sqrt(2 ln N)`
/// exceeds the mean gap. For the pinned anchor pair (Beta(3,1) vs Beta(91,11))
/// that threshold is `c ≈ 0.285`; 0.25 sits under it, so two lucky pulls never
/// outrank a hundred observed ones, while an arm with an EQUAL mean and wider
/// posterior still ranks above the well-pulled one (anti-shadowing).
const SELECTION_EXPLORATION: f64 = 0.25;

pub(super) const KEY_ALPHA: &str = "alpha";

pub(super) const KEY_BETA: &str = "beta";

/// Schema version of the outcome rows this module persists.
pub const SKILL_RELIABILITY_SCHEMA_VERSION: u64 = 1;

// ---------------------------------------------------------------------------
// Posterior
// ---------------------------------------------------------------------------

/// A Beta(α, β) posterior over one skill's success rate.
///
/// Mirrors [`crate::critic::CriticReliability`]'s shape without importing it
/// (see the module header). Both `alpha` and `beta` stay strictly positive: the
/// seeded prior is positive and outcomes only add.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SkillReliabilityPosterior {
    pub alpha: f32,
    pub beta: f32,
}

impl SkillReliabilityPosterior {
    /// The prior a skill starts from, keyed by provenance class.
    ///
    /// | class | prior | mean |
    /// |---|---|---|
    /// | [`ProvenanceTrustClass::VettedImport`] | Beta(3, 1) | 0.75 |
    /// | [`ProvenanceTrustClass::HumanAuthored`] | Beta(2, 1) | 0.667 |
    /// | [`ProvenanceTrustClass::UnvettedImport`] | Beta(1, 1) | 0.50 |
    /// | [`ProvenanceTrustClass::Generated`] | Beta(1, 2) | 0.333 |
    ///
    /// The ordering is the point: bytes a scanner cleared start optimistic, a
    /// human's own skill starts trusted-but-unproven, an unvetted import starts
    /// uniform, and machine-distilled or conversation-converted content starts
    /// WEAK — it has to earn its place against skills someone vouched for.
    #[must_use]
    pub const fn seeded_from_provenance(class: ProvenanceTrustClass) -> Self {
        let (alpha, beta) = match class {
            ProvenanceTrustClass::VettedImport => (3.0, 1.0),
            ProvenanceTrustClass::HumanAuthored => (2.0, 1.0),
            ProvenanceTrustClass::UnvettedImport => (1.0, 1.0),
            ProvenanceTrustClass::Generated => (1.0, 2.0),
        };
        Self { alpha, beta }
    }

    /// Folds one attributed outcome in.
    pub const fn apply(&mut self, win: bool) {
        if win {
            self.alpha += 1.0;
        } else {
            self.beta += 1.0;
        }
    }

    /// Total pseudo-observations: prior weight plus attributed outcomes.
    #[must_use]
    pub fn observations(&self) -> f32 {
        self.alpha + self.beta
    }

    /// Posterior mean — the value the record's `confidence` cache holds.
    #[must_use]
    pub fn mean(&self) -> f32 {
        self.alpha / self.observations()
    }

    /// One-sided 95% lower confidence bound: `mean − Z·σ`, clamped to `[0, 1]`,
    /// with `σ` the Beta standard deviation
    /// `sqrt(αβ / ((α+β)² (α+β+1)))` and `Z` = `LOWER_BOUND_Z`.
    ///
    /// The normal approximation is deliberate: it is the same σ the selection
    /// bonus rides, so the pessimistic and optimistic ends of this module can
    /// never disagree about how uncertain a posterior is.
    ///
    /// Sanity anchors: Beta(3, 1) (two wins on a uniform prior) → ≈ 0.43;
    /// Beta(91, 11) (90/100) → ≈ 0.84. Two lucky pulls never outrank a hundred
    /// observed ones on this ranking.
    #[must_use]
    pub fn lower_bound(&self) -> f32 {
        let mean = f64::from(self.mean());
        narrow((mean - LOWER_BOUND_Z * self.std_dev()).clamp(0.0, 1.0))
    }

    /// Selection score: posterior mean plus the exploration bonus
    /// `c · σ · sqrt(2 ln(N + 1))` over `total_pulls` observations across the
    /// candidate set (`c` = `SELECTION_EXPLORATION`).
    ///
    /// Deliberately NOT clamped to `[0, 1]`: the score is a ranking key, and
    /// capping it at 1.0 would flatten exactly the arms exploration is meant to
    /// separate. There is no hard active-cap anywhere in this path (OF-184) —
    /// shadowing is prevented by the bonus, not by a quota.
    #[must_use]
    pub fn ucb(&self, total_pulls: u32) -> f32 {
        let horizon = (2.0 * f64::from(total_pulls.max(1).saturating_add(1)).ln()).sqrt();
        let bonus = SELECTION_EXPLORATION * self.std_dev() * horizon;
        // A ranking key, so no unit clamp — see the doc comment above.
        narrow(f64::from(self.mean()) + bonus)
    }

    /// Beta standard deviation, in f64 so the square roots keep their digits.
    fn std_dev(&self) -> f64 {
        let alpha = f64::from(self.alpha);
        let beta = f64::from(self.beta);
        let total = alpha + beta;
        (alpha * beta / (total * total * (total + 1.0))).sqrt()
    }

    pub(super) fn to_value(self) -> Value {
        Value::Map(vec![
            (Value::from(KEY_ALPHA), Value::F32(self.alpha)),
            (Value::from(KEY_BETA), Value::F32(self.beta)),
        ])
    }

    pub(super) fn from_value(value: &Value) -> Result<Self> {
        let alpha =
            map_f32(value, KEY_ALPHA).ok_or(invalid("skill.reliability body is missing alpha"))?;
        let beta =
            map_f32(value, KEY_BETA).ok_or(invalid("skill.reliability body is missing beta"))?;
        if !alpha.is_finite() || !beta.is_finite() || alpha <= 0.0 || beta <= 0.0 {
            return Err(invalid(
                "skill.reliability alpha/beta must be finite and positive",
            ));
        }
        Ok(Self { alpha, beta })
    }
}

/// Provenance classes the prior table is keyed by (ARCH-0053 §5).
///
/// Total over lawful [`SkillRecord`] shapes: the record invariant is that
/// exactly one of `generated` / `human_authored` holds and `generated` matches
/// [`ClaimSource::Generated`], so every record lands in exactly one arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProvenanceTrustClass {
    /// Imported, and a scanner cleared the record's canonical content hash
    /// (SK-02/SK-03 `skill.scan_verdict` rows on the content anchor).
    VettedImport,
    /// Imported with no clean verdict on its bytes — including an import that
    /// carries no canonical content hash to check.
    UnvettedImport,
    /// Human-authored locally (conversion, fork, hand-written).
    HumanAuthored,
    /// Machine-generated: Dreamer distill, conversation convert.
    Generated,
}

/// f64 math down to the f32 the posterior stores. The intermediate width exists
/// so the square roots keep their digits; the stored value never needed it.
#[expect(
    clippy::cast_possible_truncation,
    reason = "f64 intermediate narrowed to the f32 the posterior stores"
)]
fn narrow(value: f64) -> f32 {
    value as f32
}

/// An attributed-outcome count as posterior weight.
///
/// Past 2^24 an f32 stops representing consecutive integers, so a skill with
/// ~16.7M attributed outcomes accumulates rounding. That is the honest failure:
/// the RATIO is unaffected at that scale, whereas saturating the count would
/// silently freeze the posterior against all further evidence.
#[expect(
    clippy::cast_precision_loss,
    reason = "outcome counts weight an f32 posterior; the ratio is what is read"
)]
pub(super) fn count_weight(count: u32) -> f32 {
    count as f32
}
