//! Beta-posterior lower-bound guard for graduation thresholds.

use crate::consent_graduation::ScopeOutcomeStats;

// ---------------------------------------------------------------------------
// The posterior guard
// ---------------------------------------------------------------------------

/// One-sided 95% normal quantile.
///
/// The same constant, over the same Beta standard deviation, that SK-05's
/// `skill_reliability::SkillReliabilityPosterior::lower_bound` rides. The two
/// implementations are deliberately local and deliberately identical: neither
/// module depends on the other, and a second Z or a second σ would let the
/// engine hold two different opinions about how much evidence is enough.
const POSTERIOR_GUARD_Z: f64 = 1.645;

/// The uniform Beta(1, 1) prior every scope starts from — no scope is born
/// trusted, and none is born suspect.
const POSTERIOR_PRIOR: f64 = 1.0;

// The f64 intermediate exists so the square root keeps its digits; the
// compared value never needed the width.

#[expect(
    clippy::cast_possible_truncation,
    reason = "f64 intermediate narrowed to the f32 a threshold row stores"
)]
#[must_use]
pub fn posterior_lower_bound(wins: u32, losses: u32) -> f32 {
    let alpha = POSTERIOR_PRIOR + f64::from(wins);
    let beta = POSTERIOR_PRIOR + f64::from(losses);
    let total = alpha + beta;
    let std_dev = (alpha * beta / (total * total * (total + 1.0))).sqrt();
    (alpha / total - POSTERIOR_GUARD_Z * std_dev).clamp(0.0, 1.0) as f32
}

/// The `(wins, losses)` a scope's counters present to the guard.
///
/// Wins are the CURRENT clean streak, losses are every correction the scope has
/// ever drawn. Asymmetric on purpose: MS-06 zeroes the streak on any
/// non-clean ruling but keeps the lifetime amendment and rejection counts, so
/// this is the honest reading of what it stores — a scope must re-earn its run,
/// and the corrections it earned it against do not evaporate.
#[must_use]
pub fn guard_evidence(stats: &ScopeOutcomeStats) -> (u32, u32) {
    (
        stats.untouched_streak,
        stats.amended.saturating_add(stats.rejected),
    )
}
