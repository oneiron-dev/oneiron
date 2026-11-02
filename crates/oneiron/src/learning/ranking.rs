//! The shared selector ranking (OF-184, OF-540; FIX 602): every arm's
//! estimate mean plus its exploration bonus over the arm set's total own
//! runs, highest first, ties by the arm's key so a replay ranks alike.
//! Fractional own runs (credit shares, faded mass) count as they are; a
//! borrowed prior adds weight to its arm's estimate, never own runs.

use super::Estimate;

/// `arms` ranked by `mean + bonus(total, exploration)`, each with its
/// score, highest first and ties by `key`. `total` is the set's own runs
/// rounded up, at least one, so an all-new set still explores.
pub(crate) fn rank_by_estimate<T, K: Ord>(
    arms: Vec<T>,
    exploration: f64,
    estimate: impl Fn(&T) -> &Estimate,
    key: impl Fn(&T) -> K,
) -> Vec<(T, f64)> {
    let runs: f64 = arms.iter().map(|arm| estimate(arm).runs).sum();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let total = (runs.ceil() as u64).max(1);
    let mut ranked: Vec<(T, f64)> = arms
        .into_iter()
        .map(|arm| {
            let read = estimate(&arm);
            let score = read.mean() + read.bonus(total, exploration);
            (arm, score)
        })
        .collect();
    ranked.sort_by(|(a, a_score), (b, b_score)| {
        b_score.total_cmp(a_score).then_with(|| key(a).cmp(&key(b)))
    });
    ranked
}
