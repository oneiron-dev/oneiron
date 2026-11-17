//! The pure graded metrics behind the retrieval scorecard (RESEARCH-0651 Tier 0).
//!
//! The engine run itself happens in oneiron-bench, which hands this crate the
//! ranked record ids; this module computes every number, so the grading code
//! depends on no engine crate. Gains are graded: `gain(grade) = 2^grade - 1`
//! (grade 0 = not in qrels). Ranks are 1-based.

use std::collections::BTreeMap;

/// Discounted cumulative gain at `k`: the sum over `i < k` of `gain / log2(i + 2)`.
///
/// `ranked` holds record ids, best first. Grades come from `qrels`; an id with
/// no entry counts as grade 0 and adds nothing.
pub fn dcg_at(ranked: &[&str], qrels: &BTreeMap<String, u8>, k: usize) -> f64 {
    let mut sum = 0.0;
    for (index, id) in ranked.iter().take(k).enumerate() {
        let grade = qrels.get(*id).copied().unwrap_or(0);
        if grade == 0 {
            continue;
        }
        let gain = 2f64.powi(i32::from(grade)) - 1.0;
        let divisor = (index.saturating_add(2) as f64).log2();
        sum += gain / divisor;
    }
    sum
}

/// Normalised discounted cumulative gain at `k`: `dcg` over the ideal `dcg`.
///
/// The ideal ranking sorts the `qrels` grades descending and cuts at `k`.
/// Returns 0.0 when `qrels` is empty or the ideal gain is not positive.
pub fn ndcg_at(ranked: &[&str], qrels: &BTreeMap<String, u8>, k: usize) -> f64 {
    if qrels.is_empty() {
        return 0.0;
    }
    let dcg = dcg_at(ranked, qrels, k);
    let mut grades: Vec<u8> = qrels.values().copied().collect();
    grades.sort_unstable();
    grades.reverse();
    let mut ideal = 0.0;
    for (index, grade) in grades.iter().take(k).enumerate() {
        if *grade == 0 {
            continue;
        }
        let gain = 2f64.powi(i32::from(*grade)) - 1.0;
        let divisor = (index.saturating_add(2) as f64).log2();
        ideal += gain / divisor;
    }
    if ideal <= 0.0 {
        return 0.0;
    }
    dcg / ideal
}

/// Reciprocal rank: `1 / rank` of the first id in `qrels`; 0.0 when none match.
///
/// Ranks are 1-based, so the best rank returns 1.0.
pub fn reciprocal_rank(ranked: &[&str], qrels: &BTreeMap<String, u8>) -> f64 {
    for (index, id) in ranked.iter().enumerate() {
        if qrels.contains_key(*id) {
            return 1.0 / (index.saturating_add(1) as f64);
        }
    }
    0.0
}

/// Recall at `k`: the share of `qrels` ids found in the top `k` ranks.
///
/// Returns 0.0 when `qrels` is empty.
pub fn recall_at(ranked: &[&str], qrels: &BTreeMap<String, u8>, k: usize) -> f64 {
    if qrels.is_empty() {
        return 0.0;
    }
    let mut found = 0usize;
    for id in ranked.iter().take(k) {
        if qrels.contains_key(*id) {
            found = found.saturating_add(1);
        }
    }
    (found as f64) / (qrels.len() as f64)
}

/// The nearest-rank percentile of a sorted sample: `None` when empty.
///
/// Otherwise `sorted[rank - 1]` with `rank = max(1, ceil(percent * n / 100))`
/// in integer arithmetic, clamped to the sample count. `percent` runs 1..=100.
pub fn nearest_rank(sorted: &[u64], percent: u32) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let count = sorted.len();
    let as_usize = usize::try_from(percent).unwrap_or(usize::MAX);
    let product = as_usize.saturating_mul(count);
    let rank = product.div_ceil(100).clamp(1, count);
    Some(sorted[rank - 1])
}

/// The F1 of abstention: `2TP / (2TP + FP + FN)`.
///
/// The positive class is "the query expects no result" and the prediction is
/// "the run returned no row". Returns 1.0 when all three counts are zero.
pub fn abstention_f1(true_positive: usize, false_positive: usize, false_negative: usize) -> f64 {
    let total = true_positive
        .saturating_add(false_positive)
        .saturating_add(false_negative);
    if total == 0 {
        return 1.0;
    }
    let twice = true_positive.saturating_mul(2);
    let denom = twice
        .saturating_add(false_positive)
        .saturating_add(false_negative);
    (twice as f64) / (denom as f64)
}
