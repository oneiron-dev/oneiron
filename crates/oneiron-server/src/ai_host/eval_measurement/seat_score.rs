//! Fixed-code scorers for seat-native legs. No chat judgment or fallback:
//! every score is weight-normalized over the case's anchoring labels.

use oneiron::skill_optimize::{EvalLabel, MeasurementUnavailable};

use super::score::Scored;

fn total_weight(labels: &[EvalLabel]) -> Option<f64> {
    if labels.is_empty() {
        return None;
    }
    let total = labels.iter().map(|label| label.weight).sum::<f64>();
    (total.is_finite() && total > 0.0).then_some(total)
}

fn score(value: f64) -> Scored {
    Scored::Score { value, judge: None }
}

/// Weighted exact-byte recall of one Choice answer.
pub(super) fn exact_match(predicted: &str, labels: &[EvalLabel]) -> Scored {
    let Some(total) = total_weight(labels) else {
        return Scored::Unavailable(MeasurementUnavailable::NoLabel);
    };
    let matched = labels
        .iter()
        .filter(|label| label.value.as_bytes() == predicted.as_bytes())
        .map(|label| label.weight)
        .sum::<f64>();
    score(matched / total)
}

/// Weighted recall of tag-span labels, matching a multiset in case order
/// without reusing one predicted occurrence. Extra predictions carry no weight.
pub(super) fn tag_recall(predicted: &[String], labels: &[EvalLabel]) -> Scored {
    let Some(total) = total_weight(labels) else {
        return Scored::Unavailable(MeasurementUnavailable::NoLabel);
    };
    let mut remaining = predicted.to_vec();
    let mut matched = 0.0;
    for label in labels {
        if let Some(index) = remaining.iter().position(|value| value == &label.value) {
            remaining.remove(index);
            matched += label.weight;
        }
    }
    score(matched / total)
}

fn cosine(left: &[f32], right: &[f32]) -> Option<f64> {
    if left.len() != right.len() || left.is_empty() {
        return None;
    }
    let mut dot = 0.0;
    let mut left_norm = 0.0;
    let mut right_norm = 0.0;
    for (&left, &right) in left.iter().zip(right) {
        let left = f64::from(left);
        let right = f64::from(right);
        dot += left * right;
        left_norm += left * left;
        right_norm += right * right;
    }
    let denominator = left_norm.sqrt() * right_norm.sqrt();
    if !denominator.is_finite() || denominator <= 0.0 {
        return None;
    }
    Some((dot / denominator).clamp(-1.0, 1.0))
}

/// Weighted mean of `(cos + 1) / 2`, with task and every anchor vector made
/// by the same exact arm model. Degenerate vectors are generation failures.
pub(super) fn embed_similarity(task: &[f32], anchors: &[Vec<f32>], labels: &[EvalLabel]) -> Scored {
    let Some(total) = total_weight(labels) else {
        return Scored::Unavailable(MeasurementUnavailable::NoLabel);
    };
    if anchors.len() != labels.len() {
        return Scored::Unavailable(MeasurementUnavailable::GenerationFailed);
    }
    let mut weighted = 0.0;
    for (anchor, label) in anchors.iter().zip(labels) {
        let Some(cosine) = cosine(task, anchor) else {
            return Scored::Unavailable(MeasurementUnavailable::GenerationFailed);
        };
        weighted += label.weight * ((cosine + 1.0) / 2.0);
    }
    score(weighted / total)
}
