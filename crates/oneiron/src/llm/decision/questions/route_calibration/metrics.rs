//! Weighted binary calibration of one half, and the accepted error and coverage at each cut
//! of a fitted map.

use super::{AcceptanceAtCut, CalibrationMetrics, MapKnot};

/// The equal-width reliability bins of a binary calibration error, one count shared by the
/// per-seat question evaluation and the per-route report so their errors compare.
pub const ECE_BINS: usize = 10;

/// The calibration of `rows`, each (P(label), label, weight): see [`CalibrationMetrics`].
/// P = 1 belongs to the last bin; empty bins add nothing. `None` when nothing weighs anything.
pub(super) fn calibration(
    rows: impl IntoIterator<Item = (f64, bool, f64)>,
) -> Option<CalibrationMetrics> {
    let mut total = 0.0;
    let mut squared = 0.0;
    let mut bins = [(0.0_f64, 0.0_f64); ECE_BINS];
    for (probability, label, weight) in rows {
        let yes = f64::from(u8::from(label));
        total += weight;
        squared += weight * (probability - yes).powi(2);
        let index = ((probability * ECE_BINS as f64) as usize).min(ECE_BINS - 1);
        bins[index].0 += weight * probability;
        bins[index].1 += weight * yes;
    }
    if total <= 0.0 {
        return None;
    }
    let error = bins
        .iter()
        .map(|&(predicted, actual)| (predicted - actual).abs())
        .sum::<f64>()
        / total;
    Some(CalibrationMetrics {
        brier_score: squared / total,
        calibration_error: error,
    })
}

/// One check pair as the acceptance table reads it: the map's fitted confidence in its own
/// answer (none for an abstention), whether that answer was right, and its label weight.
pub(super) struct Judged {
    pub(super) confidence: Option<f64>,
    pub(super) right: bool,
    pub(super) weight: f64,
}

/// Accepted error and coverage at each cut `knots` define: each distinct fitted level, in
/// ascending order, beside the lowest raw probability fitted to it. Empty when `judged`
/// weighs nothing.
pub(super) fn acceptance(knots: &[MapKnot], judged: &[Judged]) -> Vec<AcceptanceAtCut> {
    let total: f64 = judged.iter().map(|one| one.weight).sum();
    if total <= 0.0 {
        return Vec::new();
    }
    let mut cuts: Vec<MapKnot> = Vec::new();
    for knot in knots {
        if cuts.last().is_none_or(|held| held.fitted != knot.fitted) {
            cuts.push(*knot);
        }
    }
    cuts.into_iter()
        .map(|cut| {
            let mut accepted = 0;
            let mut weight = 0.0;
            let mut wrong = 0.0;
            for one in judged {
                if one
                    .confidence
                    .is_some_and(|confidence| confidence >= cut.fitted)
                {
                    accepted += 1;
                    weight += one.weight;
                    if !one.right {
                        wrong += one.weight;
                    }
                }
            }
            AcceptanceAtCut {
                cut: cut.fitted,
                raw: cut.raw,
                accepted,
                coverage: weight / total,
                accepted_error: (weight > 0.0).then_some(wrong / weight),
            }
        })
        .collect()
}
