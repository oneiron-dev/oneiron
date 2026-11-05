//! One positive temperature fitted without the held-out answers.

use serde::Serialize;

pub(super) const ECE_BINS: usize = 10;
const FIT_STEPS: usize = 96;

#[derive(Serialize)]
pub(super) struct Fit {
    pub(super) temperature: f64,
    cases: usize,
    mean_nll: f64,
    uncalibrated_mean_nll: f64,
    method: &'static str,
    steps: usize,
}

fn sigmoid(margin: f64) -> f64 {
    if margin >= 0.0 {
        1.0 / (1.0 + (-margin).exp())
    } else {
        let exp = margin.exp();
        exp / (1.0 + exp)
    }
}

pub(super) fn yes_probability(logits: [f64; 2], temperature: f64) -> f64 {
    sigmoid((logits[1] - logits[0]) / temperature)
}

fn nll(rows: &[([f64; 2], bool)], temperature: f64) -> f64 {
    rows.iter()
        .map(|(logits, yes)| {
            let margin = (logits[1] - logits[0]) / temperature;
            let wrong = if *yes { -margin } else { margin };
            wrong.max(0.0) + (-wrong.abs()).exp().ln_1p()
        })
        .sum::<f64>()
        / rows.len() as f64
}

/// Binary NLL is convex in inverse temperature. Normalize margins, bracket
/// its monotone derivative, then bisect. Flat or boundary optima are kept
/// within the representable normal-temperature range. T=1 is also scored
/// and wins a tied objective; it is never reported as an unmeasured fit.
pub(super) fn fit(rows: &[([f64; 2], bool)]) -> Fit {
    let scale = rows
        .iter()
        .map(|(logits, _)| (logits[1] - logits[0]).abs())
        .fold(0.0_f64, f64::max);
    let normalized: Vec<_> = rows
        .iter()
        .map(|(logits, yes)| {
            (
                if scale == 0.0 {
                    0.0
                } else {
                    (logits[1] - logits[0]) / scale
                },
                *yes,
            )
        })
        .collect();
    let derivative = |inverse: f64| -> f64 {
        normalized
            .iter()
            .map(|&(margin, yes)| (sigmoid(margin * inverse) - f64::from(u8::from(yes))) * margin)
            .sum::<f64>()
            / normalized.len() as f64
    };
    let mut steps = 0;
    let maximum_temperature = 1.0 / f64::MIN_POSITIVE;
    let fitted = if scale == 0.0 {
        1.0
    } else if derivative(0.0) >= 0.0 {
        maximum_temperature
    } else {
        let mut lower = 0.0;
        let mut upper = 1.0;
        while derivative(upper) < 0.0 && upper < f64::MAX / 2.0 {
            lower = upper;
            upper *= 2.0;
            steps += 1;
        }
        for _ in 0..FIT_STEPS {
            let middle = lower + (upper - lower) / 2.0;
            if derivative(middle) < 0.0 {
                lower = middle;
            } else {
                upper = middle;
            }
        }
        steps += FIT_STEPS;
        (scale / (lower + (upper - lower) / 2.0)).clamp(f64::MIN_POSITIVE, maximum_temperature)
    };
    let fitted_loss = nll(rows, fitted);
    let neutral_loss = nll(rows, 1.0);
    let (temperature, mean_nll) = if fitted_loss < neutral_loss {
        (fitted, fitted_loss)
    } else {
        (1.0, neutral_loss)
    };
    Fit {
        temperature,
        cases: rows.len(),
        mean_nll,
        uncalibrated_mean_nll: neutral_loss,
        method: "training-mean-binary-nll/inverse-temperature/bisection/neutral-on-tie/1",
        steps,
    }
}

/// Binary Brier and equal-width reliability ECE, not confidence-accuracy ECE.
/// P(yes)=1 belongs to the last bin; empty bins contribute zero.
pub(super) fn metrics(rows: &[(f64, bool)]) -> (f64, f64) {
    let mut brier = 0.0;
    let mut bins = [(0.0, 0.0); ECE_BINS];
    for &(probability, yes) in rows {
        let label = f64::from(u8::from(yes));
        brier += (probability - label).powi(2);
        let index = ((probability * ECE_BINS as f64) as usize).min(ECE_BINS - 1);
        bins[index].0 += probability;
        bins[index].1 += label;
    }
    let count = rows.len() as f64;
    let ece = bins
        .iter()
        .map(|&(predicted, actual)| (predicted - actual).abs() / count)
        .sum();
    (brier / count, ece)
}
