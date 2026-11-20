//! Moved from `crates/oneiron/src/learning/frozen.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::learning_estimate::OwnTally;
use oneiron_verb_wire::claim::learning_evidence::Observation;

/// The same numerical accumulation for live evidence and its frozen snapshot.
pub fn accumulate(tally: &mut OwnTally, observation: &Observation, w: f64) -> bool {
    match (tally, observation) {
        (OwnTally::Beta { wins, losses }, Observation::Success(ok)) => {
            if *ok {
                *wins += w;
            } else {
                *losses += w;
            }
        }
        (OwnTally::Beta { wins, losses }, Observation::Magnitude(score)) => {
            let score = score.clamp(0.0, 1.0);
            *wins += w * score;
            *losses += w * (1.0 - score);
        }
        (
            OwnTally::Mean {
                sum_w,
                sum_wx,
                sum_wxx,
            },
            Observation::Magnitude(x),
        ) => {
            *sum_w += w;
            *sum_wx += w * x;
            *sum_wxx += w * x * x;
        }
        (OwnTally::Counts { counts }, Observation::Category(name)) => {
            *counts.entry(name.clone()).or_insert(0.0) += w;
        }
        _ => return false,
    }
    true
}
