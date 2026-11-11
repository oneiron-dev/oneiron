//! A weighted pool-adjacent-violators fit: the non-decreasing map from a raw probability to a
//! label rate that fits the fit half best in weighted squared error.

use super::MapKnot;

/// One pooled run of raw probabilities: the lowest and highest, the label weight and the
/// weight of its yes labels. Its label rate is their ratio; its weight is never zero.
struct Block {
    low: f64,
    high: f64,
    weight: f64,
    yes: f64,
}

/// The isotonic map of `points`, each (raw probability, label, weight), as its knots (see
/// [`super::RouteCalibrationMap::knots`]). Every point of one raw probability pools first,
/// whatever order the points were read in; then pool-adjacent-violators runs across the
/// distinct probabilities: each level pools into the block before it while that block's label
/// rate is not below its own. A point that weighs nothing is left out. Empty when nothing
/// weighs anything.
pub(super) fn fit(points: &[(f64, bool, f64)]) -> Vec<MapKnot> {
    let mut sorted: Vec<(f64, bool, f64)> = points
        .iter()
        .copied()
        .filter(|&(_, _, weight)| weight > 0.0)
        .collect();
    sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut levels: Vec<Block> = Vec::new();
    for (probability, label, weight) in sorted {
        let yes = if label { weight } else { 0.0 };
        match levels.last_mut() {
            Some(last) if last.high.total_cmp(&probability).is_eq() => {
                last.weight += weight;
                last.yes += yes;
            }
            _ => levels.push(Block {
                low: probability,
                high: probability,
                weight,
                yes,
            }),
        }
    }
    let mut blocks: Vec<Block> = Vec::new();
    for level in levels {
        blocks.push(level);
        while blocks.len() >= 2 {
            let (earlier, later) = (&blocks[blocks.len() - 2], &blocks[blocks.len() - 1]);
            // Cross-multiplied rates: both weights are positive.
            if earlier.yes * later.weight < later.yes * earlier.weight {
                break;
            }
            let Some(later) = blocks.pop() else {
                break;
            };
            let Some(earlier) = blocks.last_mut() else {
                break;
            };
            earlier.high = later.high;
            earlier.weight += later.weight;
            earlier.yes += later.yes;
        }
    }
    let mut knots = Vec::with_capacity(blocks.len() * 2);
    for block in &blocks {
        let fitted = block.yes / block.weight;
        knots.push(MapKnot {
            raw: block.low,
            fitted,
        });
        if block.high > block.low {
            knots.push(MapKnot {
                raw: block.high,
                fitted,
            });
        }
    }
    knots
}

/// The probability `knots` fit `raw` to: the line between the two knots around it, the
/// nearest end knot's fitted value outside them, and `raw` itself for a map with no knots.
pub(super) fn apply(knots: &[MapKnot], raw: f64) -> f64 {
    let (Some(first), Some(last)) = (knots.first(), knots.last()) else {
        return raw;
    };
    if raw <= first.raw {
        return first.fitted;
    }
    for pair in knots.windows(2) {
        let (below, above) = (pair[0], pair[1]);
        if raw <= above.raw {
            let share = (raw - below.raw) / (above.raw - below.raw);
            return below.fitted + (above.fitted - below.fitted) * share;
        }
    }
    last.fitted
}
