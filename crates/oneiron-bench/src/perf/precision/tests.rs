//! Regressions for the ONE-1579 precision axis.
//!
//! Split out of `precision.rs` so the axis module itself stays well under the
//! repository's giant-file bar; nothing here is reachable outside `cfg(test)`.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::*;

fn corpus(rng: &mut StdRng, count: usize, dimensions: usize) -> Vec<Vec<f32>> {
    (0..count)
        .map(|_| {
            (0..dimensions)
                .map(|_| rng.gen_range(-1.0_f32..1.0))
                .collect()
        })
        .collect()
}

