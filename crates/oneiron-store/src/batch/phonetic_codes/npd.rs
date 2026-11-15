//! Normalized Phonetic Distance (CROSS-ARCH-0013 `#problem`, `#ladder`
//! rung 1): the phoneme edit distance between two readings divided by the
//! query's length, with each substitution weighted by how far apart the two
//! segments' PanPhon features are, so b/p and l/r are near.

use super::features::{FEATURE_COUNT, Segment};

/// A candidate further than this from the query is no sound match
/// (CROSS-ARCH-0013 `#problem`: "threshold ≈ 0.2").
pub const NPD_THRESHOLD: f32 = 0.2;

/// Candidates within this multiple of the best candidate's distance are kept
/// (CROSS-ARCH-0013 `#problem`: "keep candidates within 1.2× the best").
pub const NPD_KEEP_RATIO: f32 = 1.2;

/// At most this many candidates are kept (CROSS-ARCH-0013 `#problem`:
/// "capped at 10").
pub const NPD_CAP: usize = 10;

/// The Normalized Phonetic Distance from `query` to `candidate`: a
/// Levenshtein distance where an insertion or a deletion costs 1 and a
/// substitution costs the share of PanPhon features the two segments differ
/// in (a feature that is `+` in one and `-` in the other counts 1, one that
/// is unspecified in only one of them counts 0.5), divided by the query's
/// segment count. Equal readings are 0.
pub fn npd(query: &[Segment], candidate: &[Segment]) -> f32 {
    let mut previous: Vec<f32> = (0..=candidate.len()).map(|index| index as f32).collect();
    let mut current = vec![0.0; candidate.len() + 1];
    for (row, query_segment) in query.iter().enumerate() {
        current[0] = (row + 1) as f32;
        for (column, candidate_segment) in candidate.iter().enumerate() {
            let substitute =
                previous[column] + substitution_cost(*query_segment, *candidate_segment);
            let delete = previous[column + 1] + 1.0;
            let insert = current[column] + 1.0;
            current[column + 1] = substitute.min(delete).min(insert);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[candidate.len()] / query.len().max(1) as f32
}

/// The cost of reading `a` as `b`: 0 for the same segment, 1 for segments
/// opposite in every feature.
fn substitution_cost(a: Segment, b: Segment) -> f32 {
    let half_steps: u32 = a
        .features()
        .iter()
        .zip(b.features())
        .map(|(x, y)| match (x, y) {
            _ if x == y => 0,
            (b'0', _) | (_, b'0') => 1,
            _ => 2,
        })
        .sum();
    half_steps as f32 / (2 * FEATURE_COUNT) as f32
}
