//! The fit and check halves of a question's pairs, by source case. Pairs that share an answer
//! or an outcome fact are one case: a person's change of an answer and the answer's own pair,
//! or two answers of the question judged by one fact. A shared subject or source does not join
//! cases, since one subject (the owner) or one source may stand behind a question's every
//! fact and would put every pair on one side. A case's side is a deterministic hash of the
//! question and the case's least row, so the variants of one case, in every route group, fall
//! on one side.

use std::collections::BTreeMap;

use crate::EntityId;
use crate::llm::decision::questions::CalibrationPair;

/// The split hash's domain.
const SPLIT_DOMAIN: &[u8] = b"oneiron.route-calibration.split.v1";

/// Each pair's side, in pair order: `true` on the fit half.
pub(super) fn fit_sides(question: EntityId, pairs: &[CalibrationPair]) -> Vec<bool> {
    let mut parent: Vec<usize> = (0..pairs.len()).collect();
    // Each case row and the first pair that names it.
    let mut named: BTreeMap<EntityId, usize> = BTreeMap::new();
    for (index, pair) in pairs.iter().enumerate() {
        for row in case_rows(question, pair) {
            match named.get(&row) {
                Some(&first) => join(&mut parent, index, first),
                None => {
                    named.insert(row, index);
                }
            }
        }
    }
    // Rows in ascending order: the first one met for a case is its least.
    let mut least: BTreeMap<usize, EntityId> = BTreeMap::new();
    for (row, first) in &named {
        let case = root(&mut parent, *first);
        least.entry(case).or_insert(*row);
    }
    (0..pairs.len())
        .map(|index| {
            let case = root(&mut parent, index);
            least
                .get(&case)
                .is_some_and(|row| on_fit_side(question, *row))
        })
        .collect()
}

/// The rows that make `pair` one case with another: its answer and its outcome fact.
fn case_rows(question: EntityId, pair: &CalibrationPair) -> impl Iterator<Item = EntityId> {
    [pair.outcome.answer, pair.outcome.fact]
        .into_iter()
        .filter(move |row| *row != question)
}

/// Whether the case whose least row is `row` falls on the fit half: the low bit of the first
/// byte of the hash of the domain, the question and the row.
fn on_fit_side(question: EntityId, row: EntityId) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SPLIT_DOMAIN);
    hasher.update(question.as_bytes());
    hasher.update(row.as_bytes());
    (hasher.finalize().as_bytes()[0] & 1) == 0
}

/// The case `at` belongs to: the least pair index in it, halving the path on the way.
fn root(parent: &mut [usize], mut at: usize) -> usize {
    while parent[at] != at {
        parent[at] = parent[parent[at]];
        at = parent[at];
    }
    at
}

/// One case of the cases of pairs `a` and `b`, under the lesser root.
fn join(parent: &mut [usize], a: usize, b: usize) {
    let (a, b) = (root(parent, a), root(parent, b));
    if a != b {
        parent[a.max(b)] = a.min(b);
    }
}
