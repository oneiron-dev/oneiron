//! Offline WER and labelled-cohort E3 scoring. Pure functions, no models.
//!
//! These scorers run without any interpreter, weight, or credential. They take
//! caller-supplied reference/hypothesis token slices and labelled reference
//! maps, and return exact integer counts. Quality claims still need a measured
//! corpus run with pinned sources; scoring a fixture pair proves the scorer,
//! never that an engine default won a bake-off.

use std::collections::HashMap;

/// Exact word-error counts over caller-supplied tokens: substitutions,
/// deletions, insertions, and the reference length they were measured against.
/// Tokenization is the caller's; this helper never lowercases, strips
/// punctuation, or splits CJK text. Compare per-language arms with
/// [`aggregate_wer`] so a short arm cannot dilute a long one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WerCounts {
    pub substitutions: u64,
    pub deletions: u64,
    pub insertions: u64,
    pub reference_len: u64,
}

impl WerCounts {
    #[must_use]
    pub fn errors(&self) -> u64 {
        self.substitutions
            .saturating_add(self.deletions)
            .saturating_add(self.insertions)
    }
}

/// Levenshtein edit counts between a reference and a hypothesis token slice.
/// Exact `u64` counts only; no float division, so there is no rounding to
/// dispute. An empty reference with a non-empty hypothesis counts every
/// hypothesis token as an insertion; two empty slices score zero errors.
#[must_use]
pub fn wer_counts(reference: &[&str], hypothesis: &[&str]) -> WerCounts {
    let empty = WerCounts {
        substitutions: 0,
        deletions: 0,
        insertions: 0,
        reference_len: reference.len() as u64,
    };
    let mut previous: Vec<_> = (0..=hypothesis.len())
        .map(|n| WerCounts {
            insertions: n as u64,
            ..empty
        })
        .collect();
    let mut current = vec![empty; hypothesis.len() + 1];
    for (i, reference_token) in reference.iter().enumerate() {
        current[0] = WerCounts {
            deletions: i as u64 + 1,
            ..empty
        };
        for (j, hypothesis_token) in hypothesis.iter().enumerate() {
            let mut diagonal = previous[j];
            diagonal.substitutions += u64::from(reference_token != hypothesis_token);
            let mut deletion = previous[j + 1];
            deletion.deletions += 1;
            let mut insertion = current[j];
            insertion.insertions += 1;
            current[j + 1] = [diagonal, deletion, insertion]
                .into_iter()
                .min_by_key(WerCounts::errors)
                .unwrap_or(empty);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[hypothesis.len()]
}

/// Sum per-arm counts into one cohort total. Callers pass one [`WerCounts`]
/// per language arm so the aggregate keeps exact integer counts.
#[must_use]
pub fn aggregate_wer(arms: &[WerCounts]) -> WerCounts {
    let mut total = WerCounts {
        substitutions: 0,
        deletions: 0,
        insertions: 0,
        reference_len: 0,
    };
    for arm in arms {
        total.substitutions = total.substitutions.saturating_add(arm.substitutions);
        total.deletions = total.deletions.saturating_add(arm.deletions);
        total.insertions = total.insertions.saturating_add(arm.insertions);
        total.reference_len = total.reference_len.saturating_add(arm.reference_len);
    }
    total
}

/// Word-level global speaker attribution score, invariant to arbitrary cluster names.
/// This is not time-based DER and never performs speaker enrollment or names a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E3Score {
    pub correct: u64,
    pub wrong_speaker: u64,
    pub missing_words: u64,
    pub extra_words: u64,
}
/// Maximum-weight one-to-one global cluster mapping over aligned word IDs.
/// A new mapping is NOT chosen per chunk. More than16 speaker clusters refuses
/// explicitly, rather than an unbounded factorial search or fabricated result.
pub fn e3_score(
    words: &HashMap<String, String>,
    reference: &HashMap<String, String>,
) -> super::AudioResult<E3Score> {
    use std::collections::BTreeSet;
    let actual: Vec<_> = words
        .values()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let expected: Vec<_> = reference
        .values()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let n = actual.len().max(expected.len());
    if n > 16
        || words
            .iter()
            .chain(reference)
            .any(|(id, label)| id.is_empty() || label.is_empty())
    {
        return Err(super::AudioError::InvalidCohortManifest);
    }
    let mut weights = vec![vec![0u64; n]; n];
    let mut matched = 0u64;
    for (id, label) in words {
        if let Some(truth) = reference.get(id) {
            let i = actual
                .binary_search(&label)
                .map_err(|_| super::AudioError::InvalidCohortManifest)?;
            let j = expected
                .binary_search(&truth)
                .map_err(|_| super::AudioError::InvalidCohortManifest)?;
            weights[i][j] += 1;
            matched += 1;
        }
    }
    let mut best = vec![0u64; 1usize << n];
    for mask in 1usize..(1usize << n) {
        let row = mask.count_ones() as usize - 1;
        for col in 0..n {
            if mask & (1 << col) != 0 {
                best[mask] = best[mask].max(best[mask ^ (1 << col)] + weights[row][col]);
            }
        }
    }
    let correct = best[(1usize << n) - 1];
    Ok(E3Score {
        correct,
        wrong_speaker: matched - correct,
        missing_words: reference.len() as u64 - matched,
        extra_words: words.len() as u64 - matched,
    })
}
