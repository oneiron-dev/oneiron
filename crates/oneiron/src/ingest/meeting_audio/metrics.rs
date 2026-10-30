//! Offline WER and labelled-cohort E3 scoring. Pure functions, no models.
//!
//! These scorers run without any interpreter, weight, or credential. They take
//! caller-supplied reference/hypothesis token slices and labelled reference
//! maps, and return exact integer counts. Quality claims still need a measured
//! corpus run with pinned sources; scoring a fixture pair proves the scorer,
//! never that an engine default won a bake-off.
//!
//! Both scorers take any input size. Each also runs a step at a time
//! ([`WerAlignment`], [`E3Assignment`]) so a caller can stop at a deadline and
//! continue later; the only refusal is memory the working state cannot get.

use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use super::{AudioError, AudioResult};

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

/// `len` copies of `value`, or [`AudioError::ResourceFloor`] when memory for
/// them cannot be had.
fn try_filled<T: Clone>(len: usize, value: T) -> AudioResult<Vec<T>> {
    let mut filled = Vec::new();
    filled
        .try_reserve_exact(len)
        .map_err(|_| AudioError::ResourceFloor)?;
    filled.resize(len, value);
    Ok(filled)
}

/// One reference/hypothesis Levenshtein alignment, computed a reference row
/// at a time. Its memory is two rows of the hypothesis's length, whatever the
/// reference's; its time is one row per reference token. Every
/// [`WerAlignment::advance`] call takes the same two slices.
#[derive(Debug, Clone)]
pub struct WerAlignment {
    row: usize,
    empty: WerCounts,
    previous: Vec<WerCounts>,
    current: Vec<WerCounts>,
}

impl WerAlignment {
    /// An alignment of a `reference_len`-token reference against a
    /// `hypothesis_len`-token hypothesis, not yet started.
    ///
    /// # Errors
    /// [`AudioError::ResourceFloor`] when its two rows cannot be allocated.
    pub fn new(reference_len: usize, hypothesis_len: usize) -> AudioResult<Self> {
        let width = hypothesis_len
            .checked_add(1)
            .ok_or(AudioError::ResourceFloor)?;
        let empty = WerCounts {
            substitutions: 0,
            deletions: 0,
            insertions: 0,
            reference_len: reference_len as u64,
        };
        let mut previous = try_filled(width, empty)?;
        for (n, counts) in previous.iter_mut().enumerate() {
            counts.insertions = n as u64;
        }
        Ok(Self {
            row: 0,
            empty,
            previous,
            current: try_filled(width, empty)?,
        })
    }

    /// Runs reference rows until the alignment is complete, or `deadline`
    /// has passed after at least one row. The counts once complete; `None`
    /// while rows remain, to continue on the next call.
    pub fn advance(
        &mut self,
        reference: &[&str],
        hypothesis: &[&str],
        deadline: Option<Instant>,
    ) -> Option<WerCounts> {
        let empty = self.empty;
        while let Some(reference_token) = reference.get(self.row) {
            self.current[0] = WerCounts {
                deletions: self.row as u64 + 1,
                ..empty
            };
            for (j, hypothesis_token) in hypothesis.iter().enumerate() {
                let mut diagonal = self.previous[j];
                diagonal.substitutions += u64::from(reference_token != hypothesis_token);
                let mut deletion = self.previous[j + 1];
                deletion.deletions += 1;
                let mut insertion = self.current[j];
                insertion.insertions += 1;
                self.current[j + 1] = [diagonal, deletion, insertion]
                    .into_iter()
                    .min_by_key(WerCounts::errors)
                    .unwrap_or(empty);
            }
            std::mem::swap(&mut self.previous, &mut self.current);
            self.row += 1;
            if self.row < reference.len() && deadline.is_some_and(|at| Instant::now() >= at) {
                return None;
            }
        }
        self.previous.get(hypothesis.len()).copied()
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
    let mut alignment = WerAlignment {
        row: 0,
        empty,
        previous: (0..=hypothesis.len())
            .map(|n| WerCounts {
                insertions: n as u64,
                ..empty
            })
            .collect(),
        current: vec![empty; hypothesis.len() + 1],
    };
    alignment
        .advance(reference, hypothesis, None)
        .unwrap_or(empty)
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

/// An unreachable reduced cost: above any sum of real word counts.
const UNREACHED: i128 = i128::MAX / 4;

/// One meeting's maximum-weight one-to-one global cluster mapping, by the
/// Hungarian method over the square of the larger label set, assigned one
/// hypothesis cluster at a time: `n` steps of O(n²) work, and memory for the
/// n×n word-count weights. Exact for any number of clusters.
#[derive(Debug, Clone)]
pub struct E3Assignment {
    n: usize,
    /// Words with hypothesis cluster `i` and reference cluster `j`, at `i * n + j`.
    weights: Vec<u64>,
    /// Row and column potentials, the column each row's search came from,
    /// and the row (1-based, 0 for none) each column is assigned to.
    row_potential: Vec<i128>,
    column_potential: Vec<i128>,
    way: Vec<usize>,
    assigned: Vec<usize>,
    /// One row's search state, reused across rows.
    reduced: Vec<i128>,
    visited: Vec<bool>,
    row: usize,
    matched: u64,
    missing_words: u64,
    extra_words: u64,
}

impl E3Assignment {
    /// The assignment for hypothesis labels `words` against reference labels
    /// `reference`, both keyed by aligned word id, not yet started. A new
    /// mapping is NOT chosen per chunk.
    ///
    /// # Errors
    /// [`AudioError::InvalidCohortManifest`] for a blank word id or label;
    /// [`AudioError::ResourceFloor`] when the weights cannot be allocated.
    pub fn new(
        words: &HashMap<String, String>,
        reference: &HashMap<String, String>,
    ) -> AudioResult<Self> {
        if words
            .iter()
            .chain(reference)
            .any(|(id, label)| id.is_empty() || label.is_empty())
        {
            return Err(AudioError::InvalidCohortManifest);
        }
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
        let mut weights = try_filled(n.checked_mul(n).ok_or(AudioError::ResourceFloor)?, 0u64)?;
        let mut matched = 0u64;
        for (id, label) in words {
            if let Some(truth) = reference.get(id) {
                let i = actual
                    .binary_search(&label)
                    .map_err(|_| AudioError::InvalidCohortManifest)?;
                let j = expected
                    .binary_search(&truth)
                    .map_err(|_| AudioError::InvalidCohortManifest)?;
                weights[i * n + j] += 1;
                matched += 1;
            }
        }
        let width = n + 1;
        Ok(Self {
            n,
            weights,
            row_potential: try_filled(width, 0)?,
            column_potential: try_filled(width, 0)?,
            way: try_filled(width, 0)?,
            assigned: try_filled(width, 0)?,
            reduced: try_filled(width, UNREACHED)?,
            visited: try_filled(width, false)?,
            row: 0,
            matched,
            missing_words: reference.len() as u64 - matched,
            extra_words: words.len() as u64 - matched,
        })
    }

    /// Assigns hypothesis clusters until every one is, or `deadline` has
    /// passed after at least one. The score once complete; `None` while
    /// clusters remain, to continue on the next call.
    pub fn advance(&mut self, deadline: Option<Instant>) -> Option<E3Score> {
        let n = self.n;
        while self.row < n {
            // Rows and columns are 1-based here; column 0 holds the row
            // being placed.
            self.assigned[0] = self.row + 1;
            self.reduced.fill(UNREACHED);
            self.visited.fill(false);
            let mut column = 0;
            loop {
                self.visited[column] = true;
                let row = self.assigned[column];
                let mut delta = UNREACHED;
                let mut next = 0;
                for j in 1..=n {
                    if self.visited[j] {
                        continue;
                    }
                    let cost = -i128::from(self.weights[(row - 1) * n + (j - 1)])
                        - self.row_potential[row]
                        - self.column_potential[j];
                    if cost < self.reduced[j] {
                        self.reduced[j] = cost;
                        self.way[j] = column;
                    }
                    if self.reduced[j] < delta {
                        delta = self.reduced[j];
                        next = j;
                    }
                }
                for j in 0..=n {
                    if self.visited[j] {
                        let assigned = self.assigned[j];
                        self.row_potential[assigned] += delta;
                        self.column_potential[j] -= delta;
                    } else {
                        self.reduced[j] -= delta;
                    }
                }
                column = next;
                if self.assigned[column] == 0 {
                    break;
                }
            }
            while column != 0 {
                let previous = self.way[column];
                self.assigned[column] = self.assigned[previous];
                column = previous;
            }
            self.row += 1;
            if self.row < n && deadline.is_some_and(|at| Instant::now() >= at) {
                return None;
            }
        }
        let correct = (1..=n)
            .filter(|&j| self.assigned[j] != 0)
            .map(|j| self.weights[(self.assigned[j] - 1) * n + (j - 1)])
            .fold(0u64, u64::saturating_add);
        Some(E3Score {
            correct,
            wrong_speaker: self.matched - correct,
            missing_words: self.missing_words,
            extra_words: self.extra_words,
        })
    }
}

/// Maximum-weight one-to-one global cluster mapping over aligned word IDs,
/// exact for any number of speaker clusters ([`E3Assignment`] run whole).
/// A new mapping is NOT chosen per chunk.
///
/// # Errors
/// As [`E3Assignment::new`].
pub fn e3_score(
    words: &HashMap<String, String>,
    reference: &HashMap<String, String>,
) -> AudioResult<E3Score> {
    let mut assignment = E3Assignment::new(words, reference)?;
    loop {
        if let Some(score) = assignment.advance(None) {
            return Ok(score);
        }
    }
}
