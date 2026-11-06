//! Per-hunk mining of a partly unclear amendment (FIX 9808).
//!
//! The judgment keeps each changed hunk's label beside the retained ranges of
//! the substitutions that hunk made, at the miner's own extraction granularity
//! (FIX 11344). A judgment with an unclear share then mines only what its
//! clear hunks made; the unclear hunks stay held in the unclear ledger, and
//! nothing of theirs is taken, not even a substitution a clear hunk also made.

use std::collections::BTreeSet;

use super::mining::{line_substitutions, reconstructed_line_ranges, substitution_pair};
use super::model::Substitution;
use crate::edit_distance::attribution::{AmendmentClass, AmendmentJudgment, HunkRange};
use crate::edit_distance::{RetainedProposal, TextRead};
use crate::entity_id::EntityId;

/// The retained ranges of the substitutions one changed hunk made, at the
/// miner's own extraction granularity: each recorded change whose extracted
/// pair is one of the hunk's pairs. Empty when the hunk makes no substitution.
/// The judge records them beside the hunk's label; they are ranges, never the
/// hunk's text.
///
/// Both sides normalize at compare time: the hunk's pairs and each change's
/// pair come out of the same extractor, so a host cut that normalizes
/// differently from the recorded change still locates — the digest this
/// replaces compared pre-stored hashes and held the hunk instead.
pub(in crate::edit_distance) fn hunk_substitution_ranges(
    artifact: &RetainedProposal,
    before: &str,
    after: &str,
) -> Vec<HunkRange> {
    let hunk_pairs: Vec<Substitution> = substitution_pair(before, after)
        .into_iter()
        .chain(line_substitutions(before, after))
        .collect();
    if hunk_pairs.is_empty() {
        return Vec::new();
    }
    let found = artifact.record.artifact_ref.entity_id();
    let mut ranges: Vec<HunkRange> = artifact
        .record
        .ops_by_actor
        .iter()
        .filter_map(|(_, span)| {
            let (TextRead::Text(change_before), TextRead::Text(change_after)) =
                artifact.change_texts(span)
            else {
                return None;
            };
            let pair = substitution_pair(&change_before, &change_after)?;
            hunk_pairs
                .contains(&pair)
                .then(|| HunkRange::from_span(found, span))
        })
        .collect();
    ranges.sort();
    ranges.dedup();
    ranges
}

/// The endpoint-position ranges of the substitutions one changed hunk made
/// in a reconstructed re-diff (FIX 12715): each endpoint line pair whose
/// extracted pair is one of the hunk's pairs, through the ONE shared helper
/// [`reconstructed_line_ranges`], so the judge and the miner name the same
/// line. Empty when the hunk makes no substitution, when the endpoints pair
/// to nothing, or when the endpoint does not read — those hunks stay held,
/// as before. Ranges, never the hunk's text.
pub(in crate::edit_distance) fn reconstructed_hunk_ranges(
    artifact: EntityId,
    endpoint_before: &str,
    endpoint_after: &str,
    hunk_before: &str,
    hunk_after: &str,
) -> Vec<HunkRange> {
    let hunk_pairs: Vec<Substitution> = substitution_pair(hunk_before, hunk_after)
        .into_iter()
        .chain(line_substitutions(hunk_before, hunk_after))
        .collect();
    if hunk_pairs.is_empty() {
        return Vec::new();
    }
    let mut ranges: Vec<HunkRange> =
        reconstructed_line_ranges(artifact, endpoint_before, endpoint_after)
            .into_iter()
            .filter_map(|(pair, range)| {
                if hunk_pairs.contains(&pair) {
                    range
                } else {
                    None
                }
            })
            .collect();
    ranges.sort();
    ranges.dedup();
    ranges
}

/// The retained ranges the clear hunks of `judgment` made, or with `clear`
/// false its unclear hunks.
fn ranges_where(judgment: &AmendmentJudgment, clear: bool) -> BTreeSet<HunkRange> {
    judgment
        .hunks
        .iter()
        .filter(|hunk| (hunk.class != AmendmentClass::Unclear) == clear)
        .flat_map(|hunk| hunk.ranges.iter().copied())
        .collect()
}

/// Which of a judged amendment's substitutions the miner may take.
pub(super) enum MinableHunks {
    /// No share is unclear: every substitution the amendment shows.
    Whole,
    /// A share is unclear: only the substitutions at a range a clear hunk
    /// made and no unclear hunk did.
    Clear(BTreeSet<HunkRange>),
}

impl MinableHunks {
    /// What `judgment` lets the miner take, or `None` when it is held whole:
    /// every hunk unclear, or no clear hunk made a substitution of its own.
    pub(super) fn of(judgment: &AmendmentJudgment) -> Option<Self> {
        if judgment.share_of(AmendmentClass::Unclear) > 0.0 {
            let held = ranges_where(judgment, false);
            let clear: BTreeSet<HunkRange> = ranges_where(judgment, true)
                .into_iter()
                .filter(|range| !held.contains(range))
                .collect();
            (!clear.is_empty()).then_some(Self::Clear(clear))
        } else {
            Some(Self::Whole)
        }
    }

    /// Whether the miner may take the substitution at `range`: the whole
    /// window when no share is unclear, else only a range a clear hunk made
    /// and no unclear hunk did. A substitution with no range — when its
    /// text does not read — mines only with the whole window.
    pub(super) fn admits(&self, range: Option<&HunkRange>) -> bool {
        match self {
            Self::Whole => true,
            Self::Clear(ranges) => range.is_some_and(|range| ranges.contains(range)),
        }
    }
}
