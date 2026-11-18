//! The gaps that refuse the fold past an adopted image (FIX
//! [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]). The live fold refuses only for
//! the gaps the rows this install believes rest on; an image-grade capture
//! counts every tail row it is handed ([`parent_gaps`]).

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The gaps that refuse the fold of `tail` past `image`, `required_gaps`
/// among them, and the tail rows the fold settles. None `believed`: every
/// tail row counts. Otherwise only the gaps the believed rows rest on refuse
/// the fold. The tail rows above any other gap drop out of what the fold
/// settles: invalid, as the stored log's fold holds the rows above a gap. No
/// believed row rests on a dropped row, since its walk would have reached
/// that row's gap.
pub(super) fn refusing_gaps<'e>(
    image: &AuthorityCheckpointV2,
    tail: BTreeMap<AuthorityEntryHash, &'e AuthorityLogEntry>,
    believed: Option<&BTreeSet<AuthorityEntryHash>>,
    required_gaps: Vec<AuthorityEntryHash>,
) -> (
    BTreeSet<AuthorityEntryHash>,
    BTreeMap<AuthorityEntryHash, &'e AuthorityLogEntry>,
) {
    match believed {
        None => {
            let gaps: BTreeSet<_> = parent_gaps(image, &tail)
                .into_iter()
                .chain(required_gaps)
                .collect();
            (gaps, tail)
        }
        Some(believed) => {
            let gaps: BTreeSet<_> = believed_tail_gaps(image, &tail, believed)
                .into_iter()
                .chain(required_gaps)
                .collect();
            let unbelieved: BTreeSet<_> = parent_gaps(image, &tail)
                .difference(&gaps)
                .copied()
                .collect();
            let dropped = rows_above_gaps(&tail, &unbelieved);
            let tail: BTreeMap<_, _> = tail
                .into_iter()
                .filter(|(hash, _)| !dropped.contains(hash))
                .collect();
            (gaps, tail)
        }
    }
}

/// The parents the tail rows name that the image does not cover and the tail
/// does not hold.
pub(super) fn parent_gaps(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> BTreeSet<AuthorityEntryHash> {
    tail.values()
        .flat_map(|entry| entry.parent_hashes.iter())
        .filter(|parent| !image.rows.contains_key(*parent) && !tail.contains_key(*parent))
        .copied()
        .collect()
}

/// The gaps the `believed` tail rows rest on: walking down from their
/// parents through tail rows, whoever signed them, every hash the image does
/// not cover and the tail does not hold. A believed row rests on every row
/// below it, so a gap under a stranger's row that a believed row names still
/// counts (FIX [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]).
fn believed_tail_gaps(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    believed: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut below: Vec<AuthorityEntryHash> = believed
        .iter()
        .filter_map(|hash| tail.get(hash))
        .flat_map(|entry| entry.parent_hashes.iter().copied())
        .collect();
    let mut walked = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    while let Some(hash) = below.pop() {
        if !walked.insert(hash) {
            continue;
        }
        if let Some(entry) = tail.get(&hash) {
            below.extend(entry.parent_hashes.iter().copied());
        } else if !image.rows.contains_key(&hash) {
            gaps.insert(hash);
        }
    }
    gaps
}

/// The tail rows that rest, through tail rows, on one of `gaps`.
fn rows_above_gaps(
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    gaps: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut children: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>> = BTreeMap::new();
    for (hash, entry) in tail {
        for parent in &entry.parent_hashes {
            children.entry(*parent).or_default().push(*hash);
        }
    }
    let mut above = BTreeSet::new();
    let mut stack: Vec<AuthorityEntryHash> = gaps.iter().copied().collect();
    while let Some(hash) = stack.pop() {
        for child in children.get(&hash).into_iter().flatten() {
            if above.insert(*child) {
                stack.push(*child);
            }
        }
    }
    above
}
