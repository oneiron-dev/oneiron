//! The gaps that refuse the fold past an adopted image (FIX
//! [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]). The live fold refuses only for
//! the gaps the rows this install believes rest on; an image-grade capture
//! counts every tail row it is handed ([`parent_gaps`]).

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The gaps that refuse the fold of `tail` past `image`, `required_gaps`
/// among them, the tail rows the fold settles, and the rows it drops, with
/// their entries for [`keep_dropped_verdicts`]. None `believed`: every tail
/// row counts. Otherwise only the gaps the believed rows rest on refuse the
/// fold. The tail rows above any other gap drop out of what the fold
/// settles: invalid, as the stored log's fold holds the rows above a gap
/// ([`keep_dropped_verdicts`]). No believed row rests on a dropped row, since
/// its walk would have reached that row's gap.
pub(super) fn refusing_gaps<'e>(
    image: &AuthorityCheckpointV2,
    tail: BTreeMap<AuthorityEntryHash, &'e AuthorityLogEntry>,
    believed: Option<&BTreeSet<AuthorityEntryHash>>,
    required_gaps: Vec<AuthorityEntryHash>,
) -> (
    BTreeSet<AuthorityEntryHash>,
    BTreeMap<AuthorityEntryHash, &'e AuthorityLogEntry>,
    BTreeMap<AuthorityEntryHash, &'e AuthorityLogEntry>,
) {
    match believed {
        None => {
            let gaps: BTreeSet<_> = parent_gaps(image, &tail)
                .into_iter()
                .chain(required_gaps)
                .collect();
            (gaps, tail, BTreeMap::new())
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
            let mut settled = BTreeMap::new();
            let mut dropped_entries = BTreeMap::new();
            for (hash, entry) in tail {
                if dropped.contains(&hash) {
                    dropped_entries.insert(hash, entry);
                } else {
                    settled.insert(hash, entry);
                }
            }
            (gaps, settled, dropped_entries)
        }
    }
}

/// Gives each `dropped` row its verdict where the stored log's fold
/// reports it: after the settlement's `settled` issues, before the
/// projection's own (#9476 review round 1). A dropped row that fails the
/// stored fold's pre-scheduling checks keeps `InvalidEntry`: a bad signature
/// (`verify_entry_signatures`, `fold_engine::judged_entries`) or a parent on
/// another world's side branch (`world_privacy::side_branch_violations`, with
/// the image's recorded worlds for covered parents). Any other dropped row
/// keeps `InvalidAncestry`, as a row whose parent never folds does
/// (`fold_schedule`, #9476 review round 2 finding 2).
pub(super) fn keep_dropped_verdicts(
    fold: &mut AuthorityFold,
    settled: usize,
    dropped: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    image: &AuthorityCheckpointV2,
) {
    // The well-signed tail for the side-branch check, as `judged_entries`
    // builds it: badly signed rows never put a scope fault on another row.
    let mut by_hash: BTreeMap<AuthorityEntryHash, AuthorityLogEntry> = BTreeMap::new();
    for (hash, entry) in tail.iter().chain(dropped.iter()) {
        if super::super::verify_entry_signatures(entry).is_ok() {
            by_hash.insert(*hash, (*entry).clone());
        }
    }
    let violations = super::super::world_privacy::side_branch_violations(&by_hash);
    let projected = fold.issues.split_off(settled.min(fold.issues.len()));
    fold.issues.extend(dropped.iter().map(|(hash, entry)| {
        if !by_hash.contains_key(hash)
            || violations.contains(hash)
            || image_scope_violates(image, entry)
        {
            AuthorityFoldIssue::InvalidEntry(*hash)
        } else {
            AuthorityFoldIssue::InvalidAncestry(*hash)
        }
    }));
    fold.issues.extend(projected);
}

/// Whether `entry` names a covered side-branch row of another world as a
/// parent, by the image's recorded worlds and `side_world`: the covered half
/// of the scope check the settled tail's judge runs for settled rows.
fn image_scope_violates(image: &AuthorityCheckpointV2, entry: &AuthorityLogEntry) -> bool {
    let world = super::super::world_privacy::side_world(&entry.op);
    entry.parent_hashes.iter().any(|parent| {
        image
            .rows
            .get(parent)
            .and_then(|row| row.world)
            .is_some_and(|parent_world| world != Some(parent_world))
    })
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
