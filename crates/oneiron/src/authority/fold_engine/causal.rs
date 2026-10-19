//! Whether a row names a hash beneath its own parents: the one structural
//! "beneath these parents" predicate a world key record's request is judged
//! by (FIX 5464, CALLS "FIX 5464 request binding", "FIX 5464 presence
//! proof").
//!
//! This is topology, never authority: it reads which rows the record's
//! parents descend from, as the whole log's ancestor index
//! (`ancestor_index::entry_ancestor_index`) reads them, and nothing of any
//! row's fold state. What the request may do on the owner's behalf is still
//! read from the merged parent state alone (`world_key_fold::counts`).
//!
//! A fold that holds the whole log's index answers from it. A fold that holds
//! only its base's row summaries (a resumed fold, a fold past an adopted
//! image) walks them from the row's parents, with each row read at most once.
//! A walk that meets a row it holds no summary of cannot tell absence from
//! presence: it answers "not shown" and marks its past incomplete, and the
//! continuation that walked it declines, so the whole history judges the row.
//! An unknown walk never counts as present.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::*;

/// The parents a fold with no whole-log ancestor index reads of a row, as
/// that index reads them.
pub(in crate::authority) trait ParentSummaries {
    /// `Some(parents)` of a row the index walks through, `Some(&[])` of a row
    /// it names but never walks through (one no fold judges), and `None`
    /// where this fold holds no summary to tell.
    fn parents_of(&self, hash: &AuthorityEntryHash) -> Option<&[AuthorityEntryHash]>;
}

/// A fold past an adopted image reads a row's parents from the judged tail
/// and the image's row summaries. A tail record folds only on rows with a
/// state, so its walk reaches covered rows only beneath a frontier row the
/// image kept a state at, all of which the image's fold judged; a frontier
/// row the image holds no state at shows nothing, and the walk is then
/// incomplete (the image's history guard decides it). Any row neither judged
/// in the tail nor covered shows nothing either.
pub(in crate::authority) struct ImagePast<'a> {
    pub(in crate::authority) image: &'a AuthorityCheckpointV2,
    pub(in crate::authority) judged: &'a BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
}

impl ParentSummaries for ImagePast<'_> {
    fn parents_of(&self, hash: &AuthorityEntryHash) -> Option<&[AuthorityEntryHash]> {
        if let Some(entry) = self.judged.get(hash) {
            return Some(entry.parent_hashes.as_slice());
        }
        if matches!(self.image.per_parent.get(hash), Some(None)) {
            return None;
        }
        self.image.rows.get(hash).map(|row| row.parents.as_slice())
    }
}

/// A continuation fold's row summaries, and whether some walk over them met
/// a row they hold no summary of.
pub(in crate::authority) struct CausalPast<'a> {
    summaries: &'a dyn ParentSummaries,
    incomplete: Cell<bool>,
}

impl<'a> CausalPast<'a> {
    pub(in crate::authority) fn new(summaries: &'a dyn ParentSummaries) -> Self {
        Self {
            summaries,
            incomplete: Cell::new(false),
        }
    }

    /// Whether some walk could not finish: the fold that walked it declines,
    /// and the whole history judges its rows.
    pub(in crate::authority) fn incomplete(&self) -> bool {
        self.incomplete.get()
    }

    /// Whether `target` is among `parents` or beneath one, breadth first so a
    /// recent row is found near the parents. A row met is counted before its
    /// summary is read, as the whole-log index counts it.
    fn reaches(&self, parents: &[AuthorityEntryHash], target: &AuthorityEntryHash) -> bool {
        let mut seen = BTreeSet::new();
        let mut queue: VecDeque<AuthorityEntryHash> = parents.iter().copied().collect();
        let mut complete = true;
        while let Some(at) = queue.pop_front() {
            if at == *target {
                return true;
            }
            if !seen.insert(at) {
                continue;
            }
            match self.summaries.parents_of(&at) {
                Some(parents) => queue.extend(parents.iter().copied()),
                None => complete = false,
            }
        }
        if !complete {
            self.incomplete.set(true);
        }
        false
    }
}

/// Whether `target` is a parent of `entry`, the row signed as `hash`, or
/// beneath one: a direct parent always is; otherwise the fold's whole-log
/// ancestor index answers when it holds the row, and a continuation's row
/// summaries are walked from the row's parents. With neither, only a direct
/// parent shows, as before any walk existed. Only a complete walk's "no" is
/// an absence; an incomplete one marks the continuation's past incomplete.
pub(in crate::authority) fn named_beneath(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    target: &AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    if entry.parent_hashes.contains(target) {
        return true;
    }
    if let Some(past) = context.entry_ancestors.and_then(|index| index.get(&hash)) {
        return past.contains(target);
    }
    context
        .causal_past
        .is_some_and(|causal| causal.reaches(&entry.parent_hashes, target))
}
