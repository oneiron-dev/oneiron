//! Byte-range arithmetic of reader coverage (ARCH-0079 #reader-forks): the
//! ranges a fold receipt counts as read, merged, and what of a source they
//! leave.
//!
//! A scoped child's job row also keeps a witness of the bytes of its primary
//! source that its reads were shown (FIX 7735). The host commits a range to
//! it only after the reply that showed the range passed every check, and
//! only while the job is live at the claim it was read under. A fold counts
//! the witness of a settled job, never the job's finding alone.

use serde::{Deserialize, Serialize};

use super::ReaderJob;
use crate::EntityId;

/// The bytes of its primary source that successful reads showed one scoped
/// child (FIX 7735), as its job row keeps them. It is bound to the claim it
/// was committed under (`generation`), the parent run, the child cutoff and
/// the source occurrence (`owner`, `path`, `handle`). `ranges` are merged,
/// in the source's whole-body offsets, inside the job's delegated range.
///
/// Only a facet reply that shows body bytes adds a range. A card, an asked
/// range, a search's scan, a lent input and a finding add none. A claim
/// starts with no witness, the job's settlement freezes it, and a job that
/// settles from its queue keeps none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDeliveryWitness {
    pub generation: u32,
    pub parent_run: EntityId,
    pub cutoff_unix_ms: u64,
    pub owner: EntityId,
    pub path: String,
    pub handle: String,
    pub ranges: Vec<(u64, u64)>,
}

impl SourceDeliveryWitness {
    /// An empty witness of `job`'s current claim: its generation, its parent
    /// run, its cutoff and its primary source.
    pub(crate) fn of_claim(job: &ReaderJob) -> Self {
        let source = &job.binding.source;
        Self {
            generation: job.generation,
            parent_run: job.binding.parent_run,
            cutoff_unix_ms: job.binding.child_cutoff_unix_ms,
            owner: source.owner,
            path: source.path.clone(),
            handle: source.handle.clone(),
            ranges: Vec::new(),
        }
    }

    /// Whether it is bound to `job`: the same parent run, child cutoff and
    /// primary source occurrence.
    fn binds(&self, job: &ReaderJob) -> bool {
        let source = &job.binding.source;
        self.parent_run == job.binding.parent_run
            && self.cutoff_unix_ms == job.binding.child_cutoff_unix_ms
            && self.owner == source.owner
            && self.path == source.path
            && self.handle == source.handle
    }

    /// Adds `delivered`, each range cut to `within`, and merges it with the
    /// ranges held.
    pub(crate) fn add(&mut self, delivered: &[(u64, u64)], within: (u64, u64)) {
        let mut ranges = std::mem::take(&mut self.ranges);
        ranges.extend(clip_ranges(delivered, within));
        self.ranges = merge_ranges(ranges);
    }
}

/// Each of `ranges` cut to `within`. A range that falls outside it becomes
/// empty, and [`merge_ranges`] drops it.
fn clip_ranges(ranges: &[(u64, u64)], within: (u64, u64)) -> impl Iterator<Item = (u64, u64)> {
    ranges
        .iter()
        .map(move |&(start, end)| (start.max(within.0), end.min(within.1)))
}

impl ReaderJob {
    /// The ranges of its primary source that this job's reads are proved to
    /// have been shown (FIX 7735): a settled scoped child's witness, while it
    /// is bound to the job, cut to the job's delegated range. A read child, a
    /// summary, a job that is not settled and a scoped child with no witness
    /// prove none here: a finding alone proves no byte of its source.
    pub(crate) fn delivered_source_ranges(&self) -> Vec<(u64, u64)> {
        let Some(witness) = self.delivery_witness.as_ref().filter(|witness| {
            self.scoped_spec().is_some() && self.state.is_settled() && witness.binds(self)
        }) else {
            return Vec::new();
        };
        merge_ranges(clip_ranges(&witness.ranges, self.binding.source.range).collect())
    }
}

/// `ranges` sorted and merged where they touch or overlap.
pub(crate) fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.retain(|(start, end)| start < end);
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// What of `whole` the merged `covered` ranges leave.
pub(crate) fn subtract_ranges(whole: (u64, u64), covered: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut left = Vec::new();
    let mut at = whole.0;
    for &(start, end) in covered {
        if end <= at || start >= whole.1 {
            continue;
        }
        if start > at {
            left.push((at, start.min(whole.1)));
        }
        at = at.max(end);
    }
    if at < whole.1 {
        left.push((at, whole.1));
    }
    left
}
