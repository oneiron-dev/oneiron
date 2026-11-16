//! Consecutive batches of one enqueue ([MERGE-QUEUE-ENQUEUE-SPLITS-LARGE-BATCH],
//! RULING RESTRICTION-WAVE-15-ROWS C107 = A). One batch holds at most
//! [`MAX_BATCH_PROPOSALS`] proposals, the width of its path mask. An enqueue
//! of more forms consecutive batches of at most that many, in request
//! order, in one writer. Each later batch names the batch it follows and
//! stages on the head that batch landed, once it has: no batch is staged on
//! a base its predecessor has not reached, and none is rebased.

use super::staging::MAX_BATCH_PROPOSALS;
use super::{BatchState, MergeBatch, MergeProposal, MergeQueue, QueueSurvivorLink};
use crate::error::{Error, Result};

/// What a later batch of a split enqueue whose followed batch ended
/// without landing answers: it never stages.
pub(super) const FOLLOWED_BATCH_ENDED: &str = "the batch this one follows ended without landing; \
     no automatic rebase: cancel this batch and enqueue its proposals again on the current green";

/// Where a batch may stage, by the batch it follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FollowedBase {
    /// The first batch of its enqueue: it stages on the head it was formed
    /// on.
    First,
    /// The batch it follows, or the survivors that carry it, has not landed.
    Waiting,
    /// That batch landed as this head; this one stages there.
    Landed(String),
    /// That batch ended without landing: cancelled, rolled back,
    /// superseded, or every member quarantined.
    Ended,
}

/// `proposals` in request order, cut into consecutive groups of at most
/// [`MAX_BATCH_PROPOSALS`]; one group when they fit one batch.
pub(super) fn split_proposals(mut proposals: Vec<MergeProposal>) -> Vec<Vec<MergeProposal>> {
    let mut groups = Vec::with_capacity(proposals.len().div_ceil(MAX_BATCH_PROPOSALS));
    while proposals.len() > MAX_BATCH_PROPOSALS {
        let rest = proposals.split_off(MAX_BATCH_PROPOSALS);
        groups.push(std::mem::replace(&mut proposals, rest));
    }
    groups.push(proposals);
    groups
}

impl MergeQueue<'_> {
    /// Where `batch` may stage: on its own formation head when it follows
    /// no batch, else on the head the batch it follows landed. A quarantined
    /// followed batch is followed on to the survivors batch its diagnosis
    /// requeued, which carries its landing; each survivors batch holds fewer
    /// proposals than its source, so the walk ends.
    ///
    /// # Errors
    /// A followed batch that cannot be read, or a landed one without its
    /// landed head.
    pub(super) fn followed_base(&self, batch: &MergeBatch) -> Result<FollowedBase> {
        let Some(mut followed) = batch.follows.clone() else {
            return Ok(FollowedBase::First);
        };
        for _ in 0..=MAX_BATCH_PROPOSALS {
            let predecessor = self.batch(&followed)?;
            match predecessor.state {
                BatchState::HeadAdvanced | BatchState::GreenAdvanced => {
                    return predecessor
                        .landed_head
                        .map(FollowedBase::Landed)
                        .ok_or(Error::CorruptedIndex("landed HEAD missing"));
                }
                BatchState::Queued
                | BatchState::Staged
                | BatchState::Ready
                | BatchState::Landing => return Ok(FollowedBase::Waiting),
                BatchState::Quarantined => {
                    match predecessor.drive.and_then(|drive| drive.survivor) {
                        Some(QueueSurvivorLink::Batch(child)) => followed = child,
                        Some(QueueSurvivorLink::Empty) => return Ok(FollowedBase::Ended),
                        None => return Ok(FollowedBase::Waiting),
                    }
                }
                BatchState::RollingBack
                | BatchState::RolledBack
                | BatchState::Cancelled
                | BatchState::Superseded => return Ok(FollowedBase::Ended),
            }
        }
        Err(Error::CorruptedIndex(
            "merge batch survivor links do not end",
        ))
    }
}
