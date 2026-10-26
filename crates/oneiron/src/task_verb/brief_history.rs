//! A TASK's earlier briefs (FIX 8077). Each revision a `tasks.brief`
//! proposal landed is that settled CLAIM's value, so an exact revision and
//! digest read back the brief that revision held. A TASK's first brief,
//! which its post landed and no such CLAIM did, is read from the base brief
//! a settled revision of it kept (FIX 9005). No revision store exists
//! beside the CLAIMs.

use crate::Vault;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::scan_check::{EngineScan, ScanCount};

use super::brief::{QueueTaskBrief, brief_digest, decode_hex};
use super::consts::TASK_BRIEF_PROPOSAL_PREDICATE;
use super::highway_post::BriefRevision;
use super::wire_encode::canonical_bytes;

/// Claim ids one page of the `tasks.brief` posting list reads. The walk
/// pages on to the list's end: a page paces the read, it bounds nothing.
const HISTORY_PAGE: usize = 256;

/// The brief `task` held at revision `rev` with digest `digest` (64 hex), as
/// the settled `tasks.brief` CLAIM that landed it says, read in `txn`, with
/// that CLAIM's id, the row a copy of the brief was read from: an
/// approved revision of `task` proposed against `rev - 1` whose brief
/// digests to `digest`, or, for the first revision, an approved revision
/// proposed against it whose kept base brief digests to `digest`. Of two
/// such CLAIMs (one revision approved on two replicas) the lowest CLAIM id
/// answers. Only that exact revision is a hit: a nearby revision, or the
/// current one, is never returned for it, and a first brief no settled
/// revision kept is `None`.
/// A CLAIM whose body does not read cannot be that revision and is passed
/// over. Every CLAIM of the predicate is read until the hit, however many
/// (rule 5): past the threshold row the read raises its check and reads on.
pub(crate) fn settled_brief_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    rev: u32,
    digest: &str,
) -> Result<Option<(QueueTaskBrief, EntityId)>> {
    let Some(digest) = decode_hex::<32>(digest) else {
        return Ok(None);
    };
    let mut count = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::PredicateClaimRows,
        TASK_BRIEF_PROPOSAL_PREDICATE.as_bytes(),
    )?;
    let mut after = None;
    let found = 'pages: loop {
        let page = crate::claim::claim_ids_for_predicate_page_in_txn(
            &vault.store,
            txn,
            TASK_BRIEF_PROPOSAL_PREDICATE,
            after,
            HISTORY_PAGE,
        )?;
        let exhausted = page.len() < HISTORY_PAGE;
        after = page.last().copied();
        for id in page {
            count.row();
            if let Some(brief) = landed_revision_in(vault, txn, id, task, rev, &digest) {
                break 'pages Some((brief, id));
            }
        }
        if exhausted {
            break None;
        }
    };
    count.defer(&vault.store);
    Ok(found)
}

/// The brief of CLAIM `id` when it is the settled `tasks.brief` revision
/// that landed `task` at `rev` with `digest`, or the base brief it kept when
/// that was `task`'s first at `rev` with `digest`.
fn landed_revision_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    task: EntityId,
    rev: u32,
    digest: &[u8; 32],
) -> Option<QueueTaskBrief> {
    let claim = vault.get_claim_in_txn(txn, &id).ok().flatten()?;
    if claim.predicate != TASK_BRIEF_PROPOSAL_PREDICATE
        || claim.approval != ClaimApprovalStatus::Approved
    {
        return None;
    }
    let revision: BriefRevision = rmp_serde::from_slice(&canonical_bytes(&claim.value)).ok()?;
    if revision.task_ref != task {
        return None;
    }
    if revision.base_rev.checked_add(1) == Some(rev) && brief_digest(&revision.brief) == *digest {
        return Some(revision.brief);
    }
    let base_rev = revision.base_rev;
    revision
        .base_brief
        .filter(|base| base_rev == rev && brief_digest(base) == *digest)
}
