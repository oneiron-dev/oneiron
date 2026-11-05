//! The one store of automatic mirror push work (`ORIGIN_MIRROR_WORK`, LIVE;
//! FIX 6866 part 2). Per mirror: a head row naming its open plan, the
//! reconcile reads that failed in a row and the settled plans it keeps; per
//! plan: the frozen plan, its review pages and one progress row a batch.
//! Every change is a write in one transaction; a plan is never rewritten
//! once frozen. An actor's erase scrubs the owner a push-now plan names and
//! keeps the rest of the record; a plan row that does not decode is dropped
//! there with its pages and batches instead, never an abort of the erase or
//! restore. A head row that does not decode is rebuilt from the plan rows
//! that do, with no plan open.

use crate::origin::mirror_auto::OriginMirrorHoldCause;
use crate::origin::publish::mirror_plan_types::MirrorBatchProgress;
use crate::origin::publish::mirror_plan_types::MirrorSettledPlan;
use crate::origin::publish::mirror_plan_types::MirrorWorkHead;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// Settled plans each mirror keeps, with their reviews, beside its open one;
/// an older one goes when a newer one settles (CALLS "FIX 6866 mirror work
/// kept").
pub const ORIGIN_MIRROR_WORK_KEPT_PLANS: usize = 16;

/// The WARN code of a plan row an actor scrub dropped because it does not
/// decode.
pub const ORIGIN_MIRROR_WORK_UNDECODABLE_DROPPED: &str = "origin_mirror_work_undecodable_dropped";

/// The WARN code of a mirror's work head rebuilt because it did not decode.
pub const ORIGIN_MIRROR_WORK_HEAD_REBUILT: &str = "origin_mirror_work_head_rebuilt";

/// Repo id, then the repo id again with `head`, or a plan id with nothing
/// (the plan), `p` + u64be (a review page) or `b` + u32be (a batch).
pub type WorkKey = (EntityId, EntityId, Vec<u8>);

/// A plan row's key length after the table prefix.
pub const PLAN_KEY_BYTES: usize = 32;

pub fn head_key(repo_id: EntityId) -> WorkKey {
    (repo_id, repo_id, b"head".to_vec())
}

pub fn plan_key(repo_id: EntityId, plan_id: EntityId) -> WorkKey {
    (repo_id, plan_id, Vec::new())
}

pub fn page_key(repo_id: EntityId, plan_id: EntityId, page: u64) -> WorkKey {
    let mut suffix = vec![b'p'];
    suffix.extend_from_slice(&page.to_be_bytes());
    (repo_id, plan_id, suffix)
}

pub fn batch_key(repo_id: EntityId, plan_id: EntityId, batch: u32) -> WorkKey {
    let mut suffix = vec![b'b'];
    suffix.extend_from_slice(&batch.to_be_bytes());
    (repo_id, plan_id, suffix)
}

/// The key prefix every row of one plan shares.
pub fn plan_prefix(repo_id: EntityId, plan_id: EntityId) -> Vec<u8> {
    let mut prefix = repo_id.as_bytes().to_vec();
    prefix.extend_from_slice(plan_id.as_bytes());
    prefix
}
