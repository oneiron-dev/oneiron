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

use super::mirror_plan_types::{
    MirrorBatchProgress, MirrorPushPlan, MirrorSettledPlan, MirrorWorkHead, MirrorWorkRow,
};
use super::types::OriginPublishReviewPage;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::mirror_auto::OriginMirrorHoldCause;
use crate::side_table::{self, Named, SideTable};

/// Settled plans each mirror keeps, with their reviews, beside its open one;
/// an older one goes when a newer one settles (CALLS "FIX 6866 mirror work
/// kept").
pub(crate) const ORIGIN_MIRROR_WORK_KEPT_PLANS: usize = 16;

/// The WARN code of a plan row an actor scrub dropped because it does not
/// decode.
const ORIGIN_MIRROR_WORK_UNDECODABLE_DROPPED: &str = "origin_mirror_work_undecodable_dropped";

/// The WARN code of a mirror's work head rebuilt because it did not decode.
const ORIGIN_MIRROR_WORK_HEAD_REBUILT: &str = "origin_mirror_work_head_rebuilt";

/// Repo id, then the repo id again with `head`, or a plan id with nothing
/// (the plan), `p` + u64be (a review page) or `b` + u32be (a batch).
type WorkKey = (EntityId, EntityId, Vec<u8>);

const WORK: SideTable<WorkKey, MirrorWorkRow, Named> =
    SideTable::new(&side_table::ORIGIN_MIRROR_WORK);

/// A plan row's key length after the table prefix.
const PLAN_KEY_BYTES: usize = 32;

fn head_key(repo_id: EntityId) -> WorkKey {
    (repo_id, repo_id, b"head".to_vec())
}

fn plan_key(repo_id: EntityId, plan_id: EntityId) -> WorkKey {
    (repo_id, plan_id, Vec::new())
}

fn page_key(repo_id: EntityId, plan_id: EntityId, page: u64) -> WorkKey {
    let mut suffix = vec![b'p'];
    suffix.extend_from_slice(&page.to_be_bytes());
    (repo_id, plan_id, suffix)
}

fn batch_key(repo_id: EntityId, plan_id: EntityId, batch: u32) -> WorkKey {
    let mut suffix = vec![b'b'];
    suffix.extend_from_slice(&batch.to_be_bytes());
    (repo_id, plan_id, suffix)
}

/// The key prefix every row of one plan shares.
fn plan_prefix(repo_id: EntityId, plan_id: EntityId) -> Vec<u8> {
    let mut prefix = repo_id.as_bytes().to_vec();
    prefix.extend_from_slice(plan_id.as_bytes());
    prefix
}

impl Vault {
    /// A mirror's work head; an empty one when it has none.
    pub(super) fn mirror_work_head_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repo_id: EntityId,
    ) -> Result<MirrorWorkHead> {
        match WORK.get(&self.store, txn, &head_key(repo_id))? {
            Some(MirrorWorkRow::Head(head)) => Ok(head),
            Some(_) => Err(Error::CorruptedIndex("origin mirror work head")),
            None => Ok(MirrorWorkHead::default()),
        }
    }

    pub(super) fn put_mirror_work_head_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_id: EntityId,
        head: &MirrorWorkHead,
    ) -> Result<()> {
        WORK.put(
            &self.store,
            txn,
            &head_key(repo_id),
            &MirrorWorkRow::Head(head.clone()),
        )
    }

    /// One frozen plan.
    pub(super) fn mirror_plan_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repo_id: EntityId,
        plan_id: EntityId,
    ) -> Result<Option<MirrorPushPlan>> {
        match WORK.get(&self.store, txn, &plan_key(repo_id, plan_id))? {
            Some(MirrorWorkRow::Plan(plan)) => Ok(Some(*plan)),
            Some(_) => Err(Error::CorruptedIndex("origin mirror plan row")),
            None => Ok(None),
        }
    }

    /// One review page of a plan; `None` past its last.
    pub(super) fn mirror_plan_page_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        plan: &MirrorPushPlan,
        page: u64,
    ) -> Result<Option<OriginPublishReviewPage>> {
        match WORK.get(
            &self.store,
            txn,
            &page_key(plan.repo_id, plan.plan_id, page),
        )? {
            Some(MirrorWorkRow::Page(page)) => Ok(Some(page)),
            Some(_) => Err(Error::CorruptedIndex("origin mirror plan review page")),
            None => Ok(None),
        }
    }

    /// Every batch of a plan, in order. A batch the plan names that is
    /// missing is an error: no push stands on part of a plan.
    pub(super) fn mirror_batches_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        plan: &MirrorPushPlan,
    ) -> Result<Vec<MirrorBatchProgress>> {
        (0..plan.batches)
            .map(|batch| self.mirror_batch_in_txn(txn, plan, batch))
            .collect()
    }

    /// One batch of a plan.
    pub(super) fn mirror_batch_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        plan: &MirrorPushPlan,
        batch: u32,
    ) -> Result<MirrorBatchProgress> {
        match WORK.get(
            &self.store,
            txn,
            &batch_key(plan.repo_id, plan.plan_id, batch),
        )? {
            Some(MirrorWorkRow::Batch(progress)) => Ok(progress),
            _ => Err(Error::CorruptedIndex("origin mirror plan batch")),
        }
    }

    pub(super) fn put_mirror_batch_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        plan: &MirrorPushPlan,
        batch: u32,
        progress: &MirrorBatchProgress,
    ) -> Result<()> {
        WORK.put(
            &self.store,
            txn,
            &batch_key(plan.repo_id, plan.plan_id, batch),
            &MirrorWorkRow::Batch(progress.clone()),
        )
    }

    /// Writes a frozen plan, its review pages and its batches, and opens it
    /// on its mirror's head, in `txn`. `false`, writing nothing, when the
    /// head already has an open plan: a new plan waits for it to settle.
    pub(super) fn open_mirror_plan_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        plan: &MirrorPushPlan,
        pages: &[OriginPublishReviewPage],
        batches: &[MirrorBatchProgress],
    ) -> Result<bool> {
        let mut head = self.mirror_work_head_in_txn(txn, plan.repo_id)?;
        if head.open.is_some() {
            return Ok(false);
        }
        for (index, page) in (0_u64..).zip(pages) {
            let key = page_key(plan.repo_id, plan.plan_id, index);
            WORK.put(&self.store, txn, &key, &MirrorWorkRow::Page(page.clone()))?;
        }
        for (index, progress) in (0_u32..).zip(batches) {
            self.put_mirror_batch_in_txn(txn, plan, index, progress)?;
        }
        let key = plan_key(plan.repo_id, plan.plan_id);
        WORK.put(
            &self.store,
            txn,
            &key,
            &MirrorWorkRow::Plan(Box::new(plan.clone())),
        )?;
        head.open = Some(plan.plan_id);
        head.unread = 0;
        self.put_mirror_work_head_in_txn(txn, plan.repo_id, &head)?;
        Ok(true)
    }

    /// Closes a settled plan on its mirror's head and keeps it, dropping the
    /// oldest kept plan, rows and all, past [`ORIGIN_MIRROR_WORK_KEPT_PLANS`].
    /// `cleared` when the owner's clear of the mirror settled it.
    pub(super) fn close_mirror_plan_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        plan: &MirrorPushPlan,
        landed: bool,
        cleared: bool,
    ) -> Result<()> {
        let mut head = self.mirror_work_head_in_txn(txn, plan.repo_id)?;
        if head.open != Some(plan.plan_id) {
            return Ok(());
        }
        head.open = None;
        head.unread = 0;
        head.last = Some(MirrorSettledPlan {
            plan_id: plan.plan_id,
            landed,
            vector: plan.vector.clone(),
            cleared,
        });
        head.kept.push(plan.plan_id);
        while head.kept.len() > ORIGIN_MIRROR_WORK_KEPT_PLANS {
            let dropped = head.kept.remove(0);
            WORK.delete_from(&self.store, txn, &plan_prefix(plan.repo_id, dropped))?;
        }
        self.put_mirror_work_head_in_txn(txn, plan.repo_id, &head)
    }

    /// Rebuilds a mirror's work head that does not decode (FIX 7217), under
    /// a WARN naming only its key and the error's kind. No plan is open
    /// after it, so the mirror plans afresh; every plan whose row decodes is
    /// kept, oldest first, past [`ORIGIN_MIRROR_WORK_KEPT_PLANS`] the oldest
    /// dropped rows and all, and a plan row that does not decode goes with
    /// its pages and batches. A head that decodes again is left as it is.
    pub(super) fn rebuild_mirror_work_head(&self, repo_id: EntityId, error: &Error) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let undecodable_head = self
            .mirror_work_head_in_txn(&txn, repo_id)
            .is_err_and(|current| {
                OriginMirrorHoldCause::of(&current) == OriginMirrorHoldCause::Decode
            });
        if !undecodable_head {
            return Ok(());
        }
        let (mut kept, mut undecodable) = (Vec::new(), Vec::new());
        for row in WORK.iter_raw_from(&self.store, &txn, repo_id.as_bytes())? {
            let (key, bytes) = row?;
            if key.len() != PLAN_KEY_BYTES {
                continue;
            }
            match WORK.decode_value(&bytes) {
                Ok(MirrorWorkRow::Plan(plan)) => kept.push(plan.plan_id),
                Ok(_) => {}
                Err(_) => undecodable.push(key),
            }
        }
        for key in undecodable {
            WORK.delete_from(&self.store, &mut txn, &key)?;
        }
        while kept.len() > ORIGIN_MIRROR_WORK_KEPT_PLANS {
            let dropped = kept.remove(0);
            WORK.delete_from(&self.store, &mut txn, &plan_prefix(repo_id, dropped))?;
        }
        let head = MirrorWorkHead {
            kept,
            ..MirrorWorkHead::default()
        };
        self.put_mirror_work_head_in_txn(&mut txn, repo_id, &head)?;
        txn.commit()?;
        tracing::warn!(
            code = ORIGIN_MIRROR_WORK_HEAD_REBUILT,
            repo_id = %repo_id.to_hex(),
            kind = ?error.kind(),
            "an automatic mirror's work head that does not decode was rebuilt with no plan open"
        );
        Ok(())
    }

    /// Drops an open plan whose row does not decode, with its pages and
    /// batches, under a WARN naming only its keys and the error's kind.
    pub(super) fn drop_undecodable_mirror_plan_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_id: EntityId,
        plan_id: EntityId,
        error: &Error,
    ) -> Result<()> {
        WORK.delete_from(&self.store, txn, &plan_prefix(repo_id, plan_id))?;
        tracing::warn!(
            code = ORIGIN_MIRROR_WORK_UNDECODABLE_DROPPED,
            repo_id = %repo_id.to_hex(),
            plan_id = %plan_id.to_hex(),
            kind = ?error.kind(),
            "an open automatic mirror plan that does not decode was dropped with its review"
        );
        Ok(())
    }
}

/// Scrubs an erased actor from every plan that names it (the side-table
/// erase callback, which a restore runs again). The plan, its review and its
/// outcomes stay: the record of what left the vault outlives who asked. A
/// plan row that does not decode is dropped with its pages and batches (its
/// actor bytes go with it) under a typed WARN naming its key, and the scrub
/// goes on; a store error still ends it.
pub(crate) fn erase_mirror_work_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut rows = Vec::new();
    let mut undecodable = Vec::new();
    for row in WORK.iter_raw_from(&vault.store, wtxn, &[])? {
        let (key, bytes) = row?;
        if key.len() != PLAN_KEY_BYTES {
            continue;
        }
        let mut plan = match WORK.decode_value(&bytes) {
            Ok(MirrorWorkRow::Plan(plan)) => plan,
            Ok(_) => continue,
            Err(error) => {
                undecodable.push((key, error.kind()));
                continue;
            }
        };
        if plan.requested_by == Some(*actor) {
            plan.requested_by = None;
            rows.push(plan);
        }
    }
    for plan in rows {
        let key = plan_key(plan.repo_id, plan.plan_id);
        WORK.put(&vault.store, wtxn, &key, &MirrorWorkRow::Plan(plan))?;
    }
    for (key, kind) in undecodable {
        WORK.delete_from(&vault.store, wtxn, &key)?;
        tracing::warn!(
            code = ORIGIN_MIRROR_WORK_UNDECODABLE_DROPPED,
            repo_id = %crate::entity_id::bytes_to_hex_lower(&key[..16]),
            plan_id = %crate::entity_id::bytes_to_hex_lower(&key[16..]),
            kind = ?kind,
            "an automatic mirror plan that does not decode was dropped with its review"
        );
    }
    Ok(())
}
