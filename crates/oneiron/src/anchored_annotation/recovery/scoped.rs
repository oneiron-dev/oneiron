//! The Unattached list and its reattach offers for a narrowed reader (FIX
//! 8063): every thread, snapshot, held task and offer is served only from
//! rows the reader's lane admits, judged in the one snapshot that reads them,
//! under one live policy.
//!
//! The newest thread head decides a thread, as on the raw list: a withheld
//! head drops its thread, and no older head stands in for it. The thread's
//! pinned version must be admitted, and the words it was on are read again
//! from that version through the reader's sight, never from the stored
//! snapshot, which was read from raw bytes. An offer reads the head the same
//! way, once the head's own rows are admitted. A held task shows only when
//! the thread's newest brief and its TASK are both admitted; otherwise the
//! thread shows without it. An offer is still only an offer.

use super::super::anchor_text::{anchor_text, find_text};
use super::super::model::AnnotationThread;
use super::super::threads::{newest_thread_brief, threads_from_active_claims};
use super::{ReattachOffer, UNATTACHED, UnattachedThread};
use crate::Vault;
use crate::blob_artifact::read_blob_artifact_head_in_txn;
use crate::claim::ScopedRead;
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::SecretSight;

/// Whether the reader's lane admits one row, in the listing's snapshot.
type Admits<'a> = &'a dyn Fn(&EntityId) -> Result<bool>;

fn all_admitted(admits: Admits<'_>, rows: &[EntityId]) -> Result<bool> {
    for row in rows {
        if !admits(row)? {
            return Ok(false);
        }
    }
    Ok(true)
}

impl Vault {
    /// [`Vault::unattached_annotation_threads`] for `lane`, whose words are
    /// read through `sight` (FIX 8063). An artifact the lane withholds lists
    /// nothing, as a missing one does.
    pub fn unattached_annotation_threads_scoped(
        &self,
        lane: &ScopedRead<'_>,
        artifact_id: &EntityId,
        sight: SecretSight,
    ) -> Result<Vec<UnattachedThread>> {
        lane.persist_grant_clock()?;
        let rtxn = self.store.env.read_txn()?;
        let policy = lane.live_policy_manifest_in(&rtxn)?;
        let admits = |id: &EntityId| lane.is_ref_readable_with_policy_in(&rtxn, &policy, id);
        self.unattached_scoped_in_txn(&rtxn, &admits, artifact_id, sight)
    }

    /// [`Vault::annotation_reattach_offers`] for `lane` (FIX 8063): offers
    /// start from the threads [`Self::unattached_annotation_threads_scoped`]
    /// serves it, in the same snapshot, and the head is read through `sight`
    /// only once the lane admits the head's own CLAIM and ASSET. A withheld
    /// head offers nothing.
    pub fn annotation_reattach_offers_scoped(
        &self,
        lane: &ScopedRead<'_>,
        artifact_id: &EntityId,
        sight: SecretSight,
    ) -> Result<Vec<ReattachOffer>> {
        lane.persist_grant_clock()?;
        let rtxn = self.store.env.read_txn()?;
        let policy = lane.live_policy_manifest_in(&rtxn)?;
        let admits = |id: &EntityId| lane.is_ref_readable_with_policy_in(&rtxn, &policy, id);
        let unattached = self.unattached_scoped_in_txn(&rtxn, &admits, artifact_id, sight)?;
        if unattached.iter().all(|thread| thread.snapshot.is_none()) {
            return Ok(Vec::new());
        }
        let Some(head) = read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)? else {
            return Ok(Vec::new());
        };
        let Some(rows) =
            self.blob_artifact_version_rows_in_txn(&rtxn, artifact_id, head.version)?
        else {
            return Ok(Vec::new());
        };
        if !all_admitted(&admits, &rows)? {
            return Ok(Vec::new());
        }
        let body = self
            .get_blob_artifact_in_txn(&rtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let format = OfficeFormat::from_media_type(&body.media_type)?;
        let bytes = self
            .read_blob_artifact_version_sighted_in_txn(&rtxn, artifact_id, head.version, sight)?
            .ok_or(Error::EntityNotFound)?;
        let limits = self.text_limits_in_txn(&rtxn)?;
        // A resource refusal is the engine's error (FIX 10587), never empty offers.
        let mut offers = Vec::new();
        for (thread_id, words) in unattached
            .iter()
            .filter_map(|thread| Some((thread.thread.thread_id, thread.snapshot.as_deref()?)))
        {
            for locator in find_text(&bytes, format, words, &limits)? {
                offers.push(ReattachOffer {
                    thread_id,
                    version: head.version,
                    locator,
                });
            }
        }
        Ok(offers)
    }

    /// The Unattached list as `admits` serves it, read in `rtxn`.
    fn unattached_scoped_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        admits: Admits<'_>,
        artifact_id: &EntityId,
        sight: SecretSight,
    ) -> Result<Vec<UnattachedThread>> {
        if !admits(artifact_id)? {
            return Ok(Vec::new());
        }
        let claims = self.active_annotation_claims_in_txn(rtxn, artifact_id)?;
        let limits = self.text_limits_in_txn(rtxn)?;
        let mut out = Vec::new();
        for thread in threads_from_active_claims(*artifact_id, claims.clone())
            .into_iter()
            .filter(AnnotationThread::is_drifted)
        {
            // The newest head alone decides; a withheld one drops the thread.
            if !admits(&thread.head_claim_id)? {
                continue;
            }
            let pinned = thread.anchor.version;
            let Some(rows) = self.blob_artifact_version_rows_in_txn(rtxn, artifact_id, pinned)?
            else {
                continue;
            };
            if !all_admitted(admits, &rows)? {
                continue;
            }
            let row = UNATTACHED.get(&self.store, rtxn, &(*artifact_id, thread.thread_id))?;
            // Read again as this reader sees the pinned version: the stored
            // snapshot holds the raw words. A resource refusal is the
            // engine's error (FIX 10587), never a missing snapshot.
            let snapshot = match row.as_ref().and_then(|row| row.snapshot.as_ref()) {
                Some(_) => match self.read_blob_artifact_version_sighted_in_txn(
                    rtxn,
                    artifact_id,
                    pinned,
                    sight,
                )? {
                    Some(bytes) => anchor_text(&bytes, &thread.anchor.locator, &limits)?,
                    None => None,
                },
                None => None,
            };
            let held_task = match newest_thread_brief(*artifact_id, &claims, &thread.thread_id) {
                Some((brief_claim, brief)) => {
                    (admits(&brief_claim)? && admits(&brief.task_id)?).then_some(brief.task_id)
                }
                None => None,
            };
            out.push(UnattachedThread {
                snapshot,
                detached_at_version: row.as_ref().map_or_else(
                    || thread.drift.map_or(0, |drift| drift.drifted_at_version),
                    |row| row.detached_at_version,
                ),
                held_task,
                thread,
            });
        }
        Ok(out)
    }
}
