//! The Unattached list and its reattach offers for a narrowed reader (FIX
//! 8063): every thread, snapshot, held task and offer is served only from
//! rows the reader's lane admits, judged in the one snapshot that reads them,
//! under one live policy.
//!
//! The newest thread head decides a thread, as on the raw list: a withheld
//! head drops its thread, and no older head stands in for it. The thread's
//! pinned version must be admitted, and the words it was on are read again
//! from that version through the reader's sight, never from the stored
//! snapshot, which was read from raw bytes; a code thread's words are read
//! again from the file its hash names, once that file's ASSET is admitted.
//! An offer reads the head the same way, once the head's own rows are
//! admitted; on a code artifact it reads each file of the current snapshot
//! once the lane admits the ASSET its hash names. A held task shows only
//! when the thread's newest brief and its TASK are both admitted; otherwise
//! the thread shows without it. An offer is still only an offer.

use super::super::anchor_text::{
    UnitFormat, anchor_text, find_text, text_find_text_for_sight, text_quote_for_sight,
};
use super::super::code_units::{CodeFile, code_span_words_in_txn};
use super::super::model::{AnnotationThread, Locator};
use super::super::threads::{newest_thread_brief, threads_from_active_claims};
use super::code::{code_reattach_offers_in_txn, code_threads_shown_in_txn};
use super::{ReattachOffer, UNATTACHED, UnattachedThread};
use crate::Vault;
use crate::blob_artifact::read_blob_artifact_head_in_txn;
use crate::claim::{ClaimBody, ScopedRead};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::secret_custody::SecretSight;
use crate::store::code_snapshot::codebase_asset_entity_id;

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
    /// nothing, as a missing one does. A code thread's locator reads in
    /// `sight`'s text, as its words do (FIX 22109).
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
        let mut unattached = self.unattached_scoped_in_txn(&rtxn, &admits, artifact_id, sight)?;
        code_threads_shown_in_txn(self, &rtxn, artifact_id, &mut unattached, sight)?;
        Ok(unattached)
    }

    /// The unrestricted Unattached list with plain-text snapshots projected
    /// to `sight`, and each code thread's locator in `sight`'s text (FIX
    /// 22109). Row membership, held tasks and other formats keep the raw
    /// listing's behavior; a missing text version loses only its quote.
    pub fn unattached_annotation_threads_file_sighted(
        &self,
        artifact_id: &EntityId,
        sight: SecretSight,
    ) -> Result<Vec<UnattachedThread>> {
        let mut threads = self.unattached_annotation_threads(artifact_id)?;
        // A code thread's file is found inside the read below: every body is
        // pinned before it opens (FIX 5399).
        let _bodies = threads
            .iter()
            .any(|row| matches!(row.thread.anchor.locator, Locator::Code { .. }))
            .then(|| self.pin_all_result_bodies());
        let rtxn = self.store.env.read_txn()?;
        code_threads_shown_in_txn(self, &rtxn, artifact_id, &mut threads, sight)?;
        for detached in &mut threads {
            let Locator::Text {
                char_start,
                char_end,
            } = &detached.thread.anchor.locator
            else {
                continue;
            };
            if detached.snapshot.is_none() {
                continue;
            }
            let pinned = detached.thread.anchor.version;
            detached.snapshot = match self.read_blob_artifact_version_sighted_in_txn(
                &rtxn,
                artifact_id,
                pinned,
                sight,
            )? {
                Some(sighted) => {
                    match self.read_blob_artifact_version_in_txn(&rtxn, artifact_id, pinned)? {
                        Some(raw) => text_quote_for_sight(&raw, &sighted, *char_start, *char_end),
                        None => None,
                    }
                }
                None => None,
            };
        }
        Ok(threads)
    }

    /// Unrestricted plain-text offers use the projected snapshots and head,
    /// without adding record admission. A code artifact's offers read in
    /// `sight`'s text (FIX 22109). Other formats keep the raw offers.
    pub fn annotation_reattach_offers_file_sighted(
        &self,
        artifact_id: &EntityId,
        sight: SecretSight,
    ) -> Result<Vec<ReattachOffer>> {
        if self.get_entity_type(artifact_id)? == Some(ENTITY_TYPE_CODE_ARTIFACT) {
            let unattached = self.unattached_annotation_threads(artifact_id)?;
            if unattached.iter().all(|thread| thread.snapshot.is_none()) {
                return Ok(Vec::new());
            }
            return self.code_annotation_reattach_offers(artifact_id, &unattached, sight);
        }
        let rtxn = self.store.env.read_txn()?;
        let plain_text = self
            .get_blob_artifact_in_txn(&rtxn, artifact_id)?
            .is_some_and(|body| {
                matches!(
                    UnitFormat::from_media_type(&body.media_type),
                    Some(UnitFormat::Text)
                )
            });
        if !plain_text {
            drop(rtxn);
            return self.annotation_reattach_offers(artifact_id);
        }
        let unattached = self.unattached_annotation_threads_file_sighted(artifact_id, sight)?;
        if unattached.iter().all(|thread| thread.snapshot.is_none()) {
            return Ok(Vec::new());
        }
        let Some(head) = read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)? else {
            return Ok(Vec::new());
        };
        let bytes = self
            .read_blob_artifact_version_sighted_in_txn(&rtxn, artifact_id, head.version, sight)?
            .ok_or(Error::EntityNotFound)?;
        self.text_offers_scoped(&rtxn, artifact_id, head.version, &bytes, &unattached)
    }

    /// [`Vault::annotation_reattach_offers`] for `lane` (FIX 8063): offers
    /// start from the threads [`Self::unattached_annotation_threads_scoped`]
    /// serves it, in the same snapshot, and the head is read through `sight`
    /// only once the lane admits the head's own CLAIM and ASSET. A withheld
    /// head offers nothing. On a code artifact each file of its current
    /// snapshot is read through `sight` only once the lane admits the ASSET
    /// its hash names, and a withheld file offers nothing (FIX 7905). A code
    /// place reads in `sight`'s text, and a reattach takes it in `sight`
    /// (FIX 22109).
    pub fn annotation_reattach_offers_scoped(
        &self,
        lane: &ScopedRead<'_>,
        artifact_id: &EntityId,
        sight: SecretSight,
    ) -> Result<Vec<ReattachOffer>> {
        lane.persist_grant_clock()?;
        let code_artifact = self.get_entity_type(artifact_id)? == Some(ENTITY_TYPE_CODE_ARTIFACT);
        // A code artifact's files are found inside the read below: every body
        // is pinned before it opens (FIX 5399).
        let _bodies = code_artifact.then(|| self.pin_all_result_bodies());
        let rtxn = self.store.env.read_txn()?;
        let policy = lane.live_policy_manifest_in(&rtxn)?;
        let admits = |id: &EntityId| lane.is_ref_readable_with_policy_in(&rtxn, &policy, id);
        let unattached = self.unattached_scoped_in_txn(&rtxn, &admits, artifact_id, sight)?;
        if unattached.iter().all(|thread| thread.snapshot.is_none()) {
            return Ok(Vec::new());
        }
        if code_artifact {
            return code_reattach_offers_in_txn(
                self,
                &rtxn,
                artifact_id,
                &unattached,
                sight,
                sight,
                |hash| admits(&codebase_asset_entity_id(hash)?),
            );
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
        let format = UnitFormat::from_media_type(&body.media_type).ok_or_else(|| {
            Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "unsupported annotation media type",
            ))
        })?;
        let bytes = self
            .read_blob_artifact_version_sighted_in_txn(&rtxn, artifact_id, head.version, sight)?
            .ok_or(Error::EntityNotFound)?;
        if matches!(format, UnitFormat::Text) {
            return self.text_offers_scoped(&rtxn, artifact_id, head.version, &bytes, &unattached);
        }
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

    /// [`Vault::annotation_reattach_offers_scoped`] for plain text: offers
    /// name raw whole-text coordinates, sought from the admitted projected
    /// snapshots on the Unattached list in the projected sighted head. The
    /// head's sighted read already ran before this branch, so a sealed or
    /// withheld head serves no offers; positions never come from a raw
    /// snapshot comparison. The final reattach still checks the raw words.
    fn text_offers_scoped(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
        head_version: u64,
        head_sighted: &[u8],
        unattached: &[UnattachedThread],
    ) -> Result<Vec<ReattachOffer>> {
        let Some(head_raw) =
            self.read_blob_artifact_version_in_txn(rtxn, artifact_id, head_version)?
        else {
            return Ok(Vec::new());
        };
        let mut offers = Vec::new();
        for thread in unattached {
            let Some(words) = thread.snapshot.as_deref() else {
                continue;
            };
            for locator in text_find_text_for_sight(&head_raw, head_sighted, words) {
                offers.push(ReattachOffer {
                    thread_id: thread.thread.thread_id,
                    version: head_version,
                    locator,
                });
            }
        }
        Ok(offers)
    }

    /// The Unattached list as `admits` serves it, read in `rtxn`, each
    /// locator as stored, at the owner's offsets.
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
            if matches!(thread.anchor.locator, Locator::Code { .. }) {
                if let Some(unattached) =
                    self.code_unattached_in_txn(rtxn, admits, artifact_id, &claims, thread, sight)?
                {
                    out.push(unattached);
                }
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
                    Some(sighted) => {
                        if let Locator::Text {
                            char_start,
                            char_end,
                        } = &thread.anchor.locator
                        {
                            // Raw coordinates, projected quote: the masked copy
                            // restricted to the raw span, never raw bytes.
                            match self.read_blob_artifact_version_in_txn(
                                rtxn,
                                artifact_id,
                                pinned,
                            )? {
                                Some(raw) => {
                                    text_quote_for_sight(&raw, &sighted, *char_start, *char_end)
                                }
                                None => None,
                            }
                        } else {
                            anchor_text(&sighted, &thread.anchor.locator, &limits)?
                        }
                    }
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

    /// One drifted code thread as `admits` serves it, read in `rtxn` (FIX
    /// 7905). A code artifact keeps no version rows: the artifact's row is
    /// admitted with the list, and the file the locator's hash names must
    /// have its ASSET row admitted. Its words are read again from that file
    /// through `sight`, as the blob arm reads its version, at the stored
    /// span's place in `sight`'s text (FIX 22109): the stored snapshot holds
    /// the masked projection's words. The locator stays as stored; the list
    /// puts it in `sight`'s text. `None` when the lane withholds the file.
    fn code_unattached_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        admits: Admits<'_>,
        artifact_id: &EntityId,
        claims: &[(EntityId, ClaimBody)],
        thread: AnnotationThread,
        sight: SecretSight,
    ) -> Result<Option<UnattachedThread>> {
        let Some(file) = CodeFile::of(&thread.anchor.locator) else {
            return Ok(None);
        };
        let asset = crate::store::code_snapshot::codebase_asset_entity_id(&file.hash)?;
        if !admits(&asset)? {
            return Ok(None);
        }
        let row = UNATTACHED.get(&self.store, rtxn, &(*artifact_id, thread.thread_id))?;
        let snapshot = match row.as_ref().and_then(|row| row.snapshot.as_ref()) {
            Some(_) => {
                code_span_words_in_txn(self, rtxn, artifact_id, &thread.anchor.locator, sight)?
            }
            None => None,
        };
        let held_task = match newest_thread_brief(*artifact_id, claims, &thread.thread_id) {
            Some((brief_claim, brief)) => {
                (admits(&brief_claim)? && admits(&brief.task_id)?).then_some(brief.task_id)
            }
            None => None,
        };
        Ok(Some(UnattachedThread {
            snapshot,
            detached_at_version: row.as_ref().map_or_else(
                || thread.drift.map_or(0, |drift| drift.drifted_at_version),
                |row| row.detached_at_version,
            ),
            held_task,
            thread,
        }))
    }
}
