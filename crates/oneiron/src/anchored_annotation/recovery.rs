//! Lost-anchor recovery (OF-368, owner ruling 2026-10-17).
//!
//! - An edit inside the commented spot keeps the anchor (Word spans move
//!   with their paragraph, a deck shape keeps its creation identity); only
//!   deleting the spot detaches it, and a partial delete shrinks it.
//! - A detached comment joins the Unattached list with a snapshot of the text
//!   it was on. When the same words return, [`Vault::annotation_reattach_offers`]
//!   offers each exact place ("Reattach here?") and
//!   [`Vault::reattach_annotation_thread`] reattaches only where the words
//!   read exactly; the engine never reattaches on a guess.
//! - Undo or a version restore reattaches by exact stored identity: a thread
//!   pinned to, or moved off, the restored version returns to its stored
//!   locator there when the new version's bytes are that version's bytes.
//! - The comment's agent task pauses while its thread is unattached
//!   ([`Vault::annotation_thread_task_hold`]); a Keep answering it waits.

use std::collections::HashMap;

use oneiron_docedit::{DocxAnchorBlock, docx_anchor_blocks};
use serde::{Deserialize, Serialize};

use super::anchor_text::{TextLimits, anchor_text, find_text, remap_span};
use super::codec::{ThreadHead, decode_locator, encode_locator};
use super::model::{AnnotationThread, Locator, ReanchorOutcome, ReanchorSummary};
use super::threads::thread_from_head;
use crate::Vault;
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// The most prior-anchor hops one restore walks back.
const MAX_PRIOR_HOPS: usize = 4_096;

/// Key: artifact + thread + the version the sweep moved the thread onto.
const PRIOR: SideTable<(EntityId, EntityId, u64), PriorAnchor, Named> =
    SideTable::new(&side_table::ANNOTATION_PRIOR_ANCHOR);

/// Key: artifact + thread.
const UNATTACHED: SideTable<(EntityId, EntityId), UnattachedRow, Named> =
    SideTable::new(&side_table::ANNOTATION_UNATTACHED);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PriorAnchor {
    from_version: u64,
    locator: rmpv::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnattachedRow {
    pinned_version: u64,
    detached_at_version: u64,
    snapshot: Option<String>,
    detached_at: u64,
}

/// One comment on the Unattached list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnattachedThread {
    /// The thread, pinned to the version its spot last existed in.
    pub thread: AnnotationThread,
    /// The words it was anchored on, read from the pinned version.
    pub snapshot: Option<String>,
    /// The version whose edit deleted the spot.
    pub detached_at_version: u64,
    /// The agent task that waits while the comment is unattached.
    pub held_task: Option<EntityId>,
}

/// One exact place the snapshot's words read again: "Reattach here?".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReattachOffer {
    pub thread_id: EntityId,
    pub version: u64,
    pub locator: Locator,
}

/// The DOCX side of one sweep: both versions' body paragraphs.
pub(super) struct DocxReanchor {
    before: Option<Paragraphs>,
    after: Option<Paragraphs>,
    /// Whether the versions share any paraId: a producer that mints new ids
    /// on save leaves none to follow.
    shares_ids: bool,
}

/// One version's body paragraphs, and which of them carry each paraId.
struct Paragraphs {
    blocks: Vec<DocxAnchorBlock>,
    ids: HashMap<String, Vec<usize>>,
}

impl Paragraphs {
    fn new(blocks: Vec<DocxAnchorBlock>) -> Self {
        let mut ids: HashMap<String, Vec<usize>> = HashMap::new();
        for (at, block) in blocks.iter().enumerate() {
            if let Some(id) = &block.para_id {
                ids.entry(id.clone()).or_default().push(at);
            }
        }
        Self { blocks, ids }
    }

    /// The paragraph that alone carries `id`.
    fn only(&self, id: &str) -> Option<usize> {
        match self.ids.get(id).map(Vec::as_slice) {
            Some([at]) => Some(*at),
            _ => None,
        }
    }
}

impl DocxReanchor {
    pub(super) fn load(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        from: u64,
        to: u64,
        threads: &[AnnotationThread],
    ) -> Result<Option<Self>> {
        if !threads.iter().any(|t| {
            t.anchor.version == from
                && !t.is_drifted()
                && matches!(t.anchor.locator, Locator::Docx { .. })
        }) {
            return Ok(None);
        }
        let limits = vault.text_limits_in_txn(txn)?;
        let read = |version| -> Result<Option<Paragraphs>> {
            Ok(vault
                .read_blob_artifact_version_in_txn(txn, artifact, version)?
                .and_then(|bytes| {
                    oneiron_docedit::preflight_with_limits(&bytes, limits.docx).ok()?;
                    let document = oneiron_docedit::Document::parse(&bytes).ok()?;
                    Some(Paragraphs::new(docx_anchor_blocks(&document)))
                }))
        };
        let (before, after) = (read(from)?, read(to)?);
        let shares_ids = match (&before, &after) {
            (Some(before), Some(after)) => before.ids.keys().any(|id| after.ids.contains_key(id)),
            _ => false,
        };
        Ok(Some(Self {
            before,
            after,
            shares_ids,
        }))
    }

    /// The paragraph keeps its anchor when it survives the edit: one whose
    /// Word id (`w14:paraId`) both versions carry follows that id, through a
    /// move and an edit at once. Otherwise unchanged paragraphs pair by
    /// position around the changed stretch, and inside it a paragraph pairs
    /// by position when the count held, else by its exact unique text. A
    /// deleted paragraph, or a span deleted whole, detaches.
    pub(super) fn rebind(&self, locator: &Locator) -> ReanchorOutcome {
        let Locator::Docx {
            para_path,
            char_start,
            char_end,
        } = locator
        else {
            return ReanchorOutcome::Drifted;
        };
        let (Some(before), Some(after)) = (&self.before, &self.after) else {
            return ReanchorOutcome::Drifted;
        };
        let Some(index) = before
            .blocks
            .iter()
            .position(|block| block.block_id == *para_path)
        else {
            return ReanchorOutcome::Drifted;
        };
        let Some(paired) = pair_paragraph(before, after, index, self.shares_ids) else {
            return ReanchorOutcome::Drifted;
        };
        let new = &after.blocks[paired];
        match remap_span(
            &before.blocks[index].text,
            &new.text,
            *char_start,
            *char_end,
        )
        .and_then(|(start, end)| Locator::docx(new.block_id.clone(), start, end).ok())
        {
            Some(locator) => ReanchorOutcome::Mapped(locator),
            None => ReanchorOutcome::Drifted,
        }
    }
}

fn pair_paragraph(
    before: &Paragraphs,
    after: &Paragraphs,
    index: usize,
    shares_ids: bool,
) -> Option<usize> {
    // A paraId one paragraph alone carries on each side is its identity;
    // gone from the new version, the paragraph was deleted. Two carrying it
    // there prove nothing, so the text decides.
    let id = before.blocks[index]
        .para_id
        .as_deref()
        .filter(|id| shares_ids && before.only(id).is_some());
    if let Some(id) = id {
        match after.ids.get(id).map_or(0, Vec::len) {
            0 => return None,
            1 => return after.only(id),
            _ => {}
        }
    }
    let found = pair_by_text(&before.blocks, &after.blocks, index)?;
    // The text never pairs it with a paragraph another one's id follows.
    let claimed = shares_ids
        && after.blocks[found]
            .para_id
            .as_deref()
            .and_then(|other| before.only(other))
            .is_some_and(|owner| owner != index);
    (!claimed).then_some(found)
}

fn pair_by_text(
    before: &[DocxAnchorBlock],
    after: &[DocxAnchorBlock],
    index: usize,
) -> Option<usize> {
    let shared = before.len().min(after.len());
    let prefix = before
        .iter()
        .zip(after)
        .take_while(|(a, b)| a.text == b.text)
        .count();
    let suffix = before
        .iter()
        .rev()
        .zip(after.iter().rev())
        .take(shared - prefix)
        .take_while(|(a, b)| a.text == b.text)
        .count();
    let (before_end, after_end) = (before.len() - suffix, after.len() - suffix);
    if index < prefix {
        return Some(index);
    }
    if index >= before_end {
        return Some(index - before_end + after_end);
    }
    if before_end - prefix == after_end - prefix {
        return Some(prefix + (index - prefix));
    }
    let text = &before[index].text;
    let mut same = (prefix..after_end).filter(|&at| after[at].text == *text);
    let found = same.next()?;
    same.next().is_none().then_some(found)
}

impl Vault {
    pub(super) fn text_limits_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<TextLimits> {
        // Reading a spot's words is bound by the vault's live package and
        // Word archive policy, as this transaction sees them.
        Ok(TextLimits {
            package: self.docedit_package_limits_in_txn(txn)?,
            docx: self.docx_archive_limits_in_txn(txn, None)?,
        })
    }

    /// Puts a thread the sweep just detached on the Unattached list, with the
    /// words its spot held in the version it stays pinned to.
    pub(super) fn record_detached_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        thread: &AnnotationThread,
        detached_at_version: u64,
        detached_at: u64,
    ) -> Result<()> {
        let pinned = thread.anchor.version;
        let snapshot = match self.read_blob_artifact_version_in_txn(wtxn, artifact_id, pinned)? {
            Some(bytes) => {
                let limits = self.text_limits_in_txn(wtxn)?;
                anchor_text(&bytes, &thread.anchor.locator, &limits)
            }
            None => None,
        };
        UNATTACHED.put(
            &self.store,
            wtxn,
            &(*artifact_id, thread.thread_id),
            &UnattachedRow {
                pinned_version: pinned,
                detached_at_version,
                snapshot,
                detached_at,
            },
        )
    }

    /// Stores the anchor a thread held before the sweep moved it onto
    /// `to_version`, so a restore of the earlier version finds it exactly.
    pub(super) fn record_prior_anchor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        thread: &AnnotationThread,
        to_version: u64,
    ) -> Result<()> {
        PRIOR.put(
            &self.store,
            wtxn,
            &(*artifact_id, thread.thread_id, to_version),
            &PriorAnchor {
                from_version: thread.anchor.version,
                locator: encode_locator(&thread.anchor.locator),
            },
        )
    }

    /// The comments on one artifact whose spot was deleted, with what they
    /// were on and the task that waits for them.
    pub fn unattached_annotation_threads(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<UnattachedThread>> {
        let threads = self.annotation_threads_for_artifact(artifact_id)?;
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for thread in threads.into_iter().filter(AnnotationThread::is_drifted) {
            let row = UNATTACHED.get(&self.store, &rtxn, &(*artifact_id, thread.thread_id))?;
            let held_task = self
                .annotation_brief_for_thread(artifact_id, &thread.thread_id)?
                .map(|brief| brief.task_id);
            out.push(UnattachedThread {
                snapshot: row.as_ref().and_then(|row| row.snapshot.clone()),
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

    /// Every exact place in the artifact's head where an unattached comment's
    /// words read again. An offer is only an offer: nothing moves until a
    /// person picks one through [`Vault::reattach_annotation_thread`].
    pub fn annotation_reattach_offers(&self, artifact_id: &EntityId) -> Result<Vec<ReattachOffer>> {
        let unattached = self.unattached_annotation_threads(artifact_id)?;
        if unattached.iter().all(|thread| thread.snapshot.is_none()) {
            return Ok(Vec::new());
        }
        let head = self
            .blob_artifact_head(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let format = OfficeFormat::from_media_type(&body.media_type)?;
        let bytes = self
            .read_blob_artifact_version(artifact_id, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let limits = {
            let rtxn = self.store.env.read_txn()?;
            self.text_limits_in_txn(&rtxn)?
        };
        Ok(unattached
            .iter()
            .filter_map(|thread| Some((thread.thread.thread_id, thread.snapshot.as_deref()?)))
            .flat_map(|(thread_id, words)| {
                find_text(&bytes, format, words, &limits)
                    .into_iter()
                    .map(move |locator| ReattachOffer {
                        thread_id,
                        version: head.version,
                        locator,
                    })
            })
            .collect())
    }

    /// One-click reattach of an unattached comment at `locator` in `version`.
    /// Refused unless the words there read exactly as the comment's snapshot.
    #[expect(clippy::too_many_arguments)]
    pub fn reattach_annotation_thread(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
        version: u64,
        locator: &Locator,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AnnotationThread> {
        self.with_write_txn_grouped(|wtxn| {
            self.require_anchor_version_in_txn(wtxn, artifact_id, version)?;
            let thread = self
                .annotation_thread_in_txn(wtxn, artifact_id, thread_id, true)?
                .ok_or(Error::Artifact(ArtifactError::AnnotationThreadNotFound))?;
            let row = UNATTACHED
                .get(&self.store, wtxn, &(*artifact_id, *thread_id))?
                .filter(|_| thread.is_drifted());
            let Some(snapshot) = row.and_then(|row| row.snapshot) else {
                return Err(Error::Artifact(ArtifactError::InvalidAnchor(
                    "only an unattached comment with a snapshot reattaches",
                )));
            };
            let bytes = self
                .read_blob_artifact_version_in_txn(wtxn, artifact_id, version)?
                .ok_or(Error::EntityNotFound)?;
            let limits = self.text_limits_in_txn(wtxn)?;
            if anchor_text(&bytes, locator, &limits).as_deref() != Some(snapshot.as_str()) {
                return Err(Error::Artifact(ArtifactError::InvalidAnchor(
                    "the words at that place are not the comment's words",
                )));
            }
            self.reattach_in_txn(
                wtxn,
                artifact_id,
                &thread,
                version,
                locator.clone(),
                actor,
                occurred,
                learned_at,
            )
        })
        .inspect(|_| self.store.notify_attempt_observers())
    }

    /// Reattaches by exact stored identity after a restore: `new_version`
    /// holds `restored`'s bytes, so every thread pinned to `restored`, or
    /// moved off it by later sweeps, returns to its stored locator there.
    /// Threads that never stood on `restored` stay where they are.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn reattach_restored_threads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        restored: u64,
        new_version: u64,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<ReanchorSummary> {
        let mut summary = ReanchorSummary::default();
        let (Some(old), Some(new)) = (
            self.blob_artifact_version_metadata_in_txn(wtxn, artifact_id, restored)?,
            self.blob_artifact_version_metadata_in_txn(wtxn, artifact_id, new_version)?,
        ) else {
            return Err(Error::EntityNotFound);
        };
        if old.content_hash != new.content_hash {
            return Ok(summary);
        }
        for thread in self.effect_annotation_threads_for_artifact_in_txn(wtxn, artifact_id)? {
            let locator = match thread.drift {
                Some(drift) => (drift.pinned_version == restored
                    && thread.anchor.version == restored)
                    .then(|| thread.anchor.locator.clone()),
                None if thread.anchor.version == restored => Some(thread.anchor.locator.clone()),
                None => self.prior_locator_in_txn(wtxn, artifact_id, &thread, restored)?,
            };
            let Some(locator) = locator else {
                continue;
            };
            if thread.anchor.version != restored {
                self.record_prior_anchor_in_txn(wtxn, artifact_id, &thread, new_version)?;
            }
            summary.remapped.push(self.reattach_in_txn(
                wtxn,
                artifact_id,
                &thread,
                new_version,
                locator,
                actor,
                occurred,
                learned_at,
            )?);
        }
        Ok(summary)
    }

    /// The task a comment's assignment made, while that comment is
    /// unattached: the task waits until the comment is reattached.
    pub fn annotation_thread_task_hold(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
    ) -> Result<Option<EntityId>> {
        let Some(thread) = self.get_annotation_thread(artifact_id, thread_id)? else {
            return Ok(None);
        };
        if !thread.is_drifted() {
            return Ok(None);
        }
        Ok(self
            .annotation_brief_for_thread(artifact_id, thread_id)?
            .map(|brief| brief.task_id))
    }

    /// Whether a thread is unattached, read in the caller's transaction.
    pub(crate) fn annotation_thread_unattached_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
        thread_id: &EntityId,
    ) -> Result<bool> {
        Ok(self
            .annotation_thread_in_txn(txn, artifact_id, thread_id, true)?
            .is_some_and(|thread| thread.is_drifted()))
    }

    fn prior_locator_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
        thread: &AnnotationThread,
        restored: u64,
    ) -> Result<Option<Locator>> {
        let mut at = thread.anchor.version;
        for _ in 0..MAX_PRIOR_HOPS {
            let Some(prior) = PRIOR.get(&self.store, txn, &(*artifact_id, thread.thread_id, at))?
            else {
                return Ok(None);
            };
            if prior.from_version == restored {
                return decode_locator(&prior.locator).map(Some);
            }
            if prior.from_version < restored || prior.from_version >= at {
                return Ok(None);
            }
            at = prior.from_version;
        }
        Ok(None)
    }

    #[expect(clippy::too_many_arguments)]
    fn reattach_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        thread: &AnnotationThread,
        version: u64,
        locator: Locator,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AnnotationThread> {
        let head = ThreadHead {
            thread_id: thread.thread_id,
            origin_version: thread.origin_version,
            anchor_version: version,
            state: thread.state,
            locator,
            drift: None,
        };
        let new_head_id = self.write_thread_head_in_txn(
            wtxn,
            artifact_id,
            &head,
            actor,
            "reattach",
            occurred,
            learned_at,
        )?;
        self.supersede_claim_in_txn(wtxn, &new_head_id, &thread.head_claim_id, learned_at)?;
        UNATTACHED.delete(&self.store, wtxn, &(*artifact_id, thread.thread_id))?;
        // The task this comment's assignment made waited while it was
        // unattached; its held attempts resume with the comment (OF-368).
        // Callers signal attempt observers after the commit.
        if let Some(brief) =
            self.annotation_brief_for_thread_in_txn(wtxn, artifact_id, &thread.thread_id)?
        {
            self.resume_annotation_held_attempts_in_txn(wtxn, &brief.task_id)?;
        }
        Ok(thread_from_head(*artifact_id, new_head_id, head))
    }
}
