//! Atomic managed annotation writes accompanying verified modern-comment exports.

use super::codec::{
    ThreadHead, annotation_envelope, decode_comment, decode_thread_head, encode_comment_value,
};
use super::threads::thread_from_head;
use super::{
    ANNOTATION_COMMENT_PREDICATE, ANNOTATION_COMMENT_TEXT_MAX_BYTES, ANNOTATION_THREAD_PREDICATE,
    Locator, ThreadState,
};
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::edit_roundtrip::pptx::{
    PptxCommentAction, PptxCommentTarget, PptxInspection, inspect_pptx,
};
use crate::edit_roundtrip::{EditOp, EditProposal};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor};
use std::collections::BTreeMap;

impl crate::Vault {
    /// Called only after candidate verification in the existing settlement txn.
    /// New threads start at the judged version. The same txn's re-anchor sweep
    /// advances them or records explicit unknown-anchor drift. No second settle
    /// token or standalone write path is introduced.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn apply_pptx_comment_annotations_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: &EntityId,
        base_version: u64,
        proposal: &EditProposal,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let bytes = self
            .read_blob_artifact_version_in_txn(txn, artifact, base_version)?
            .ok_or(Error::EntityNotFound)?;
        let inspection = inspect_pptx(&bytes).map_err(|_| invalid_anchor())?;
        let mut threads: BTreeMap<_, _> = self
            .annotation_threads_for_artifact_in_txn(txn, artifact)?
            .into_iter()
            .map(|t| (t.thread_id, t))
            .collect();
        let mut known_threads = std::collections::BTreeSet::new();
        for id in self.claims_for_subject_in_txn(txn, artifact)? {
            if let Some(body) = self.get_claim_in_txn(txn, &id)?
                && body.predicate == ANNOTATION_THREAD_PREDICATE
            {
                known_threads.insert(decode_thread_head(&body.value)?.thread_id);
            }
        }
        for op in &proposal.manifest.ops {
            let EditOp::PptxComment { patch } = op else {
                continue;
            };
            match &patch.action {
                PptxCommentAction::Add { target, text } => {
                    let locator = locator_for_target(target, &inspection)?;
                    if let Some(existing) = threads.get(&patch.thread_id) {
                        if existing.anchor.version != base_version
                            || existing.is_drifted()
                            || !same_target(&existing.anchor.locator, &locator, &inspection)
                        {
                            return Err(invalid_anchor());
                        }
                    } else {
                        if !known_threads.insert(patch.thread_id) {
                            return Err(invalid_anchor());
                        }
                        let head = ThreadHead {
                            thread_id: patch.thread_id,
                            origin_version: base_version,
                            anchor_version: base_version,
                            state: ThreadState::Open,
                            locator,
                            drift: None,
                        };
                        let id = self.write_thread_head_in_txn(
                            txn,
                            artifact,
                            &head,
                            actor,
                            "pptx_comment",
                            occurred,
                            learned_at,
                        )?;
                        threads.insert(patch.thread_id, thread_from_head(*artifact, id, head));
                    }
                    self.append_pptx_annotation_in_txn(
                        txn,
                        artifact,
                        patch.thread_id,
                        text,
                        actor,
                        occurred,
                        learned_at,
                    )?;
                }
                PptxCommentAction::Reply { text } => {
                    let thread = threads
                        .get(&patch.thread_id)
                        .ok_or(Error::Artifact(ArtifactError::AnnotationThreadNotFound))?;
                    if thread.anchor.version != base_version || thread.is_drifted() {
                        return Err(invalid_anchor());
                    }
                    self.append_pptx_annotation_in_txn(
                        txn,
                        artifact,
                        patch.thread_id,
                        text,
                        actor,
                        occurred,
                        learned_at,
                    )?;
                }
                PptxCommentAction::Resolve { resolved } => {
                    let thread = threads
                        .get(&patch.thread_id)
                        .ok_or(Error::Artifact(ArtifactError::AnnotationThreadNotFound))?;
                    if self.pptx_thread_author_in_txn(txn, artifact, patch.thread_id)?
                        != Some(actor.entity_ref())
                    {
                        return Err(Error::Artifact(ArtifactError::SettleNotAuthorized(
                            "only the managed thread's original author may resolve it",
                        )));
                    }
                    let state = if *resolved {
                        ThreadState::Resolved
                    } else {
                        ThreadState::Open
                    };
                    if thread.state != state {
                        let head = ThreadHead {
                            thread_id: thread.thread_id,
                            origin_version: thread.origin_version,
                            anchor_version: thread.anchor.version,
                            state,
                            locator: thread.anchor.locator.clone(),
                            drift: thread.drift,
                        };
                        let id = self.write_thread_head_in_txn(
                            txn,
                            artifact,
                            &head,
                            actor,
                            "pptx_resolve",
                            occurred,
                            learned_at,
                        )?;
                        self.supersede_claim_in_txn(txn, &id, &thread.head_claim_id, learned_at)?;
                        threads.insert(patch.thread_id, thread_from_head(*artifact, id, head));
                    }
                }
            }
        }
        Ok(())
    }
    #[expect(clippy::too_many_arguments)]
    fn append_pptx_annotation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: &EntityId,
        thread: EntityId,
        text: &str,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if text.trim().is_empty() || text.len() > ANNOTATION_COMMENT_TEXT_MAX_BYTES {
            return Err(invalid_anchor());
        }
        let envelope = annotation_envelope(actor, "pptx_comment")?;
        self.batch_in()
            .claim_candidate(
                &EntityId::now(),
                ClaimCandidate::new(
                    ANNOTATION_COMMENT_PREDICATE,
                    ClaimSubject::Entity(*artifact),
                    encode_comment_value(&thread, &actor.entity_ref(), text, learned_at),
                    1.0,
                ),
                &envelope,
                occurred,
                learned_at,
            )
            .apply(txn)?;
        Ok(())
    }
    fn pptx_thread_author_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        thread: EntityId,
    ) -> Result<Option<EntityId>> {
        let mut first: Option<(EntityId, EntityId)> = None;
        for id in self.claims_for_subject_in_txn(txn, artifact)? {
            let Some(body) = self.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if body.predicate != ANNOTATION_COMMENT_PREDICATE || !claim_surfaceable(&body) {
                continue;
            }
            let comment = decode_comment(&body.value, id)?;
            if comment.thread_id == thread && first.is_none_or(|(old, _)| id < old) {
                first = Some((id, comment.author));
            }
        }
        Ok(first.map(|(_, author)| author))
    }
}
fn locator_for_target(target: &PptxCommentTarget, inspection: &PptxInspection) -> Result<Locator> {
    let slide = if let Some(id) = target.slide_creation_id {
        inspection.slides.iter().find(|s| s.creation_id == Some(id))
    } else {
        inspection.slides.iter().find(|s| s.slide == target.slide)
    }
    .ok_or_else(invalid_anchor)?;
    let shape = target
        .shape_creation_id
        .as_ref()
        .map(|id| uuid::Uuid::parse_str(id).map(|id| format!("{{{id}}}").to_ascii_uppercase()))
        .transpose()
        .map_err(|_| invalid_anchor())?
        .unwrap_or_else(|| "slide".into());
    Locator::pptx(slide.slide, shape)
}
fn same_target(existing: &Locator, target: &Locator, inspection: &PptxInspection) -> bool {
    if existing == target {
        return true;
    }
    let (
        Locator::Pptx { slide, shape_id },
        Locator::Pptx {
            slide: target_slide,
            shape_id: target_shape,
        },
    ) = (existing, target)
    else {
        return false;
    };
    if slide != target_slide {
        return false;
    }
    if let Ok(id) = uuid::Uuid::parse_str(shape_id) {
        return format!("{{{id}}}").eq_ignore_ascii_case(target_shape);
    }
    let Ok(number) = shape_id.parse::<u32>() else {
        return false;
    };
    let Some(slide) = inspection.slides.iter().find(|s| s.slide == *slide) else {
        return false;
    };
    let shapes: Vec<_> = slide
        .shapes
        .iter()
        .filter(|s| s.shape_id == number)
        .collect();
    matches!(shapes.as_slice(),[shape] if shape.creation_id.as_deref()==Some(target_shape))
}
fn invalid_anchor() -> Error {
    Error::Artifact(ArtifactError::InvalidAnchor(
        "PPTX managed annotation does not match the judged target",
    ))
}
