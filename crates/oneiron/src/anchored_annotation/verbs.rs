//! Credential-bound adapters over the engine's anchored annotation lifecycle.

use super::anchor_text::{anchor_text, unit_texts};
use super::codec::decode_thread_head;
use super::wire::{
    AnnotationAnchorView, AnnotationAssignRequest, AnnotationBriefView, AnnotationCommentRequest,
    AnnotationCommentView, AnnotationPinRequest, AnnotationResolution, AnnotationStateRequest,
    AnnotationThreadOpenRequest, AnnotationThreadRequest, AnnotationThreadView, ArtifactUnitView,
    ArtifactUnitsRequest, ArtifactUnitsView,
};
use super::{ANNOTATION_THREAD_PREDICATE, Anchor, AnnotationThread, Locator, TaskBrief};
use crate::blob_artifact::{ArtifactKind, ArtifactRefRequest};
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult, resolve_entity_ref};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

impl Memory<'_> {
    fn annotation_actor(&self) -> WriteActor {
        self.write_actor()
    }

    fn annotation_moment(&self) -> (TimeRange, u64) {
        let now = self.vault().now_recorded_at();
        (
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
    }

    /// `vault.artifacts.units`: actual version units, or an explicit lack of
    /// an annotation adapter. Kind enum membership alone promises no reader.
    pub fn artifacts_units(&self, input: &ArtifactUnitsRequest) -> MemoryResult<ArtifactUnitsView> {
        let artifact = resolve_entity_ref(self.vault(), &input.artifact_ref)?;
        let kind = self
            .vault()
            .artifact_kind(&artifact)?
            .ok_or_else(|| MemoryError::not_found("artifact not found"))?;
        let unsupported = |kind| ArtifactUnitsView::Unsupported {
            artifact_id: artifact,
            kind,
            reason: "this kind has no office annotation unit adapter".to_owned(),
        };
        if kind == ArtifactKind::Code {
            return Ok(unsupported(kind));
        }
        let file = self
            .vault()
            .export_blob_artifact_as_raw(&artifact, input.version, self.secret_sight()?)?
            .ok_or_else(|| MemoryError::not_found("artifact version not found"))?;
        let Ok(format) = OfficeFormat::from_media_type(&file.media_type) else {
            return Ok(unsupported(file.kind));
        };
        let limits = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            self.vault().text_limits_in_txn(&txn)?
        };
        let units = unit_texts(&file.bytes, format, &limits)
            .ok_or_else(|| MemoryError::bad_request("artifact units could not be read"))?
            .into_iter()
            .map(|(locator, quote)| ArtifactUnitView {
                locator: (&locator).into(),
                quote,
            })
            .collect();
        Ok(ArtifactUnitsView::Supported {
            artifact_id: artifact,
            version: file.version,
            content_hash: crate::blob_artifact::hash_hex(&file.content_hash),
            kind: file.kind,
            units,
        })
    }

    /// The text of an exact immutable anchor, through the caller's file sight.
    fn annotation_anchor_view(&self, anchor: &Anchor) -> MemoryResult<AnnotationAnchorView> {
        let file = self
            .vault()
            .export_blob_artifact_as_raw(
                &anchor.artifact_id,
                Some(anchor.version),
                self.secret_sight()?,
            )?
            .ok_or_else(|| MemoryError::not_found("anchor version not found"))?;
        let limits = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            self.vault().text_limits_in_txn(&txn)?
        };
        Ok(AnnotationAnchorView {
            artifact_id: anchor.artifact_id,
            version: anchor.version,
            locator: (&anchor.locator).into(),
            quote: anchor_text(&file.bytes, &anchor.locator, &limits),
        })
    }

    /// `vault.artifacts.anchors.pin`: a readable locator in a real version.
    /// The version and locator, not a matching-text search, define the pin.
    pub fn artifacts_anchors_pin(
        &self,
        input: &AnnotationPinRequest,
    ) -> MemoryResult<AnnotationAnchorView> {
        let artifact = resolve_entity_ref(self.vault(), &input.artifact_ref)?;
        let file = self
            .vault()
            .export_blob_artifact_as_raw(&artifact, input.version, self.secret_sight()?)?
            .ok_or_else(|| MemoryError::not_found("artifact version not found"))?;
        let locator = Locator::try_from(&input.locator)?;
        let format = OfficeFormat::from_media_type(&file.media_type)?;
        let matches = matches!(
            (format, &locator),
            (OfficeFormat::Docx, Locator::Docx { .. })
                | (OfficeFormat::Xlsx, Locator::Xlsx { .. })
                | (OfficeFormat::Pptx, Locator::Pptx { .. })
        );
        if !matches {
            return Err(MemoryError::bad_request(
                "locator format does not match the artifact",
            ));
        }
        let pin = self.annotation_anchor_view(&Anchor::new(artifact, file.version, locator))?;
        if pin.quote.is_none() {
            return Err(MemoryError::bad_request(
                "the exact locator has no readable unambiguous quote",
            ));
        }
        Ok(pin)
    }

    /// Reconstructs the durable opening locator from its append-only head
    /// claim. The version bytes retain its quote, even after mapping or drift.
    fn annotation_origin(&self, thread: &AnnotationThread) -> MemoryResult<Anchor> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let mut first = None;
        for claim_id in vault.claims_for_subject_in_txn(&txn, &thread.anchor.artifact_id)? {
            let Some(body) = vault.get_claim_in_txn(&txn, &claim_id)? else {
                continue;
            };
            if body.predicate != ANNOTATION_THREAD_PREDICATE {
                continue;
            }
            let Ok(head) = decode_thread_head(&body.value) else {
                continue;
            };
            if head.thread_id == thread.thread_id
                && head.anchor_version == thread.origin_version
                && first.as_ref().is_none_or(|(id, _)| claim_id < *id)
            {
                first = Some((claim_id, head.locator));
            }
        }
        let (_, locator) = first.ok_or(Error::InvariantViolation(
            "annotation opening pin is missing",
        ))?;
        Ok(Anchor::new(
            thread.anchor.artifact_id,
            thread.origin_version,
            locator,
        ))
    }

    fn annotation_brief_view(&self, brief: TaskBrief) -> MemoryResult<AnnotationBriefView> {
        Ok(AnnotationBriefView {
            brief_ref: brief.brief_ref,
            task_id: brief.task_id,
            thread_id: brief.thread_id,
            anchor: self.annotation_anchor_view(&brief.anchor)?,
            artifact_version: brief.artifact_version,
            thread_text: brief.thread_text,
            assignee: brief.assignee,
        })
    }

    fn annotation_thread_view(
        &self,
        thread: AnnotationThread,
    ) -> MemoryResult<AnnotationThreadView> {
        let origin = self.annotation_origin(&thread)?;
        let resolution = if thread.drift.is_some() {
            AnnotationResolution::Drifted
        } else if thread.anchor == origin {
            AnnotationResolution::Pinned
        } else {
            AnnotationResolution::Mapped
        };
        let comments = self
            .vault()
            .annotation_thread_comments(&thread.anchor.artifact_id, &thread.thread_id)?
            .into_iter()
            .map(AnnotationCommentView::from)
            .collect();
        let brief = self
            .vault()
            .annotation_brief_for_thread(&thread.anchor.artifact_id, &thread.thread_id)?
            .map(|brief| self.annotation_brief_view(brief))
            .transpose()?;
        Ok(AnnotationThreadView {
            thread_id: thread.thread_id,
            origin: self.annotation_anchor_view(&origin)?,
            anchor: self.annotation_anchor_view(&thread.anchor)?,
            resolution,
            drift: thread.drift.map(Into::into),
            state: thread.state.into(),
            head_claim_id: thread.head_claim_id,
            comments,
            brief,
        })
    }

    /// `vault.artifacts.threads.open`: caller-stamped pin and opening comment.
    pub fn artifacts_threads_open(
        &self,
        input: &AnnotationThreadOpenRequest,
    ) -> MemoryResult<AnnotationThreadView> {
        let pin = self.artifacts_anchors_pin(&AnnotationPinRequest {
            artifact_ref: input.artifact_ref.clone(),
            version: Some(input.version),
            locator: input.locator.clone(),
        })?;
        let anchor = Anchor::new(
            pin.artifact_id,
            pin.version,
            Locator::try_from(&pin.locator)?,
        );
        let (occurred, now) = self.annotation_moment();
        let thread = self.vault().open_annotation_thread(
            &anchor,
            self.annotation_actor(),
            &input.text,
            occurred,
            now,
        )?;
        self.annotation_thread_view(thread)
    }

    /// Appends through the engine. A long comment's first stored part is
    /// returned; threads.read lists every linked part in authored order.
    pub fn artifacts_threads_comment(
        &self,
        input: &AnnotationCommentRequest,
    ) -> MemoryResult<AnnotationCommentView> {
        let artifact = resolve_entity_ref(self.vault(), &input.artifact_ref)?;
        let thread = EntityId::from_hex(&input.thread_ref)?;
        let (occurred, now) = self.annotation_moment();
        Ok(self
            .vault()
            .add_annotation_comment(
                &artifact,
                &thread,
                self.annotation_actor(),
                &input.text,
                occurred,
                now,
            )?
            .into())
    }

    /// Reads the engine's current mapping or drift, never reattaching by text.
    pub fn artifacts_threads_read(
        &self,
        input: &AnnotationThreadRequest,
    ) -> MemoryResult<Option<AnnotationThreadView>> {
        let artifact = resolve_entity_ref(self.vault(), &input.artifact_ref)?;
        let thread = EntityId::from_hex(&input.thread_ref)?;
        self.vault()
            .get_annotation_thread(&artifact, &thread)?
            .map(|thread| self.annotation_thread_view(thread))
            .transpose()
    }

    pub fn artifacts_threads_list(
        &self,
        input: &ArtifactRefRequest,
    ) -> MemoryResult<Vec<AnnotationThreadView>> {
        let artifact = resolve_entity_ref(self.vault(), &input.artifact_ref)?;
        self.vault()
            .annotation_threads_for_artifact(&artifact)?
            .into_iter()
            .map(|thread| self.annotation_thread_view(thread))
            .collect()
    }

    /// Assignment, durable transcript and any agent dispatch belong to the
    /// engine's one transaction, under its existing claim/effect gate.
    pub fn artifacts_threads_assign(
        &self,
        input: &AnnotationAssignRequest,
    ) -> MemoryResult<AnnotationBriefView> {
        let artifact = resolve_entity_ref(self.vault(), &input.artifact_ref)?;
        let thread = EntityId::from_hex(&input.thread_ref)?;
        let assignee = input
            .assignee_ref
            .as_deref()
            .map(|reference| resolve_entity_ref(self.vault(), reference))
            .transpose()?;
        let (occurred, now) = self.annotation_moment();
        let brief = self.vault().assign_annotation_thread_to_brief(
            &artifact,
            &thread,
            assignee,
            self.annotation_actor(),
            occurred,
            now,
        )?;
        self.annotation_brief_view(brief)
    }

    pub fn artifacts_threads_state(
        &self,
        input: &AnnotationStateRequest,
    ) -> MemoryResult<AnnotationThreadView> {
        let artifact = resolve_entity_ref(self.vault(), &input.artifact_ref)?;
        let thread = EntityId::from_hex(&input.thread_ref)?;
        let (occurred, now) = self.annotation_moment();
        let updated = self.vault().set_annotation_thread_state(
            &artifact,
            &thread,
            input.state.into(),
            self.annotation_actor(),
            occurred,
            now,
        )?;
        self.annotation_thread_view(updated)
    }
}
