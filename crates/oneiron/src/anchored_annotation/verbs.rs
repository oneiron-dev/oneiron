//! Credential-bound adapters over the engine's anchored annotation lifecycle.

use super::anchor_text::{
    UnitFormat, anchor_text, text_quote_for_sight, text_units_for_sight, unit_texts,
};
use super::code_units::{
    CodeFile, CodeSpace, code_file_unit, code_line_units, code_span_shown,
    file_bytes_and_space_by_hash,
};
use super::codec::decode_thread_head;
use super::wire::{
    AnnotationAnchorView, AnnotationAssignRequest, AnnotationBriefView, AnnotationCommentRequest,
    AnnotationCommentView, AnnotationPinRequest, AnnotationResolution, AnnotationStateRequest,
    AnnotationThreadOpenRequest, AnnotationThreadRequest, AnnotationThreadView, ArtifactUnitView,
    ArtifactUnitsRequest, ArtifactUnitsView,
};
use super::{
    ANNOTATION_THREAD_PREDICATE, Anchor, AnnotationThread, BodyAnchor, CODE_ANCHOR_VERSION,
    Locator, PLAN_DOC_ANCHOR_VERSION, TaskBrief,
};
use crate::blob_artifact::{ArtifactKind, ArtifactRefRequest};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult, resolve_entity_ref};
use crate::registry::{ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_NOTE};
use crate::secret_custody::SecretSight;
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
            reason: "this kind has no annotation unit adapter".to_owned(),
        };
        if kind == ArtifactKind::Code {
            return self.code_artifact_units(artifact, input);
        }
        let sight = self.secret_sight()?;
        let file = self
            .vault()
            .export_blob_artifact_as_raw(&artifact, input.version, sight)?
            .ok_or_else(|| MemoryError::not_found("artifact version not found"))?;
        let Some(format) = UnitFormat::from_media_type(&file.media_type) else {
            return Ok(unsupported(file.kind));
        };
        if matches!(format, UnitFormat::Text) {
            // Main's per-line units keep raw coordinates. Only their quotes
            // are projected to this caller's sight, from the same resolved
            // version rather than from a moving head.
            let raw = self
                .vault()
                .export_blob_artifact_raw(&artifact, Some(file.version))?
                .ok_or_else(|| MemoryError::not_found("artifact version not found"))?;
            let sighted = if sight == SecretSight::Masked {
                file.bytes.as_slice()
            } else {
                raw.bytes.as_slice()
            };
            let units = text_units_for_sight(&raw.bytes, sighted)
                .ok_or_else(|| MemoryError::bad_request("artifact units could not be read"))?
                .into_iter()
                .map(|(locator, quote)| ArtifactUnitView {
                    locator: (&locator).into(),
                    quote,
                })
                .collect();
            return Ok(ArtifactUnitsView::Supported {
                artifact_id: artifact,
                version: file.version,
                content_hash: crate::blob_artifact::hash_hex(&file.content_hash),
                kind: file.kind,
                units,
            });
        }
        let limits = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            self.vault().text_limits_in_txn(&txn)?
        };
        // A resource refusal is the engine's error (FIX 10587), never unreadable units.
        let units = unit_texts(&file.bytes, format, &limits)?
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

    /// `vault.artifacts.units` for a code artifact: the files its snapshot
    /// reads at the artifact's repo_ref commit, a withheld path read as
    /// absent. Without a path, one whole-file unit per file that reads as
    /// text, with no quote (a code file's words are read by pin or with
    /// `path`); with a path, that file's lines with their words. Units count
    /// the caller's text; a file whose offsets do not translate to the
    /// owner's text has none (FIX 22109).
    fn code_artifact_units(
        &self,
        artifact: EntityId,
        input: &ArtifactUnitsRequest,
    ) -> MemoryResult<ArtifactUnitsView> {
        require_code_anchor_version(input.version)?;
        let Some(mount) = self.vault().mount_codebase_snapshot(&artifact)? else {
            return Ok(ArtifactUnitsView::Unsupported {
                artifact_id: artifact,
                kind: ArtifactKind::Code,
                reason: "this code artifact has no snapshot to read".to_owned(),
            });
        };
        let snapshot = mount.snapshot();
        let commit = snapshot
            .repo_ref
            .commit_hash()
            .ok_or(Error::InvariantViolation("a repo_ref names its commit"))?;
        let sight = self.code_file_sight()?;
        let units = match input.path.as_deref() {
            None => {
                let mut units = Vec::new();
                for entry in &snapshot.files {
                    if mount.is_withheld(&entry.path) {
                        continue;
                    }
                    let Some((bytes, space)) =
                        self.code_file_bytes_and_space(&entry.content_hash, sight)?
                    else {
                        continue;
                    };
                    if space.is_unmappable() {
                        continue;
                    }
                    // A file that is not text, or whose path is past the
                    // locator bound, has no code span.
                    if let Some(locator) =
                        code_file_unit(commit, &entry.path, &entry.content_hash, &bytes)
                    {
                        units.push(ArtifactUnitView {
                            locator: (&locator).into(),
                            quote: None,
                        });
                    }
                }
                units
            }
            Some(path) => {
                let absent =
                    || MemoryError::not_found("the code artifact has no such file to read");
                let entry = snapshot
                    .files
                    .binary_search_by(|entry| entry.path.as_str().cmp(path))
                    .ok()
                    .map(|at| &snapshot.files[at])
                    .filter(|entry| !mount.is_withheld(&entry.path))
                    .ok_or_else(absent)?;
                let (bytes, space) = self
                    .code_file_bytes_and_space(&entry.content_hash, sight)?
                    .ok_or_else(absent)?;
                if space.is_unmappable() {
                    Vec::new()
                } else {
                    code_line_units(commit, path, &entry.content_hash, &bytes)?
                        .ok_or_else(|| {
                            MemoryError::bad_request("artifact units could not be read")
                        })?
                        .into_iter()
                        .map(|(locator, quote)| ArtifactUnitView {
                            locator: (&locator).into(),
                            quote,
                        })
                        .collect()
                }
            }
        };
        Ok(ArtifactUnitsView::Supported {
            artifact_id: artifact,
            version: CODE_ANCHOR_VERSION,
            content_hash: bytes_to_hex_lower(&snapshot.fork_hash),
            kind: ArtifactKind::Code,
            units,
        })
    }

    /// The text of an exact immutable anchor, through the caller's file sight.
    fn annotation_anchor_view(&self, anchor: &Anchor) -> MemoryResult<AnnotationAnchorView> {
        match self.vault().get_entity_type(&anchor.artifact_id)? {
            Some(ENTITY_TYPE_CODE_ARTIFACT) => return self.code_anchor_view(anchor),
            Some(ENTITY_TYPE_NOTE) => return Ok(self.plan_doc_anchor_views(anchor)?.0),
            _ => {}
        }
        let sight = self.secret_sight()?;
        let file = self
            .vault()
            .export_blob_artifact_as_raw(&anchor.artifact_id, Some(anchor.version), sight)?
            .ok_or_else(|| MemoryError::not_found("anchor version not found"))?;
        let limits = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            self.vault().text_limits_in_txn(&txn)?
        };
        // A resource refusal is the engine's error (FIX 10587), never a missing quote.
        // A text span names raw coordinates; its quote is the door's sighted
        // copy there for masked readers, never raw bytes.
        let quote = if let Locator::Text {
            char_start,
            char_end,
        } = &anchor.locator
        {
            let raw = self
                .vault()
                .export_blob_artifact_raw(&anchor.artifact_id, Some(anchor.version))?
                .ok_or_else(|| MemoryError::not_found("anchor version not found"))?;
            let sighted = if sight == SecretSight::Masked {
                file.bytes.as_slice()
            } else {
                raw.bytes.as_slice()
            };
            text_quote_for_sight(&raw.bytes, sighted, *char_start, *char_end)
        } else {
            anchor_text(&file.bytes, &anchor.locator, &limits)?
        };
        Ok(AnnotationAnchorView {
            artifact_id: anchor.artifact_id,
            version: anchor.version,
            locator: (&anchor.locator).into(),
            quote,
            body: anchor.body.as_ref().map(Into::into),
        })
    }

    /// The words of an exact code anchor, read from the file its hash names
    /// through the caller's code file sight (FIX 7905). A code artifact takes
    /// only a code locator at [`CODE_ANCHOR_VERSION`]. The stored locator
    /// counts the owner's text and the view reads in the caller's (FIX
    /// 22109); a spot that does not read, or whose offsets do not translate,
    /// keeps the stored locator with no words.
    fn code_anchor_view(&self, anchor: &Anchor) -> MemoryResult<AnnotationAnchorView> {
        require_code_anchor_version(Some(anchor.version))?;
        if !matches!(anchor.locator, Locator::Code { .. }) {
            return Err(MemoryError::bad_request(
                "locator format does not match the artifact",
            ));
        }
        let readable = match CodeFile::of(&anchor.locator) {
            Some(file) => self.code_file_row_readable(&file.hash)?,
            None => false,
        };
        let shown = if readable {
            code_span_shown(
                self.vault(),
                &anchor.artifact_id,
                &anchor.locator,
                self.code_file_sight()?,
            )?
        } else {
            None
        };
        let (locator, quote) = shown.unwrap_or_else(|| (anchor.locator.clone(), None));
        Ok(AnnotationAnchorView {
            artifact_id: anchor.artifact_id,
            version: anchor.version,
            locator: (&locator).into(),
            quote,
            body: anchor.body.as_ref().map(Into::into),
        })
    }

    /// `vault.artifacts.anchors.pin` on a code artifact: the locator names
    /// the artifact's current repo_ref commit and that commit's file hash for
    /// a path its snapshot reads, and its span holds words. The span is read
    /// in the caller's text and pins at the owner's (FIX 22109): the anchor
    /// holds that canonical locator, and the view reads it in the caller's
    /// text again. A file whose offsets do not translate pins nothing.
    fn code_anchor_pin(
        &self,
        artifact: EntityId,
        input: &AnnotationPinRequest,
    ) -> MemoryResult<(Anchor, AnnotationAnchorView)> {
        require_code_anchor_version(input.version)?;
        let locator = Locator::try_from(&input.locator)?;
        let Some(file) = CodeFile::of(&locator) else {
            return Err(MemoryError::bad_request(
                "locator format does not match the artifact",
            ));
        };
        let unreadable =
            || MemoryError::bad_request("the exact locator has no readable unambiguous quote");
        let mount = self
            .vault()
            .mount_codebase_snapshot(&artifact)?
            .ok_or_else(unreadable)?;
        let snapshot = mount.snapshot();
        let current = snapshot.repo_ref.commit_hash() == Some(file.commit)
            && !mount.is_withheld(file.path)
            && snapshot
                .files
                .binary_search_by(|entry| entry.path.as_str().cmp(file.path))
                .is_ok_and(|at| snapshot.files[at].content_hash == file.hash);
        if !current {
            return Err(unreadable());
        }
        let (_, space) = self
            .code_file_bytes_and_space(&file.hash, self.code_file_sight()?)?
            .ok_or_else(unreadable)?;
        let raw = space.raw_locator(&locator).ok_or_else(unreadable)?;
        let anchor = Anchor::new(artifact, CODE_ANCHOR_VERSION, raw);
        let pin = self.code_anchor_view(&anchor)?;
        if pin.quote.is_none() {
            return Err(unreadable());
        }
        Ok((anchor, pin))
    }

    /// `vault.artifacts.anchors.pin`: a readable locator in a real version.
    /// The version and locator, not a matching-text search, define the pin.
    pub fn artifacts_anchors_pin(
        &self,
        input: &AnnotationPinRequest,
    ) -> MemoryResult<AnnotationAnchorView> {
        Ok(self.anchor_pin(input)?.1)
    }

    /// [`Self::artifacts_anchors_pin`] with the anchor its view reads: the
    /// canonical anchor a thread opened on the pin stores, a code span at
    /// the owner's offsets (FIX 22109).
    fn anchor_pin(
        &self,
        input: &AnnotationPinRequest,
    ) -> MemoryResult<(Anchor, AnnotationAnchorView)> {
        let artifact = resolve_entity_ref(self.vault(), &input.artifact_ref)?;
        match self.vault().get_entity_type(&artifact)? {
            Some(ENTITY_TYPE_CODE_ARTIFACT) => return self.code_anchor_pin(artifact, input),
            Some(ENTITY_TYPE_NOTE) => return self.plan_doc_anchor_pin(artifact, input),
            _ => {}
        }
        let file = self
            .vault()
            .export_blob_artifact_as_raw(&artifact, input.version, self.secret_sight()?)?
            .ok_or_else(|| MemoryError::not_found("artifact version not found"))?;
        let locator = Locator::try_from(&input.locator)?;
        let format = UnitFormat::from_media_type(&file.media_type).ok_or_else(|| {
            MemoryError::bad_request("locator format does not match the artifact")
        })?;
        let matches = matches!(
            (format, &locator),
            (
                UnitFormat::Docx,
                Locator::Docx { .. } | Locator::DocxStory { .. }
            ) | (UnitFormat::Xlsx, Locator::Xlsx { .. })
                | (UnitFormat::Pptx, Locator::Pptx { .. })
                | (UnitFormat::Html, Locator::Html { .. })
                | (UnitFormat::Text, Locator::Text { .. })
        );
        if !matches {
            return Err(MemoryError::bad_request(
                "locator format does not match the artifact",
            ));
        }
        let anchor = Anchor::new(artifact, file.version, locator);
        let pin = self.annotation_anchor_view(&anchor)?;
        if pin.quote.is_none() {
            return Err(MemoryError::bad_request(
                "the exact locator has no readable unambiguous quote",
            ));
        }
        Ok((anchor, pin))
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
        let on_note =
            self.vault().get_entity_type(&thread.anchor.artifact_id)? == Some(ENTITY_TYPE_NOTE);
        let (origin, anchor, resolution) = if on_note {
            // A plan-doc thread's head keeps the span it was opened on;
            // where that span stands is read now.
            self.plan_doc_anchor_views(&thread.anchor)?
        } else {
            let origin = self.annotation_origin(&thread)?;
            let resolution = if thread.drift.is_some() {
                AnnotationResolution::Drifted
            } else if thread.anchor.version == origin.version
                && thread.anchor.locator == origin.locator
            {
                AnnotationResolution::Pinned
            } else {
                AnnotationResolution::Mapped
            };
            (
                self.annotation_anchor_view(&origin)?,
                self.annotation_anchor_view(&thread.anchor)?,
                resolution,
            )
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
            origin,
            anchor,
            resolution,
            drift: thread.drift.map(Into::into),
            state: thread.state.into(),
            head_claim_id: thread.head_claim_id,
            comments,
            brief,
            sub_session_id: thread.sub_session_id,
        })
    }

    /// `vault.artifacts.anchors.pin` on a plan-doc NOTE (plan mode's
    /// markup): a text span of the plan-doc's text at its head, read
    /// through the caller's NOTE read. The anchor holds the span at
    /// [`PLAN_DOC_ANCHOR_VERSION`] and, as its body, the frontier it was
    /// read at; any other NOTE takes no anchor.
    fn plan_doc_anchor_pin(
        &self,
        plan: EntityId,
        input: &AnnotationPinRequest,
    ) -> MemoryResult<(Anchor, AnnotationAnchorView)> {
        if input
            .version
            .is_some_and(|version| version != PLAN_DOC_ANCHOR_VERSION)
        {
            return Err(MemoryError::bad_request(
                "a plan-doc's anchor version is PLAN_DOC_ANCHOR_VERSION (0)",
            ));
        }
        let Locator::Text {
            char_start,
            char_end,
        } = Locator::try_from(&input.locator)?
        else {
            return Err(MemoryError::bad_request(
                "locator format does not match the artifact",
            ));
        };
        let span = self
            .plan_doc_head_span(plan, char_start, char_end)?
            .ok_or_else(|| MemoryError::not_found("plan-doc not found"))?;
        let locator = Locator::Text {
            char_start,
            char_end,
        };
        let body = BodyAnchor {
            frontier: span.frontier,
            locator: locator.clone(),
        };
        let view = AnnotationAnchorView {
            artifact_id: plan,
            version: PLAN_DOC_ANCHOR_VERSION,
            locator: (&locator).into(),
            quote: Some(span.quote),
            body: Some((&body).into()),
        };
        let anchor = Anchor {
            artifact_id: plan,
            version: PLAN_DOC_ANCHOR_VERSION,
            locator,
            body: Some(body),
        };
        Ok((anchor, view))
    }

    /// A plan-doc anchor's view at the span it names, and the same span's
    /// view at the head with where it stands, read through the caller's NOTE
    /// read: pinned while the span sits at its opening offsets, mapped where
    /// an edit before it moved it, drifted where its characters no longer
    /// all stand with the same text. A drifted anchor stays on the span it
    /// names. An anchor with no frontier (a brief's copy) reads no words.
    fn plan_doc_anchor_views(
        &self,
        anchor: &Anchor,
    ) -> MemoryResult<(
        AnnotationAnchorView,
        AnnotationAnchorView,
        AnnotationResolution,
    )> {
        let view = |locator: &Locator, body: Option<&BodyAnchor>, quote: Option<String>| {
            AnnotationAnchorView {
                artifact_id: anchor.artifact_id,
                version: anchor.version,
                locator: locator.into(),
                quote,
                body: body.map(Into::into),
            }
        };
        let (
            Locator::Text {
                char_start,
                char_end,
            },
            Some(body),
        ) = (&anchor.locator, &anchor.body)
        else {
            let named = view(&anchor.locator, anchor.body.as_ref(), None);
            return Ok((named.clone(), named, AnnotationResolution::Pinned));
        };
        let read = self
            .plan_doc_span_read(anchor.artifact_id, &body.frontier, *char_start, *char_end)?
            .ok_or_else(|| MemoryError::not_found("plan-doc not found"))?;
        let named = view(&anchor.locator, Some(body), read.quote);
        let Some(head) = read.head else {
            return Ok((named.clone(), named, AnnotationResolution::Drifted));
        };
        let locator = Locator::Text {
            char_start: head.char_start,
            char_end: head.char_end,
        };
        let resolution = if locator == anchor.locator {
            AnnotationResolution::Pinned
        } else {
            AnnotationResolution::Mapped
        };
        let head_body = BodyAnchor {
            frontier: head.frontier,
            locator: locator.clone(),
        };
        let now = view(&locator, Some(&head_body), Some(head.quote));
        Ok((named, now, resolution))
    }

    /// `vault.artifacts.threads.open`: caller-stamped pin and opening comment.
    pub fn artifacts_threads_open(
        &self,
        input: &AnnotationThreadOpenRequest,
    ) -> MemoryResult<AnnotationThreadView> {
        // The thread stores the pin's canonical anchor, never its view: a
        // code view reads in the caller's text (FIX 22109).
        let (anchor, _) = self.anchor_pin(&AnnotationPinRequest {
            artifact_ref: input.artifact_ref.clone(),
            version: Some(input.version),
            locator: input.locator.clone(),
        })?;
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

/// A code artifact's anchor version is [`CODE_ANCHOR_VERSION`]; a request
/// may leave it out.
impl Memory<'_> {
    /// How the caller reads a code file's bytes, as the snapshot file face
    /// reads them: the stored bytes only for the vault owner's key on a
    /// handle whose repo reads are not masked; masked otherwise, a file a
    /// repo mark covers as its masked copy (FIX 8964). An MCP tool call or a
    /// code run on the owner's key reads masked.
    fn code_file_sight(&self) -> MemoryResult<crate::secret_custody::SecretSight> {
        if self.repo_reads_masked()? {
            return Ok(crate::secret_custody::SecretSight::Masked);
        }
        self.secret_sight()
    }

    /// Whether the caller's credential reads the ASSET row that holds a code
    /// file's bytes, as the code snapshot doors require of each file they
    /// read (`codebase_readable`, FIX 7905). Absent and withheld read alike.
    fn code_file_row_readable(&self, hash: &[u8; 32]) -> MemoryResult<bool> {
        let row = crate::store::code_snapshot::codebase_asset_entity_id(hash)?;
        self.produced_from([row]);
        Ok(self.get_entity_tolerant(&row.to_hex())?.value.is_some())
    }

    /// A code file's bytes by its hash, through the caller's row read and
    /// code file sight, with how their offsets translate to the owner's text
    /// (FIX 22109); `None` when the caller does not read its row or the
    /// ASSET is gone.
    fn code_file_bytes_and_space(
        &self,
        hash: &[u8; 32],
        sight: crate::secret_custody::SecretSight,
    ) -> MemoryResult<Option<(Vec<u8>, CodeSpace)>> {
        if !self.code_file_row_readable(hash)? {
            return Ok(None);
        }
        Ok(file_bytes_and_space_by_hash(self.vault(), hash, sight)?)
    }
}

fn require_code_anchor_version(version: Option<u64>) -> MemoryResult<()> {
    if version.is_some_and(|version| version != CODE_ANCHOR_VERSION) {
        return Err(MemoryError::bad_request(
            "a code artifact's anchor version is CODE_ANCHOR_VERSION (0)",
        ));
    }
    Ok(())
}
