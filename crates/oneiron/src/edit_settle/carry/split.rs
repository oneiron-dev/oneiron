//! Splitting carried editor answers into their native units.

use super::*;

impl Vault {
    pub(super) fn split_sheet_answers(
        &self,
        artifact: &EntityId,
        proposal: &EditProposal,
        bundle: &SheetAnswerBundle,
        made_by: Option<&MadeBy>,
        carry: bool,
    ) -> Result<Option<Split>> {
        let Some(base_version) = proposal.base_version else {
            return Ok(None);
        };
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let moved = head.version != base_version || head.content_hash != proposal.base_content_hash;
        // Each folder answer's file as it stands now: its head and hash.
        let mut files = Vec::with_capacity(bundle.answers.len());
        let mut files_moved = false;
        for answer in &bundle.answers {
            let now = match &answer.source {
                Some(pin) => {
                    let now = self
                        .blob_artifact_head(&pin.id)?
                        .map(|file| (file.version, file.content_hash));
                    files_moved |= now.is_none_or(|(_, hash)| hash != pin.body_hash);
                    now
                }
                None => None,
            };
            files.push(now);
        }
        // An edit to a live body never exported moves no version (FIX 2115).
        let live = self.live_sheet_split(artifact, bundle)?;
        if !moved && !files_moved && !live.moved() {
            return Ok(None);
        }
        let answer_col = bundle.range.start.col;
        let rows: BTreeSet<u32> = bundle
            .answers
            .iter()
            .map(|answer| answer.cell.row)
            .collect();
        let reads = bundle.reads;
        let read_cols: Vec<u32> = reads
            .map(|reads| {
                (reads.first_col..=reads.last_col)
                    .filter(|col| *col != answer_col)
                    .collect()
            })
            .unwrap_or_default();
        let header_row = reads.and_then(|reads| reads.header_row);
        let wanted = |cell: &CellRef| {
            (cell.col == answer_col && rows.contains(&cell.row))
                || (read_cols.contains(&cell.col)
                    && (rows.contains(&cell.row) || Some(cell.row) == header_row))
        };
        // The cells the answers read and write, at their base and on the head.
        let (then, now) = if moved {
            let base = self
                .read_blob_artifact_version(artifact, base_version)?
                .ok_or(Error::EntityNotFound)?;
            let current = self
                .read_blob_artifact_version(artifact, head.version)?
                .ok_or(Error::EntityNotFound)?;
            (
                named_sheet_cells(&base, &bundle.sheet, &wanted)?,
                named_sheet_cells(&current, &bundle.sheet, &wanted).ok(),
            )
        } else {
            (Default::default(), None)
        };
        // Rows read on the live body: their read cells and header compare
        // from the newest export since the base, which holds them as the body
        // did at its frontier, compared with the pin (FIX 12017). The answer
        // cell was read on the version and compares from the base.
        let exported = self.export_span(
            artifact,
            bundle.base_live.as_ref(),
            base_version,
            head.version,
        )?;
        let exported_sheet = match &exported {
            Some(span) => self.live_sheet_until(
                artifact,
                bundle.base_live.as_ref(),
                &bundle.sheet,
                Some((span.frontier.as_slice(), span.version)),
            )?,
            None => None,
        };
        let export_cells = match exported.as_ref().and_then(|span| span.bytes.as_ref()) {
            Some(bytes) => named_sheet_cells(bytes, &bundle.sheet, &wanted).ok(),
            None => None,
        };
        let read_from = match &exported {
            Some(span) if span.bytes.is_none() => now.as_ref(),
            Some(_) => export_cells.as_ref(),
            None => Some(&then),
        };
        let differs = |from: Option<&std::collections::BTreeMap<CellRef, CellValue>>,
                       cell: CellRef| {
            let read = |cells: &std::collections::BTreeMap<CellRef, CellValue>| {
                cells.get(&cell).cloned().unwrap_or(CellValue::Blank)
            };
            match (from, now.as_ref()) {
                (Some(from), Some(now)) => read(from) != read(now),
                _ => true,
            }
        };
        let header_changed = moved
            && header_row.is_some_and(|row| {
                read_cols
                    .iter()
                    .any(|col| differs(read_from, CellRef { col: *col, row }))
            });
        let mut kept = Vec::new();
        let mut withdrawn = Vec::new();
        for (index, (answer, file)) in bundle.answers.iter().zip(&files).enumerate() {
            let blob = if moved && now.is_none() {
                Some(WithdrawReason::UnitMissing)
            } else if moved && differs(Some(&then), answer.cell) {
                Some(WithdrawReason::AnswerCellChanged)
            } else if moved
                && (header_changed
                    || read_cols.iter().any(|col| {
                        differs(
                            read_from,
                            CellRef {
                                col: *col,
                                row: answer.cell.row,
                            },
                        )
                    }))
            {
                Some(WithdrawReason::UnitChanged)
            } else if let Some(reason) = exported_sheet
                .as_ref()
                .and_then(|sheet| live::sheet_row_reason(sheet, answer, &read_cols, header_row))
            {
                Some(reason)
            } else if let Some(pin) = &answer.source {
                match file {
                    None => Some(WithdrawReason::UnitMissing),
                    Some((version, hash))
                        if *hash != pin.body_hash
                            && self.folder_file_changed(answer, pin, (*version, *hash))? =>
                    {
                        Some(WithdrawReason::UnitChanged)
                    }
                    Some(_) => None,
                }
            } else {
                None
            };
            let live_change = live.reason(index, answer, &read_cols, header_row);
            let Some(reason) = blob.or(live_change.as_ref().map(|(reason, _)| *reason)) else {
                kept.push(answer.clone());
                continue;
            };
            let (unit, judged_on, judged_hash, changed_version) = match &answer.source {
                Some(pin) => (
                    WithdrawnUnit::FolderItem {
                        file: pin.id,
                        row: answer.cell.row,
                    },
                    pin.id,
                    pin.body_hash,
                    match reason {
                        WithdrawReason::AnswerCellChanged => Some(head.version),
                        _ => file.map(|(version, _)| version),
                    },
                ),
                None => (
                    WithdrawnUnit::SheetRow {
                        row: answer.cell.row,
                    },
                    *artifact,
                    proposal.base_content_hash,
                    Some(head.version),
                ),
            };
            withdrawn.push(WithdrawnAnswer {
                unit,
                judged_on,
                judged_version: answer.judged_version,
                judged_hash,
                changed_version: blob.and(changed_version),
                judged_live: match &answer.source {
                    Some(_) => answer.judged_live.clone(),
                    None => bundle.base_live.clone(),
                },
                changed_live: live_change.and_then(|(_, pin)| pin),
                reason,
                decision: answer.decision.clone(),
                woken_at: None,
            });
        }
        // A live edit that changed no answer's unit lands the proposal whole, as before.
        if carry && !moved && !files_moved && withdrawn.is_empty() {
            return Ok(None);
        }
        let carried = if carry && kept.iter().any(|answer| answer.value.is_some()) {
            let mut bundle = bundle.clone();
            bundle.answers = kept;
            self.stage_sheet_answers(
                artifact,
                bundle,
                &proposal.run_ref,
                head.version,
                head.content_hash,
                None,
            )?
        } else {
            None
        };
        let files: Vec<EntityId> = bundle
            .answers
            .iter()
            .filter_map(|answer| answer.source.as_ref().map(|pin| pin.id))
            .collect();
        let shape = match reads {
            Some(reads) => ReaskShape::SheetRows {
                sheet: bundle.sheet.clone(),
                answer_col,
                reads,
                max_count_override: bundle.max_count_override,
            },
            None => ReaskShape::FolderItems {
                sheet: bundle.sheet.clone(),
                answer_col,
                max_count_override: bundle.max_count_override,
            },
        };
        Ok(Some(Split {
            carried,
            withdrawal: UnitWithdrawal {
                artifact: *artifact,
                proposal_ref: proposal.run_ref.clone(),
                question: bundle.question.clone(),
                principal: bundle.principal,
                made_by: made_by.cloned(),
                shape,
                answers: withdrawn,
                observed: self.observed_versions(artifact, &files)?,
                observed_live: self.observed_live(artifact, &files)?,
                reask_refs: Vec::new(),
                retry_at: None,
                delta_receipt: None,
            },
        }))
    }

    pub(super) fn split_paragraphs(
        &self,
        artifact: &EntityId,
        proposal: &EditProposal,
        principal: EntityId,
        made_by: Option<&MadeBy>,
        carry: bool,
    ) -> Result<Option<Split>> {
        let (Some(base_version), Some(question)) = (
            proposal.base_version,
            proposal.manifest.paragraph_question.as_ref(),
        ) else {
            return Ok(None);
        };
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let moved = head.version != base_version || head.content_hash != proposal.base_content_hash;
        let rows = &proposal.manifest.paragraph_judgments;
        // An edit to the live body never exported moves no version (FIX 2115).
        let judged_live = rows.first().and_then(|row| row.judged_live.clone());
        let live = self.live_paragraphs(artifact, judged_live.as_ref())?;
        if !moved && live.is_none() {
            return Ok(None);
        }
        let live_now = match &live {
            Some(_) => self.office_body_pin(artifact)?,
            None => None,
        };
        let current = self
            .read_blob_artifact_version(artifact, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let limits = {
            let rtxn = self.store.env.read_txn()?;
            self.docx_archive_limits_in_txn(&rtxn, Some(principal))?
        };
        // The DOCX read runs in the host's memory (FIX 10651); a resource
        // refusal is the engine's error, never an invalid document (FIX 10587).
        let resources = crate::office_body::document_resources();
        let read_blocks = |bytes: &[u8]| {
            resources
                .docx(|| oneiron_docedit::docx_body::read_docx_blocks(bytes, limits))
                .map_err(|error| {
                    if let Some(refusal) = error.resource() {
                        return crate::office_body::document_refused(refusal);
                    }
                    Error::Artifact(ArtifactError::InvalidEditManifest(
                        "the held paragraphs' document does not read",
                    ))
                })
        };
        let blocks = read_blocks(current.as_slice())?;
        // Paragraphs read on the live body: their text compares from the
        // newest export since the base, which holds it as the body did at its
        // frontier, compared with the pin (FIX 12017).
        let exported =
            self.export_span(artifact, judged_live.as_ref(), base_version, head.version)?;
        let exported_units = match &exported {
            Some(span) => self.live_paragraphs_until(
                artifact,
                judged_live.as_ref(),
                Some(span.frontier.as_slice()),
            )?,
            None => None,
        };
        let export_blocks = match exported.as_ref().and_then(|span| span.bytes.as_ref()) {
            Some(bytes) => Some(read_blocks(bytes.as_slice())?),
            None => None,
        };
        let mut kept = Vec::new();
        let mut withdrawn = Vec::new();
        for row in rows {
            let head_block = blocks.iter().find(|block| block.id == row.block);
            let text_moved = |text: &str| match (&exported, &export_blocks) {
                (None, _) => *blake3::hash(text.as_bytes()).as_bytes() != row.text_hash,
                (Some(_), None) => false,
                (Some(_), Some(was)) => was
                    .iter()
                    .find(|was| was.id == row.block)
                    .is_none_or(|was| was.text != text),
            };
            let blob = match head_block {
                _ if !moved => None,
                None => Some(WithdrawReason::UnitMissing),
                Some(block)
                    if block.locked.is_some()
                        || !matches!(
                            block.kind,
                            oneiron_docedit::docx_body::DocxBlockKind::Paragraph
                                | oneiron_docedit::docx_body::DocxBlockKind::Heading(_)
                        )
                        || text_moved(block.text.as_str()) =>
                {
                    Some(WithdrawReason::UnitChanged)
                }
                Some(_) => exported_units
                    .as_ref()
                    .and_then(|units| units.change(&row.block))
                    .map(live::withdraw_reason),
            };
            let live_change = live.as_ref().and_then(|units| units.change(&row.block));
            match blob.or(live_change.map(live::withdraw_reason)) {
                // A kept answer's comment quotes the paragraph as the head
                // holds it, an export's projection of the text it read.
                None => kept.push(ParagraphJudgment {
                    text_hash: match (&exported, head_block) {
                        (Some(_), Some(block)) => *blake3::hash(block.text.as_bytes()).as_bytes(),
                        _ => row.text_hash,
                    },
                    ..row.clone()
                }),
                Some(reason) => withdrawn.push(WithdrawnAnswer {
                    unit: WithdrawnUnit::Paragraph {
                        block: row.block.clone(),
                    },
                    judged_on: *artifact,
                    judged_version: row.judged_version,
                    judged_hash: row.frontier,
                    changed_version: blob.map(|_| head.version),
                    judged_live: row.judged_live.clone(),
                    changed_live: live_change.and(live_now.clone()),
                    reason,
                    decision: row.decision.clone(),
                    woken_at: None,
                }),
            }
        }
        // A live edit that changed no answered paragraph lands the proposal whole.
        if carry && !moved && withdrawn.is_empty() {
            return Ok(None);
        }
        let shape = ReaskShape::Paragraphs {
            author: rows[0].author.clone(),
            labels: rows[0].labels.clone(),
        };
        let carried = if carry && !kept.is_empty() {
            let mut carried =
                carry_paragraph_judgments(&current, head.version, kept, &proposal.run_ref, limits)?;
            carried.manifest.paragraph_question = Some(question.clone());
            Some(carried)
        } else {
            None
        };
        Ok(Some(Split {
            carried,
            withdrawal: UnitWithdrawal {
                artifact: *artifact,
                proposal_ref: proposal.run_ref.clone(),
                question: question.clone(),
                principal,
                made_by: made_by.cloned(),
                shape,
                answers: withdrawn,
                observed: self.observed_versions(artifact, &[])?,
                observed_live: self.observed_live(artifact, &[])?,
                reask_refs: Vec::new(),
                retry_at: None,
                delta_receipt: None,
            },
        }))
    }

    /// The slide branch of [`Self::split_typed_answers`]: a slide whose
    /// content, or any part it renders through, moved since the base is
    /// withdrawn, as is a slide gone from the head; a comment written on a
    /// slide since moves nothing. The untouched comments are written again
    /// on their slides on the head.
    pub(super) fn split_slides(
        &self,
        artifact: &EntityId,
        proposal: &EditProposal,
        principal: EntityId,
        made_by: Option<&MadeBy>,
        carry: bool,
    ) -> Result<Option<Split>> {
        let (Some(base_version), Some(question)) = (
            proposal.base_version,
            proposal.manifest.slide_question.as_ref(),
        ) else {
            return Ok(None);
        };
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let moved = head.version != base_version || head.content_hash != proposal.base_content_hash;
        let rows = &proposal.manifest.slide_judgments;
        // An edit to the live deck never exported moves no version (FIX 2115).
        let judged_live = rows.first().and_then(|row| row.judged_live.clone());
        let live = self.live_slides(artifact, judged_live.as_ref(), None)?;
        if !moved && live.is_none() {
            return Ok(None);
        }
        let live_now = match &live {
            Some(_) => self.office_body_pin(artifact)?,
            None => None,
        };
        let limits = self.docedit_package_limits()?;
        let current = self
            .read_blob_artifact_version(artifact, head.version)?
            .ok_or(Error::EntityNotFound)?;
        // Slides read on the live deck compare from the newest export since
        // the base, which shows them as the deck did at its frontier,
        // compared with the pin (FIX 12017).
        let exported =
            self.export_span(artifact, judged_live.as_ref(), base_version, head.version)?;
        let exported_units = match &exported {
            Some(span) => self.live_slides(
                artifact,
                judged_live.as_ref(),
                Some(span.frontier.as_slice()),
            )?,
            None => None,
        };
        let export_is_head = exported.as_ref().is_some_and(|span| span.bytes.is_none());
        let (was, now) = if moved {
            let was = match exported.as_ref().map(|span| span.bytes.as_ref()) {
                Some(None) => Vec::new(),
                Some(Some(bytes)) => deck_slides_now(bytes, limits)?,
                None => {
                    let base = self
                        .read_blob_artifact_version(artifact, base_version)?
                        .ok_or(Error::EntityNotFound)?;
                    deck_slides_now(&base, limits)?
                }
            };
            (was, deck_slides_now(&current, limits)?)
        } else {
            (Vec::new(), Vec::new())
        };
        let patches = proposal.manifest.ops.iter().filter_map(|op| match op {
            EditOp::PptxComment { patch } => Some(patch),
            _ => None,
        });
        let mut kept = Vec::new();
        let mut withdrawn = Vec::new();
        for (row, patch) in rows.iter().zip(patches) {
            let shows = |slides: &[SlideNow]| {
                slides
                    .iter()
                    .find(|slide| slide.is(&row.anchor))
                    .map(|slide| slide.shows)
            };
            let slide = (row.anchor.slide_part.clone(), row.anchor.sld_id);
            let blob = match (shows(&was), shows(&now)) {
                _ if !moved => None,
                (_, None) => Some(WithdrawReason::UnitMissing),
                _ if export_is_head => None,
                (Some(was), Some(now)) if was == now => None,
                _ => Some(WithdrawReason::UnitChanged),
            }
            .or_else(|| {
                exported_units
                    .as_ref()?
                    .change(&slide)
                    .map(live::withdraw_reason)
            });
            let live_change = live.as_ref().and_then(|units| units.change(&slide));
            match blob.or(live_change.map(live::withdraw_reason)) {
                None => kept.push((row.clone(), patch.clone())),
                Some(reason) => withdrawn.push(WithdrawnAnswer {
                    unit: WithdrawnUnit::Slide {
                        part: row.anchor.slide_part.clone(),
                        sld_id: row.anchor.sld_id,
                        shape: row.target.shape_creation_id.clone(),
                    },
                    judged_on: *artifact,
                    judged_version: row.judged_version,
                    judged_hash: row.frontier,
                    changed_version: blob.map(|_| head.version),
                    judged_live: row.judged_live.clone(),
                    changed_live: live_change.and(live_now.clone()),
                    reason,
                    decision: row.decision.clone(),
                    woken_at: None,
                }),
            }
        }
        let author = proposal
            .manifest
            .ops
            .iter()
            .find_map(|op| match op {
                EditOp::PptxComment { patch } => Some(patch.author.clone()),
                _ => None,
            })
            .ok_or(Error::Artifact(ArtifactError::InvalidEditManifest(
                "a held slide review has no comment",
            )))?;
        // A live edit that changed no answered slide lands the proposal whole.
        if carry && !moved && withdrawn.is_empty() {
            return Ok(None);
        }
        let shape = ReaskShape::Slides {
            author,
            labels: rows[0].labels.clone(),
        };
        let carried = if carry && !kept.is_empty() {
            let mut carried =
                carry_slide_judgments(&current, head.version, kept, &proposal.run_ref, limits)?;
            self.measure_pptx_comment_patches(&carried);
            carried.manifest.slide_question = Some(question.clone());
            Some(carried)
        } else {
            None
        };
        Ok(Some(Split {
            carried,
            withdrawal: UnitWithdrawal {
                artifact: *artifact,
                proposal_ref: proposal.run_ref.clone(),
                question: question.clone(),
                principal,
                made_by: made_by.cloned(),
                shape,
                answers: withdrawn,
                observed: self.observed_versions(artifact, &[])?,
                observed_live: self.observed_live(artifact, &[])?,
                reask_refs: Vec::new(),
                retry_at: None,
                delta_receipt: None,
            },
        }))
    }
}
