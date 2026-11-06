//! Typed questions over files in a folder (ARCH-0076 §2, "File in a folder"):
//! each selected file is one unit read whole at its head, and its answer
//! lands as one cell of a column in a result workbook, settled once on Keep.
//! The files themselves are never written. A folder is the caller's
//! selection; every file is read as the asker, by its own artifact id.

use super::artifact_question::{ArtifactAsk, ArtifactAskRun, UnitAbstention, UnitRefusal, invalid};
use super::judgment::{SheetAnswerBundle, finish_decided_sheet_unit};
use super::judgment_cells::named_sheet_cells;
use super::{CellRef, CellValue, OfficeFormat, RangeRef};
use crate::edit_settle::{
    DecidedSheetAnswers, DecidedSheetInputs, DecidedSheetProgress, DecidedSheetRequest,
    DecidedSheetShape, DecidedSheetUnitDecision,
};
use crate::llm::decision::{DecisionImage, EvidenceVersion, MAX_DECISION_IMAGE_BYTES};
use crate::llm::image::ImageBytes;
use crate::office_body::document_resources;
use crate::{EntityId, Result, Vault};
use oneiron_docedit::ArchiveLimits;
use oneiron_docedit::deck::DeckView;
use oneiron_docedit::docx_body::read_docx_blocks;
use oneiron_docedit::retained_opc::{Limits, Package};
use oneiron_docedit::xlsx_body::{XlsxValue, read_xlsx_cells};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

/// One file and the result row its answer fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderItem {
    pub artifact: EntityId,
    pub row: u32,
}

/// One typed ask over files, answered into column `answer_col` of a sheet
/// of the result workbook.
#[derive(Clone, Copy)]
pub struct FolderAsk<'a> {
    pub ask: ArtifactAsk<'a>,
    pub items: &'a [FolderItem],
    pub sheet: &'a str,
    pub answer_col: u32,
    pub max_count_override: Option<u64>,
    /// How the asker sees secret spans: a call reads each file as the asker
    /// would export it. The answer stays pinned to the stored version.
    pub sight: crate::secret_custody::SecretSight,
}

impl Vault {
    /// Ask one typed question of each selected file, one decide() call per
    /// file under the run's deadline, and stage the answers as one column on
    /// a copy of the `output` workbook, held for Keep. A file read as text
    /// (an office document's text, a text file) or as an image (PNG, JPEG,
    /// for a decider that reads images); one with neither abstains without
    /// a call, never counting as a no.
    pub fn ask_folder_items_into_sheet(
        &self,
        output: &EntityId,
        request: &FolderAsk<'_>,
    ) -> Result<ArtifactAskRun> {
        let ask = &request.ask;
        ask.validate()?;
        let answer_col = request.answer_col;
        let mut rows = BTreeSet::new();
        let mut files = BTreeSet::new();
        for item in request.items {
            ask.check_deadline()?;
            rows.insert(item.row);
            files.insert(item.artifact);
        }
        let (Some(first), Some(last)) = (rows.first().copied(), rows.last().copied()) else {
            return Err(invalid("a folder ask names its files"));
        };
        if request.sheet.trim().is_empty()
            || answer_col == 0
            || first == 0
            || rows.len() != request.items.len()
            || files.len() != request.items.len()
            || files.contains(output)
        {
            return Err(invalid("invalid folder ask selection"));
        }
        let identity = DecidedSheetRequest::new(
            ask,
            DecidedSheetShape::FolderItems {
                sheet: request.sheet.to_owned(),
                items: request.items.to_vec(),
                answer_col,
                max_count_override: request.max_count_override,
            },
        );
        let unmasked = request.sight != crate::secret_custody::SecretSight::Masked;
        let mut row = if let Some(row) = self.decided_sheet_answers(output, &identity, unmasked)? {
            row
        } else {
            ask.check_deadline()?;
            let base_live = self.office_body_pin(output)?;
            let (version, bytes, read_rows) = self.office_head(output, OfficeFormat::Xlsx)?;
            let frontier = *blake3::hash(&bytes).as_bytes();
            let cells = named_sheet_cells(&bytes, request.sheet, &|cell: &CellRef| {
                cell.col == answer_col && rows.contains(&cell.row)
            })?;
            let before = request
                .items
                .iter()
                .map(|item| {
                    ask.check_deadline()?;
                    Ok(cells
                        .get(&CellRef {
                            col: answer_col,
                            row: item.row,
                        })
                        .cloned()
                        .unwrap_or(CellValue::Blank))
                })
                .collect::<Result<Vec<_>>>()?;
            self.retain_decided_sheet_answers(
                output,
                DecidedSheetAnswers {
                    request: identity,
                    generation: EntityId::now(),
                    bundle: SheetAnswerBundle {
                        question: ask.question.clone(),
                        principal: ask.principal,
                        sheet: request.sheet.to_owned(),
                        range: RangeRef {
                            start: CellRef {
                                col: answer_col,
                                row: first,
                            },
                            end: CellRef {
                                col: answer_col,
                                row: last,
                            },
                        },
                        answers: Vec::new(),
                        max_count_override: request.max_count_override,
                        reads: None,
                        base_live,
                    },
                    version,
                    frontier,
                    read_rows,
                    abstained: Vec::new(),
                    refused: Vec::new(),
                    progress: Some(DecidedSheetProgress {
                        next: 0,
                        inputs: DecidedSheetInputs::FolderItems { before },
                        decision: None,
                    }),
                    unmasked,
                },
                ask.deadline,
            )?
        };
        if row.progress.is_none() {
            return self.stage_decided_sheet_answers(output, &row, ask.deadline);
        }
        let package_limits = self.docedit_package_limits()?;
        let archive_limits = {
            let rtxn = self.store.env.read_txn()?;
            self.docx_archive_limits_in_txn(&rtxn, Some(ask.principal))?
        };
        while let Some(progress) = &row.progress {
            ask.check_deadline()?;
            let DecidedSheetInputs::FolderItems { before } = &progress.inputs else {
                return Err(invalid("folder ask has different stored inputs"));
            };
            let expected = row.clone();
            let Some(item) = request.items.get(progress.next) else {
                row.progress = None;
                row = self.advance_decided_sheet_answers(output, &expected, row, ask.deadline)?;
                continue;
            };
            let before = before
                .get(progress.next)
                .cloned()
                .ok_or_else(|| invalid("folder ask has missing stored inputs"))?;
            let target = CellRef {
                col: answer_col,
                row: item.row,
            };
            let unit = json!({
                "file": item.artifact.to_hex(),
                "row": item.row,
                "cell": target.to_a1(),
            });
            let has_decision = progress.decision.is_some();
            // A paid result commits before conversion; completed and no-call
            // outcomes advance the cursor in their own canonical commit.
            (|| -> Result<()> {
                if has_decision {
                    finish_decided_sheet_unit(self, output, &mut row, unit, target, before)?;
                    return Ok(());
                }
                if matches!(before, CellValue::Formula { .. }) {
                    row.refused.push(UnitRefusal {
                        unit,
                        reason: "answer_cell_formula".into(),
                        judged_live: None,
                    });
                    return Ok(());
                }
                // Read only the next file now. Completed files keep their own
                // pins and the existing withdrawal-at-Keep behavior.
                let live = self.live_head_text(&item.artifact, request.sight)?;
                let judged_live = live.as_ref().map(|(pin, _)| pin.clone());
                let (Some(head), Some(body)) = (
                    self.blob_artifact_head(&item.artifact)?,
                    self.get_blob_artifact(&item.artifact)?,
                ) else {
                    row.refused.push(UnitRefusal {
                        unit,
                        reason: "missing_file".into(),
                        judged_live,
                    });
                    return Ok(());
                };
                let Some((file, rows)) =
                    self.read_blob_artifact_version_listing(&item.artifact, head.version)?
                else {
                    row.refused.push(UnitRefusal {
                        unit,
                        reason: "missing_file".into(),
                        judged_live,
                    });
                    return Ok(());
                };
                // The file's head version is read for its unit (FIX 5455).
                row.read_rows.extend(rows);
                let pin = EvidenceVersion {
                    id: item.artifact,
                    body_hash: *blake3::hash(&file).as_bytes(),
                };
                let (text, images) = match live {
                    Some((_, text)) => (
                        Some(text).filter(|text| !text.trim().is_empty()),
                        Vec::new(),
                    ),
                    None => file_content(
                        &self.sighted_asset_bytes_with_digest(
                            file,
                            &pin.body_hash,
                            request.sight,
                        )?,
                        &body.media_type,
                        &pin,
                        package_limits,
                        archive_limits,
                    )?,
                };
                if text.is_none() && (images.is_empty() || !ask.decider.reads_images()) {
                    row.abstained.push(UnitAbstention {
                        unit,
                        decision: None,
                        judged_live,
                    });
                    return Ok(());
                }
                let state = json!({
                    "unit": {
                        "file": item.artifact.to_hex(),
                        "version": head.version,
                        "media_type": body.media_type,
                    },
                    "text": text,
                });
                let Some(decision) = ask.decide(&state, std::slice::from_ref(&pin), &images)?
                else {
                    row.refused.push(UnitRefusal {
                        unit,
                        reason: "evidence_budget".into(),
                        judged_live,
                    });
                    return Ok(());
                };
                row.progress
                    .as_mut()
                    .expect("partial folder answers")
                    .decision = Some(DecidedSheetUnitDecision {
                    decision,
                    source: Some(pin),
                    version: head.version,
                    live: judged_live,
                });
                Ok(())
            })()?;
            row.unmasked |= unmasked;
            let progress = row.progress.as_mut().expect("partial folder answers");
            if progress.decision.is_none() {
                progress.next += 1;
            }
            row = self.advance_decided_sheet_answers(output, &expected, row, ask.deadline)?;
        }
        self.stage_decided_sheet_answers(output, &row, ask.deadline)
    }
}

/// What a file gives its call: an office document's text, a text file's
/// text, or a PNG or JPEG as the call's `file` image pinned at the file's
/// version. Anything else gives neither.
fn file_content(
    bytes: &[u8],
    media_type: &str,
    pin: &EvidenceVersion,
    package_limits: Limits,
    archive_limits: ArchiveLimits,
) -> Result<(Option<String>, Vec<DecisionImage>)> {
    let lower = media_type.to_ascii_lowercase();
    if matches!(lower.as_str(), "image/png" | "image/jpeg" | "image/jpg") {
        let image = DecisionImage {
            name: "file".to_owned(),
            evidence: pin.clone(),
            image: ImageBytes {
                bytes: bytes.to_vec(),
                media_type: lower,
            },
            frame: None,
        };
        let images = (bytes.len() <= MAX_DECISION_IMAGE_BYTES)
            .then_some(image)
            .into_iter()
            .collect();
        return Ok((None, images));
    }
    if lower.starts_with("text/") || lower == "application/json" {
        let text = String::from_utf8(bytes.to_vec()).ok();
        return Ok((text.filter(|text| !text.trim().is_empty()), Vec::new()));
    }
    let text = match OfficeFormat::from_media_type(media_type) {
        Ok(OfficeFormat::Docx) => {
            // The DOCX read runs in the host's memory (FIX 10651); a resource
            // refusal is the engine's error, never a quiet abstention (FIX 10587).
            let resources = document_resources();
            match resources.docx(|| read_docx_blocks(bytes, archive_limits)) {
                Ok(blocks) => Some(
                    blocks
                        .iter()
                        .flat_map(|block| {
                            std::iter::once(block.text.clone())
                                .chain(block.cells.iter().map(|cell| cell.text.clone()))
                        })
                        .filter(|text| !text.trim().is_empty())
                        .collect::<Vec<_>>()
                        .join("\n\n"),
                ),
                Err(error) => {
                    if let Some(refusal) = error.resource() {
                        return Err(crate::office_body::document_refused(refusal));
                    }
                    None
                }
            }
        }
        Ok(OfficeFormat::Pptx) => {
            // A resource refusal is the engine's error, never a quiet
            // abstention (FIX 10587).
            match Package::open(bytes, package_limits, &document_resources()) {
                Err(error) => {
                    if let Some(refusal) = error.resource() {
                        return Err(crate::office_body::document_refused(refusal));
                    }
                    None
                }
                Ok(package) => match DeckView::read(&package) {
                    Err(error) => {
                        if let Some(refusal) = error.resource() {
                            return Err(crate::office_body::document_refused(refusal));
                        }
                        None
                    }
                    Ok(view) => Some(
                        view.slides
                            .iter()
                            .flat_map(|slide| slide.shapes.iter())
                            .filter_map(super::slides_review::shape_text)
                            .filter(|text| !text.trim().is_empty())
                            .collect::<Vec<_>>()
                            .join("\n\n"),
                    ),
                },
            }
        }
        Ok(OfficeFormat::Xlsx) => {
            // A resource refusal is the engine's error, never a quiet
            // abstention (FIX 10587).
            match read_xlsx_cells(bytes, package_limits, &document_resources()) {
                Err(error) => {
                    if let Some(refusal) = error.resource() {
                        return Err(crate::office_body::document_refused(refusal));
                    }
                    None
                }
                Ok(book) => Some(
                    book.sheets
                        .iter()
                        .flat_map(|sheet| {
                            sheet.cells.iter().filter_map(move |cell| {
                                let value = match &cell.value {
                                    XlsxValue::Blank => return None,
                                    XlsxValue::Number(number) => number.to_string(),
                                    XlsxValue::Text(text) | XlsxValue::Error(text) => text.clone(),
                                    XlsxValue::Bool(value) => value.to_string(),
                                };
                                Some(format!(
                                    "{}!{}{}: {value}",
                                    sheet.name,
                                    super::address::column_to_letters(cell.col),
                                    cell.row
                                ))
                            })
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            }
        }
        _ => None,
    };
    Ok((text.filter(|text| !text.trim().is_empty()), Vec::new()))
}
