//! Typed questions over files in a folder (ARCH-0076 §2, "File in a folder"):
//! each selected file is one unit read whole at its head, and its answer
//! lands as one cell of a column in a result workbook, settled once on Keep.
//! The files themselves are never written. A folder is the caller's
//! selection; every file is read as the asker, by its own artifact id.

use super::artifact_question::{
    ArtifactAsk, ArtifactAskRun, UnitAbstention, UnitRefusal, answer_cell, invalid,
};
use super::judgment::{SheetAnswerBundle, SheetCellAnswer};
use super::judgment_cells::named_sheet_cells;
use super::{CellRef, CellValue, OfficeFormat, RangeRef};
use crate::llm::decision::{DecisionImage, EvidenceVersion, MAX_DECISION_IMAGE_BYTES};
use crate::llm::image::ImageBytes;
use crate::{EntityId, Result, Vault};
use oneiron_docedit::ArchiveLimits;
use oneiron_docedit::deck::DeckView;
use oneiron_docedit::docx_body::read_docx_blocks;
use oneiron_docedit::retained_opc::{Limits, Package};
use oneiron_docedit::xlsx_body::{XlsxValue, read_xlsx_cells};
use serde_json::json;
use std::collections::BTreeSet;

/// One file and the result row its answer fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        let rows: BTreeSet<u32> = request.items.iter().map(|item| item.row).collect();
        let files: BTreeSet<EntityId> = request.items.iter().map(|item| item.artifact).collect();
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
        let (version, bytes) = self.office_head(output, OfficeFormat::Xlsx)?;
        let frontier = *blake3::hash(&bytes).as_bytes();
        let cells = named_sheet_cells(&bytes, request.sheet, &|cell: &CellRef| {
            cell.col == answer_col && rows.contains(&cell.row)
        })?;
        let package_limits = self.docedit_package_limits()?;
        let archive_limits = {
            let rtxn = self.store.env.read_txn()?;
            self.docx_archive_limits_in_txn(&rtxn, Some(ask.principal))?
        };
        let mut answers = Vec::new();
        let mut abstained = Vec::new();
        let mut refused = Vec::new();
        for item in request.items {
            let target = CellRef {
                col: answer_col,
                row: item.row,
            };
            let unit = json!({
                "file": item.artifact.to_hex(),
                "row": item.row,
                "cell": target.to_a1(),
            });
            let before = cells.get(&target).cloned().unwrap_or(CellValue::Blank);
            if matches!(before, CellValue::Formula { .. }) {
                refused.push(UnitRefusal {
                    unit,
                    reason: "answer_cell_formula".into(),
                });
                continue;
            }
            let (Some(head), Some(body)) = (
                self.blob_artifact_head(&item.artifact)?,
                self.get_blob_artifact(&item.artifact)?,
            ) else {
                refused.push(UnitRefusal {
                    unit,
                    reason: "missing_file".into(),
                });
                continue;
            };
            let Some(file) = self.read_blob_artifact_version(&item.artifact, head.version)? else {
                refused.push(UnitRefusal {
                    unit,
                    reason: "missing_file".into(),
                });
                continue;
            };
            let pin = EvidenceVersion {
                id: item.artifact,
                body_hash: *blake3::hash(&file).as_bytes(),
            };
            let seen = self.sighted_asset_bytes(file, request.sight)?;
            let (text, images) = file_content(
                &seen,
                &body.media_type,
                &pin,
                package_limits,
                archive_limits,
            );
            if text.is_none() && (images.is_empty() || !ask.decider.reads_images()) {
                abstained.push(UnitAbstention {
                    unit,
                    decision: None,
                });
                continue;
            }
            let state = json!({
                "unit": {
                    "file": item.artifact.to_hex(),
                    "version": head.version,
                    "media_type": body.media_type,
                },
                "text": text,
            });
            let Some(decision) = ask.decide(&state, std::slice::from_ref(&pin), &images)? else {
                refused.push(UnitRefusal {
                    unit,
                    reason: "evidence_budget".into(),
                });
                continue;
            };
            let value = answer_cell(&decision.answer)?;
            if value.is_none() {
                abstained.push(UnitAbstention {
                    unit,
                    decision: Some(decision.clone()),
                });
            }
            answers.push(SheetCellAnswer {
                cell: target,
                before: Some(before),
                value,
                decision,
                source: Some(pin),
            });
        }
        let bundle = SheetAnswerBundle {
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
            answers,
            max_count_override: request.max_count_override,
        };
        Ok(ArtifactAskRun {
            proposal: self.stage_sheet_answers(output, bundle, ask.run_ref, version, frontier)?,
            abstained,
            refused,
        })
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
) -> (Option<String>, Vec<DecisionImage>) {
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
        return (None, images);
    }
    if lower.starts_with("text/") || lower == "application/json" {
        let text = String::from_utf8(bytes.to_vec()).ok();
        return (text.filter(|text| !text.trim().is_empty()), Vec::new());
    }
    let text = match OfficeFormat::from_media_type(media_type) {
        Ok(OfficeFormat::Docx) => read_docx_blocks(bytes, archive_limits).ok().map(|blocks| {
            blocks
                .iter()
                .flat_map(|block| {
                    std::iter::once(block.text.clone())
                        .chain(block.cells.iter().map(|cell| cell.text.clone()))
                })
                .filter(|text| !text.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n\n")
        }),
        Ok(OfficeFormat::Pptx) => Package::open(bytes, package_limits)
            .ok()
            .and_then(|package| DeckView::read(&package).ok())
            .map(|view| {
                view.slides
                    .iter()
                    .flat_map(|slide| slide.shapes.iter())
                    .filter_map(super::slides_review::shape_text)
                    .filter(|text| !text.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n\n")
            }),
        Ok(OfficeFormat::Xlsx) => read_xlsx_cells(bytes, package_limits).ok().map(|book| {
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
                .join("\n")
        }),
        _ => None,
    };
    (text.filter(|text| !text.trim().is_empty()), Vec::new())
}
