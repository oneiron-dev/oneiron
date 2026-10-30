//! The live-body half of a held answer proposal's split (FIX 2115).
//!
//! A person's edit to an artifact's live body that was never exported moves
//! no version, so the version half of the split sees nothing. Each answer
//! keeps the live body it was judged against; the split reads that body at
//! the pinned frontier and at its head and withdraws the answers whose units
//! changed there, by the rules the version half keeps: a sheet row's read
//! cells, its header or its answer cell, a paragraph's text, a slide's
//! content, a folder file whole.
//!
//! A wake asks a live deck's slides again as the deck renders at its head
//! (FIX 11981); every other unit's ask reads the live body itself.
//!
//! An answer read on the live body is not withdrawn by the export of the edit
//! it read. Past the newest export since its base, the version half compares
//! the unit as the export holds it, the live body at the frontier the
//! export's record names, against the body at the answer's pin, by the same
//! rules; the versions after that export compare as before (FIX 12017).

use super::{UnitWithdrawal, WithdrawReason, WithdrawnUnit};
use crate::Vault;
use crate::edit_roundtrip::pptx::PptxCommentTarget;
use crate::edit_roundtrip::slides_review::{SlideNow, deck_slides_now};
use crate::edit_roundtrip::{EditProposal, SheetAnswerBundle, SheetCellAnswer};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::decision::EvidenceVersion;
use crate::office_body::{LiveChange, LivePin, LiveSheet};
use oneiron_docedit::retained_opc::Limits;

/// The live half of a sheet answer split: the workbook's sheet and each
/// folder answer's file, where their live bodies moved since the ask.
pub(super) struct LiveSheetSplit {
    sheet: Option<LiveSheet>,
    /// The workbook's live body now, when its sheet moved.
    workbook: Option<LivePin>,
    /// Each answer's file's live body now, when it changed since the answer
    /// was judged.
    files: Vec<Option<LivePin>>,
}

impl LiveSheetSplit {
    pub(super) fn moved(&self) -> bool {
        self.sheet.is_some() || self.files.iter().any(Option::is_some)
    }

    /// Why the answer at `index` is withdrawn on the live side, with the live
    /// body it was found changed in: its sheet gone or reshaped, its answer
    /// cell written, its row's read cells or the header changed, its file
    /// changed.
    pub(super) fn reason(
        &self,
        index: usize,
        answer: &SheetCellAnswer,
        read_cols: &[u32],
        header_row: Option<u32>,
    ) -> Option<(WithdrawReason, Option<LivePin>)> {
        if let Some(reason) = self
            .sheet
            .as_ref()
            .and_then(|sheet| sheet_row_reason(sheet, answer, read_cols, header_row))
        {
            return Some((reason, self.workbook.clone()));
        }
        let file = self.files.get(index)?.as_ref()?;
        Some((WithdrawReason::UnitChanged, Some(file.clone())))
    }
}

/// Why a sheet row's answer is withdrawn on `sheet`: the sheet gone or
/// reshaped, its answer cell written, its read cells or the header changed.
pub(super) fn sheet_row_reason(
    sheet: &LiveSheet,
    answer: &SheetCellAnswer,
    read_cols: &[u32],
    header_row: Option<u32>,
) -> Option<WithdrawReason> {
    let row = answer.cell.row;
    match sheet.whole() {
        Some(change) => Some(withdraw_reason(change)),
        None if sheet.differs(answer.cell.col, row) => Some(WithdrawReason::AnswerCellChanged),
        None if read_cols.iter().any(|col| {
            sheet.differs(*col, row) || header_row.is_some_and(|header| sheet.differs(*col, header))
        }) =>
        {
            Some(WithdrawReason::UnitChanged)
        }
        None => None,
    }
}

/// The newest export of an artifact since a held answer's base, when its
/// answers were read on the live body (FIX 12017).
pub(crate) struct ExportSpan {
    /// The frontier the export's record names: the body its version holds.
    pub(crate) frontier: Vec<u8>,
    /// The export version's bytes, when versions landed after it.
    pub(crate) bytes: Option<Vec<u8>>,
    /// The export version: its record names the clock the export side of a
    /// live compare recalculates at (FIX 12183).
    pub(crate) version: u64,
}

/// The withdraw reason a live unit's change gives.
pub(super) fn withdraw_reason(change: LiveChange) -> WithdrawReason {
    match change {
        LiveChange::Changed => WithdrawReason::UnitChanged,
        LiveChange::Gone => WithdrawReason::UnitMissing,
    }
}

/// The live bodies `proposal`'s answers were judged against, the artifact's
/// first, as [`Vault::observed_live`] lists them.
pub(super) fn judged_live(artifact: EntityId, proposal: &EditProposal) -> Vec<(EntityId, LivePin)> {
    let base = match proposal.sheet_answers.as_deref() {
        Some(bundle) => bundle.base_live.clone(),
        None => proposal
            .manifest
            .paragraph_judgments
            .first()
            .and_then(|row| row.judged_live.clone())
            .or_else(|| {
                proposal
                    .manifest
                    .slide_judgments
                    .first()
                    .and_then(|row| row.judged_live.clone())
            }),
    };
    base.map(|pin| (artifact, pin))
        .into_iter()
        .chain(
            proposal
                .sheet_answers
                .iter()
                .flat_map(|bundle| bundle.answers.iter())
                .filter_map(|answer| {
                    Some((answer.source.as_ref()?.id, answer.judged_live.clone()?))
                }),
        )
        .collect()
}

/// The slides `wake` asks again, each with the number it renders at: found
/// on the head version `bytes`, where its comment lands, and on `shown`, a
/// live deck's projection at its head, when the deck is asked as it renders
/// there (FIX 11981). A slide gone from either has nothing to ask of.
pub(super) fn reask_slide_targets(
    wake: &UnitWithdrawal,
    bytes: &[u8],
    shown: Option<&[u8]>,
    limits: Limits,
) -> Result<Vec<(PptxCommentTarget, u64)>> {
    let slides = deck_slides_now(bytes, limits)?;
    let shown = shown
        .map(|deck| deck_slides_now(deck, limits))
        .transpose()?;
    Ok(wake
        .answers
        .iter()
        .filter_map(|answer| {
            let WithdrawnUnit::Slide {
                part,
                sld_id,
                shape,
            } = &answer.unit
            else {
                return None;
            };
            let at = |slides: &[SlideNow]| {
                slides
                    .iter()
                    .find(|slide| slide.part == *part && slide.sld_id == *sld_id)
                    .map(|slide| (slide.slide, slide.creation_id))
            };
            let (slide, slide_creation_id) = at(slides.as_slice())?;
            let number = match &shown {
                Some(shown) => at(shown.as_slice())?.0,
                None => slide,
            };
            Some((
                PptxCommentTarget {
                    slide,
                    slide_creation_id,
                    shape_creation_id: shape.clone(),
                    shape_fingerprint: None,
                },
                number,
            ))
        })
        .collect())
}

/// The receipt's view of a live pin: its commit count and frontier.
pub(super) fn live_field(pin: &LivePin) -> serde_json::Value {
    serde_json::json!({
        "commits": pin.commits,
        "frontier": crate::receipt::hex_lower(&pin.frontier),
    })
}

impl Vault {
    /// The newest version of `artifact` after `base`, up to `head`, that an
    /// export of its live body landed, with the frontier its record names:
    /// the body that version holds (FIX 12017).
    pub(super) fn exported_since(
        &self,
        artifact: &EntityId,
        base: u64,
        head: u64,
    ) -> Result<Option<(u64, Vec<u8>)>> {
        for version in (base.saturating_add(1)..=head).rev() {
            if let Some(record) = self.office_body_export(artifact, version)? {
                return Ok(Some((version, record.frontier)));
            }
        }
        Ok(None)
    }

    /// The newest export of `artifact` after `base`, up to `head`, for
    /// answers read on the live body at `judged_live`; none for others.
    pub(crate) fn export_span(
        &self,
        artifact: &EntityId,
        judged_live: Option<&LivePin>,
        base: u64,
        head: u64,
    ) -> Result<Option<ExportSpan>> {
        if judged_live.is_none() {
            return Ok(None);
        }
        let Some((version, frontier)) = self.exported_since(artifact, base, head)? else {
            return Ok(None);
        };
        let bytes = if version == head {
            None
        } else {
            Some(
                self.read_blob_artifact_version(artifact, version)?
                    .ok_or(Error::EntityNotFound)?,
            )
        };
        Ok(Some(ExportSpan { frontier, bytes, version }))
    }

    /// Whether a folder answer's file, which moved off the version `source`
    /// it read, changed for the answer. A file read on its live body changed
    /// only if the newest export since holds it otherwise than the body at
    /// the answer's pin, or a later version moved it (FIX 12017).
    pub(super) fn folder_file_changed(
        &self,
        answer: &SheetCellAnswer,
        source: &EvidenceVersion,
        (head, head_hash): (u64, [u8; 32]),
    ) -> Result<bool> {
        let (Some(pin), Some(read)) = (answer.judged_live.as_ref(), answer.judged_version) else {
            return Ok(true);
        };
        let Some((version, frontier)) = self.exported_since(&source.id, read, head)? else {
            return Ok(true);
        };
        if self.live_body_changed_until(&source.id, Some(pin), Some(frontier.as_slice()))? {
            return Ok(true);
        }
        if version == head {
            return Ok(false);
        }
        Ok(self
            .read_blob_artifact_version(&source.id, version)?
            .is_none_or(|bytes| *blake3::hash(&bytes).as_bytes() != head_hash))
    }

    /// The live half of splitting `bundle`, held on `artifact`.
    pub(super) fn live_sheet_split(
        &self,
        artifact: &EntityId,
        bundle: &SheetAnswerBundle,
    ) -> Result<LiveSheetSplit> {
        let sheet = self.live_sheet(artifact, bundle.base_live.as_ref(), &bundle.sheet)?;
        let workbook = match &sheet {
            Some(_) => self.office_body_pin(artifact)?,
            None => None,
        };
        let mut files = Vec::with_capacity(bundle.answers.len());
        for answer in &bundle.answers {
            files.push(match &answer.source {
                Some(pin) if self.live_body_changed(&pin.id, answer.judged_live.as_ref())? => {
                    self.office_body_pin(&pin.id)?
                }
                _ => None,
            });
        }
        Ok(LiveSheetSplit {
            sheet,
            workbook,
            files,
        })
    }

    /// The live bodies of `artifact` and `files` where they stand now, those
    /// with one, the artifact's first.
    pub(super) fn observed_live(
        &self,
        artifact: &EntityId,
        files: &[EntityId],
    ) -> Result<Vec<(EntityId, LivePin)>> {
        let mut pins = Vec::new();
        for id in std::iter::once(artifact).chain(files) {
            if let Some(pin) = self.office_body_pin(id)? {
                pins.push((*id, pin));
            }
        }
        Ok(pins)
    }
}
