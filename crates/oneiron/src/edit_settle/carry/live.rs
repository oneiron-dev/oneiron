//! The live-body half of a held answer proposal's split (FIX 2115).
//!
//! A person's edit to an artifact's live body that was never exported moves
//! no version, so the version half of the split sees nothing. Each answer
//! keeps the live body it was judged against; the split reads that body at
//! the pinned frontier and at its head and withdraws the answers whose units
//! changed there, by the rules the version half keeps: a sheet row's read
//! cells, its header or its answer cell, a paragraph's text, a slide's
//! content, a folder file whole.

use super::WithdrawReason;
use crate::Vault;
use crate::edit_roundtrip::{EditProposal, SheetAnswerBundle, SheetCellAnswer};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::office_body::{LiveChange, LivePin, LiveSheet};

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
        if let Some(sheet) = &self.sheet {
            let row = answer.cell.row;
            let reason = match sheet.whole() {
                Some(change) => Some(withdraw_reason(change)),
                None if sheet.differs(answer.cell.col, row) => {
                    Some(WithdrawReason::AnswerCellChanged)
                }
                None if read_cols.iter().any(|col| {
                    sheet.differs(*col, row)
                        || header_row.is_some_and(|header| sheet.differs(*col, header))
                }) =>
                {
                    Some(WithdrawReason::UnitChanged)
                }
                None => None,
            };
            if let Some(reason) = reason {
                return Some((reason, self.workbook.clone()));
            }
        }
        let file = self.files.get(index)?.as_ref()?;
        Some((WithdrawReason::UnitChanged, Some(file.clone())))
    }
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

/// The receipt's view of a live pin: its commit count and frontier.
pub(super) fn live_field(pin: &LivePin) -> serde_json::Value {
    serde_json::json!({
        "commits": pin.commits,
        "frontier": crate::receipt::hex_lower(&pin.frontier),
    })
}

impl Vault {
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
