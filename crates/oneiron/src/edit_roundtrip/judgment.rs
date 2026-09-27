//! Typed sheet answers: one ask over a bounded range becomes one retained edit.
//!
//! The caller's agent supplies answers; this adapter never chooses a model,
//! grants access or sends unit text to a provider. Its only job is to bind
//! answers to cells on a copy and carry their provenance through Keep.

use super::{
    CellRef, CellValue, EditOp, EditOutcome, EditPlan, EditProposal, EditSession, RangeRef,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One answer's target and the answerer's evidence. `None` means abstain:
/// it does not write a cell, and is not a negative answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SheetCellAnswer {
    pub cell: CellRef,
    pub before: Option<CellValue>,
    pub value: Option<CellValue>,
    pub probability: f64,
    pub confidence: f64,
    pub rung: String,
    pub model: String,
    pub revision: String,
    pub cost_per_thousand: f64,
    pub evidence_versions: Vec<String>,
}

/// The agent's one-off ask, bound to a selection and an access principal.
/// A new question text must use a new `question_version`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SheetAnswerBundle {
    pub question: String,
    pub question_version: String,
    pub principal: String,
    pub sheet: String,
    pub range: RangeRef,
    pub answers: Vec<SheetCellAnswer>,
}

impl SheetAnswerBundle {
    /// Fail closed before passing untrusted answer positions or values to the
    /// session; the same check runs at Keep against a public proposal.
    pub(crate) fn ops(&self) -> Result<Vec<EditOp>> {
        fn invalid() -> Error {
            Error::Artifact(ArtifactError::InvalidEditManifest(
                "invalid typed sheet answer bundle",
            ))
        }
        if self.question.trim().is_empty()
            || self.question_version.trim().is_empty()
            || self.principal.trim().is_empty()
            || self.sheet.trim().is_empty()
            || self.range.start.col == 0
            || self.range.start.row == 0
            || self.range.end.col < self.range.start.col
            || self.range.end.row < self.range.start.row
            || self.answers.is_empty()
            || self.answers.len() > 4096
        {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut ops = Vec::new();
        for answer in &self.answers {
            let cell = answer.cell;
            if cell.col < self.range.start.col
                || cell.col > self.range.end.col
                || cell.row < self.range.start.row
                || cell.row > self.range.end.row
                || !seen.insert((cell.row, cell.col))
                || !answer.probability.is_finite()
                || !(0.0..=1.0).contains(&answer.probability)
                || !answer.confidence.is_finite()
                || !(0.0..=1.0).contains(&answer.confidence)
                || !answer.cost_per_thousand.is_finite()
                || answer.cost_per_thousand < 0.0
                || answer.rung.trim().is_empty()
                || answer.model.trim().is_empty()
                || answer.revision.trim().is_empty()
                || answer.evidence_versions.iter().any(|v| v.trim().is_empty())
                || matches!(answer.value, Some(CellValue::Formula { .. }))
            {
                return Err(invalid());
            }
            if let Some(value) = &answer.value {
                ops.push(EditOp::SetCell {
                    sheet: self.sheet.clone(),
                    cell,
                    before: answer.before.clone(),
                    after: value.clone(),
                });
            }
        }
        if ops.is_empty() {
            return Err(invalid());
        }
        Ok(ops)
    }
}

impl Vault {
    /// Stage already-computed typed answers on the current workbook copy.
    /// No version is written until [`Vault::settle_select_edit_proposal`].
    pub fn propose_sheet_answers<S: EditSession>(
        &self,
        artifact_id: &EntityId,
        session: &S,
        bundle: SheetAnswerBundle,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        let ops = bundle.ops()?;
        let outcome = self.propose_blob_artifact_edit(
            artifact_id,
            session,
            &EditPlan::new(ops.clone()),
            run_ref,
        )?;
        Ok(match outcome {
            EditOutcome::Proposed(mut proposal) => {
                // The session's applied-op manifest must agree with the ask;
                // never receipt answers the session omitted or changed.
                if proposal.manifest.ops != ops {
                    return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                        "session applied ops differ from typed answers",
                    )));
                }
                proposal.sheet_answers = Some(Box::new(bundle));
                EditOutcome::Proposed(proposal)
            }
            rejected => rejected,
        })
    }
}

impl EditProposal {
    /// The answer bundle on a retained sheet proposal, if any.
    #[must_use]
    pub fn typed_sheet_answers(&self) -> Option<&SheetAnswerBundle> {
        self.sheet_answers.as_deref()
    }
}
