//! Typed sheet answers: one ask over a bounded range becomes one retained edit.
//!
//! Each answer is a full decide() decision for one typed question (ARCH-0076
//! §2, "Sheet row or cell"), its cell value fixed by the answer contract. The
//! adapter never grants access or settles; it binds decisions to cells on a
//! copy and carries their receipts through Keep.

use super::artifact_question::{
    ArtifactAsk, ArtifactAskRun, UnitAbstention, UnitRefusal, answer_cell, cell_text,
};
use super::judgment_cells::{named_sheet_cells, verify_sheet_answer_bytes};
use super::{
    AppliedEdit, CellRef, CellValue, EditOp, EditOutcome, EditPlan, EditProposal, EditSession,
    OfficeDoc, OfficeFormat, RangeRef,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::decision::{DecisionQuestion, EvidenceVersion, TypedDecision};
use oneiron_docedit::retained_opc::Limits;
use oneiron_docedit::xlsx_body::{XlsxChange, XlsxValue, project_xlsx, read_xlsx_cells};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

/// One answer's target and its decision. `value` is the cell the decision's
/// answer writes; `None` is an abstention, which writes nothing and is not
/// a negative answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SheetCellAnswer {
    pub cell: CellRef,
    pub before: Option<CellValue>,
    pub value: Option<CellValue>,
    /// The decide() call's full decision and receipt.
    pub decision: TypedDecision,
    /// For a folder column: the file this row answers for, at the version
    /// read. Keep refuses the column when that file has moved.
    #[serde(default)]
    pub source: Option<EvidenceVersion>,
    /// The version of what the call read: the workbook for a row, the file
    /// for a folder column. With the evidence hash it names the revision
    /// the answer was judged against.
    #[serde(default)]
    pub judged_version: Option<u64>,
}

/// What each row's call read beside its own cells: the row's cells in
/// columns `first_col..=last_col` (the answer column aside) and the header
/// row's. An answer whose read cells change under it is withdrawn at Keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SheetRowReads {
    pub first_col: u32,
    pub last_col: u32,
    pub header_row: Option<u32>,
}

/// The ask, bound to a selection and an access principal. Every decision is
/// for this question version and this principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SheetAnswerBundle {
    pub question: DecisionQuestion,
    pub principal: EntityId,
    pub sheet: String,
    pub range: RangeRef,
    pub answers: Vec<SheetCellAnswer>,
    /// Holder-selected run cap; the manifest vault and scoped rows can only narrow it.
    #[serde(default)]
    pub max_count_override: Option<u64>,
    /// A sheet-row ask's read columns; a folder column reads its files.
    #[serde(default)]
    pub reads: Option<SheetRowReads>,
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
        if self.question.validate().is_err()
            || self.sheet.trim().is_empty()
            || self.range.start.col == 0
            || self.range.start.row == 0
            || self.range.end.col < self.range.start.col
            || self.range.end.row < self.range.start.row
            || self.answers.is_empty()
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
                || answer.decision.receipt.evidence_versions.is_empty()
                || matches!(answer.before, Some(CellValue::Formula { .. }))
                || crate::llm::decision::questions::validate_unit_decision(
                    &self.question,
                    self.principal,
                    &answer.decision,
                )
                .is_err()
                || answer_cell(&answer.decision.answer).ok().as_ref() != Some(&answer.value)
                || answer.source.as_ref().is_some_and(|source| {
                    !answer.decision.receipt.evidence_versions.contains(source)
                })
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

/// One typed ask over sheet rows: each row of `rows` is a unit whose cells
/// the call reads; its answer lands in column `answer_col` of that row.
#[derive(Clone, Copy)]
pub struct SheetRowsAsk<'a> {
    pub ask: ArtifactAsk<'a>,
    pub sheet: &'a str,
    pub rows: RangeRef,
    pub answer_col: u32,
    /// The row naming the read columns, given to the call beside the cells.
    pub header_row: Option<u32>,
    pub max_count_override: Option<u64>,
    /// Only these rows of `rows` are asked: a wake asks again only the rows
    /// that changed under a held answer.
    pub only_rows: Option<&'a BTreeSet<u32>>,
}

impl Vault {
    /// Stage already-decided typed answers on the current workbook copy.
    /// No version is written until [`Vault::settle_select_edit_proposal`].
    pub fn propose_sheet_answers<S: EditSession>(
        &self,
        artifact_id: &EntityId,
        session: &S,
        bundle: SheetAnswerBundle,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        let ops = bundle.ops()?;
        let rtxn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &rtxn)?;
        let cap = policy
            .sheet_answer_limit(
                &artifact_id.to_hex(),
                &bundle.sheet,
                bundle.max_count_override,
            )
            .ok_or(Error::Artifact(ArtifactError::InvalidEditManifest(
                "typed answer count policy unavailable",
            )))?;
        if u64::try_from(bundle.answers.len()).unwrap_or(u64::MAX) > cap {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "typed answer count exceeds policy",
            )));
        }
        drop(rtxn);
        let head = self
            .blob_artifact_head(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let source = self
            .read_blob_artifact_version(artifact_id, head.version)?
            .ok_or(Error::EntityNotFound)?;
        // Verify the source independently of the edit session, including any
        // caller-supplied before values, before the agent edits a copy.
        verify_sheet_answer_bytes(&bundle, Some(&source), None)?;
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
                // Applied ops are a writer promise; check the actual OPC bytes.
                // A concurrent head move is handled as stale by ARTL-4.
                verify_sheet_answer_bytes(&bundle, None, Some(&proposal.new_bytes))?;
                proposal.sheet_answers = Some(Box::new(bundle));
                EditOutcome::Proposed(proposal)
            }
            rejected => rejected,
        })
    }

    /// Ask one typed question of each row of a workbook head, one decide()
    /// call per row under the run's deadline, and stage the answers as one
    /// proposal on a copy, held for Keep. A row with no cell to read
    /// abstains without a call; an answer cell holding a formula is refused.
    pub fn ask_blob_artifact_sheet_rows(
        &self,
        artifact: &EntityId,
        request: &SheetRowsAsk<'_>,
    ) -> Result<ArtifactAskRun> {
        let ask = &request.ask;
        ask.validate()?;
        let rows = request.rows;
        let answer_col = request.answer_col;
        if request.sheet.trim().is_empty()
            || rows.start.col == 0
            || rows.start.row == 0
            || rows.end.col < rows.start.col
            || rows.end.row < rows.start.row
            || answer_col == 0
        {
            return Err(invalid("invalid sheet ask selection"));
        }
        let (version, bytes) = self.office_head(artifact, OfficeFormat::Xlsx)?;
        let frontier = *blake3::hash(&bytes).as_bytes();
        let in_rows = |row: u32| (rows.start.row..=rows.end.row).contains(&row);
        let header_row = request.header_row;
        let cells = named_sheet_cells(&bytes, request.sheet, &|cell: &CellRef| {
            let read_col = (rows.start.col..=rows.end.col).contains(&cell.col);
            (read_col && (in_rows(cell.row) || Some(cell.row) == header_row))
                || (cell.col == answer_col && in_rows(cell.row))
        })?;
        let columns: Vec<u32> = (rows.start.col..=rows.end.col)
            .filter(|col| *col != answer_col)
            .collect();
        let headers: Map<String, Value> = header_row
            .map(|row| {
                columns
                    .iter()
                    .filter_map(|col| {
                        let text = cells.get(&CellRef { col: *col, row }).and_then(cell_text)?;
                        Some((super::address::column_to_letters(*col), Value::String(text)))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let sources = [EvidenceVersion {
            id: *artifact,
            body_hash: frontier,
        }];
        let mut answers = Vec::new();
        let mut abstained = Vec::new();
        let mut refused = Vec::new();
        for row in rows.start.row..=rows.end.row {
            if request
                .only_rows
                .is_some_and(|only| !only.contains(&row))
            {
                continue;
            }
            let target = CellRef {
                col: answer_col,
                row,
            };
            let unit = json!({"sheet": request.sheet, "row": row, "cell": target.to_a1()});
            let before = cells.get(&target).cloned().unwrap_or(CellValue::Blank);
            if matches!(before, CellValue::Formula { .. }) {
                refused.push(UnitRefusal {
                    unit,
                    reason: "answer_cell_formula".into(),
                });
                continue;
            }
            let read: Map<String, Value> = columns
                .iter()
                .filter_map(|col| {
                    let text = cells.get(&CellRef { col: *col, row }).and_then(cell_text)?;
                    Some((super::address::column_to_letters(*col), Value::String(text)))
                })
                .collect();
            if read.is_empty() {
                abstained.push(UnitAbstention {
                    unit,
                    decision: None,
                });
                continue;
            }
            let state = json!({
                "unit": unit.clone(),
                "headers": headers,
                "cells": read,
            });
            let Some(decision) = ask.decide(&state, &sources, &[])? else {
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
                source: None,
                judged_version: Some(version),
            });
        }
        let bundle = SheetAnswerBundle {
            question: ask.question.clone(),
            principal: ask.principal,
            sheet: request.sheet.to_owned(),
            range: RangeRef {
                start: CellRef {
                    col: answer_col,
                    row: rows.start.row,
                },
                end: CellRef {
                    col: answer_col,
                    row: rows.end.row,
                },
            },
            answers,
            max_count_override: request.max_count_override,
            reads: Some(SheetRowReads {
                first_col: rows.start.col,
                last_col: rows.end.col,
                header_row,
            }),
        };
        Ok(ArtifactAskRun {
            proposal: self.stage_sheet_answers(artifact, bundle, ask.run_ref, version, frontier)?,
            abstained,
            refused,
        })
    }

    /// Stage decided answers through the in-process cell writer on the exact
    /// workbook version they were asked over; a head that moved meanwhile is
    /// refused rather than answered on bytes nobody read. `None` when every
    /// unit abstained: no empty edit is proposed.
    pub(crate) fn stage_sheet_answers(
        &self,
        artifact: &EntityId,
        bundle: SheetAnswerBundle,
        run_ref: &str,
        version: u64,
        frontier: [u8; 32],
    ) -> Result<Option<EditProposal>> {
        if bundle.answers.iter().all(|answer| answer.value.is_none()) {
            return Ok(None);
        }
        let session = NativeCellSession {
            limits: self.docedit_package_limits()?,
        };
        match self.propose_sheet_answers(artifact, &session, bundle, run_ref)? {
            EditOutcome::Proposed(proposal) => {
                if proposal.base_version != Some(version) || proposal.base_content_hash != frontier
                {
                    return Err(invalid("the workbook moved while it was asked; ask again"));
                }
                Ok(Some(*proposal))
            }
            EditOutcome::Rejected { .. } => Err(Error::Artifact(
                ArtifactError::EditRoundtripFailed("the answered copy failed validation"),
            )),
        }
    }
}

impl EditProposal {
    /// The answer bundle on a retained sheet proposal, if any.
    #[must_use]
    pub fn typed_sheet_answers(&self) -> Option<&SheetAnswerBundle> {
        self.sheet_answers.as_deref()
    }
}

/// The in-process cell writer for typed answers: each answer cell goes
/// through the native XLSX projection with its format kept, and formulas
/// recalculate in process. No host recalc stands behind it.
struct NativeCellSession {
    limits: Limits,
}

impl EditSession for NativeCellSession {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        let failed = || {
            Error::Artifact(ArtifactError::EditRoundtripFailed(
                "typed answers could not be written to the workbook copy",
            ))
        };
        let book = read_xlsx_cells(&doc.bytes, self.limits).map_err(|_| failed())?;
        let changes = plan
            .ops
            .iter()
            .map(|op| {
                let EditOp::SetCell {
                    sheet, cell, after, ..
                } = op
                else {
                    return Err(failed());
                };
                let value = match after {
                    CellValue::Blank => XlsxValue::Blank,
                    CellValue::Number(number) => XlsxValue::Number(*number),
                    CellValue::Text(text) => XlsxValue::Text(text.clone()),
                    CellValue::Bool(value) => XlsxValue::Bool(*value),
                    CellValue::Error(error) => XlsxValue::Error(error.clone()),
                    CellValue::Formula { .. } => return Err(failed()),
                };
                let style = book
                    .sheets
                    .iter()
                    .find(|named| named.name == *sheet)
                    .and_then(|named| {
                        named
                            .cells
                            .iter()
                            .find(|stored| stored.col == cell.col && stored.row == cell.row)
                    })
                    .and_then(|stored| stored.style);
                Ok(XlsxChange::Cell {
                    sheet: sheet.clone(),
                    col: cell.col,
                    row: cell.row,
                    value,
                    formula: None,
                    style,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let bytes = project_xlsx(&doc.bytes, &changes, self.limits).map_err(|_| failed())?;
        Ok(AppliedEdit {
            bytes,
            applied_ops: plan.ops.clone(),
            warnings: Vec::new(),
        })
    }

    fn recalc(&self, _doc: &OfficeDoc) -> Result<Vec<u8>> {
        Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "typed answers have no host recalc behind the in-process engine",
        )))
    }

    fn supports_recalc(&self) -> bool {
        false
    }
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
