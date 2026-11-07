//! Typed sheet answers: one ask over a bounded range becomes one retained edit.
//!
//! Each answer is a full decide() decision for one typed question (ARCH-0076
//! §2, "Sheet row or cell"), its cell value fixed by the answer contract. The
//! adapter never grants access or settles; it binds decisions to cells on a
//! copy and carries their receipts through Keep.

use super::artifact_question::{
    ArtifactAsk, ArtifactAskRun, UnitAbstention, UnitRefusal, answer_cell, cell_text,
};
use super::judgment_cells::{named_sheet_cells_until, verify_sheet_answer_bytes};
use super::{
    AppliedEdit, CellRef, CellValue, EditOp, EditOutcome, EditPlan, EditProposal, EditSession,
    OfficeDoc, OfficeFormat, RangeRef, SheetRowSelection,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::decision::questions::keep_artifact_unit_ask;
use crate::llm::decision::{DecisionQuestion, EvidenceVersion, TypedDecision};
use oneiron_docedit::resource::ResourceRefusal;
use oneiron_docedit::retained_opc::Limits;
use oneiron_docedit::xlsx_body::{XlsxChange, XlsxValue, project_xlsx, read_xlsx_cells};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::time::Instant;

use oneiron_docedit::resource::Resources;

mod batches;

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
    /// For a folder column: the file's live body when it was read, so an
    /// edit to it never exported withdraws the answer (FIX 2115).
    #[serde(default)]
    pub judged_live: Option<crate::office_body::LivePin>,
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
    /// Maximum edits per write batch; vault and scoped rows can only narrow it.
    #[serde(default)]
    pub max_count_override: Option<u64>,
    /// A sheet-row ask's read columns; a folder column reads its files.
    #[serde(default)]
    pub reads: Option<SheetRowReads>,
    /// The workbook's live body when it was asked, so an edit to it never
    /// exported withdraws the answers it changed (FIX 2115).
    #[serde(default)]
    pub base_live: Option<crate::office_body::LivePin>,
}

/// Paid sheet decisions before byte staging. The owning caller retains this
/// work, with its read rows and ask journal, before using the original deadline.
#[derive(Debug, Clone)]
pub struct SheetAnswerWork {
    answers: std::sync::Arc<RetainedSheetAnswers>,
    pub base_version: u64,
    pub base_content_hash: [u8; 32],
    /// The original whole-ask clock, never renewed by staging.
    pub deadline: Instant,
    /// First selected row not included in this paid cohort.
    pub next_sheet_row: Option<u32>,
}

struct RetainedSheetAnswers {
    bundle: SheetAnswerBundle,
    // Declared after the bytes, so the actual answers are freed first.
    _memory: Option<Box<dyn oneiron_docedit::resource::ResourceAllocation>>,
}

impl std::fmt::Debug for RetainedSheetAnswers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedSheetAnswers")
            .finish_non_exhaustive()
    }
}

impl SheetAnswerWork {
    pub(super) fn new(
        bundle: SheetAnswerBundle,
        memory: Option<Box<dyn oneiron_docedit::resource::ResourceAllocation>>,
        base_version: u64,
        base_content_hash: [u8; 32],
        deadline: Instant,
        next_sheet_row: Option<u32>,
    ) -> Self {
        Self {
            answers: std::sync::Arc::new(RetainedSheetAnswers {
                bundle,
                _memory: memory,
            }),
            base_version,
            base_content_hash,
            deadline,
            next_sheet_row,
        }
    }

    /// The actual paid decisions, shared with their allocation's lifetime.
    pub fn bundle(&self) -> &SheetAnswerBundle {
        &self.answers.bundle
    }
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
    pub only_rows: Option<&'a SheetRowSelection>,
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
        let head = self
            .blob_artifact_head(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        self.propose_sheet_answers_at(
            artifact_id,
            session,
            bundle,
            run_ref,
            head.version,
            head.content_hash,
            &crate::office_body::document_resources(),
        )
    }

    fn propose_sheet_answers_at<S: EditSession>(
        &self,
        artifact_id: &EntityId,
        session: &S,
        bundle: SheetAnswerBundle,
        run_ref: &str,
        version: u64,
        frontier: [u8; 32],
        resources: &Resources,
    ) -> Result<EditOutcome> {
        let ops = bundle.ops()?;
        let rtxn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &rtxn)?;
        let batch_size = policy
            .sheet_answer_batch_size(
                &artifact_id.to_hex(),
                &bundle.sheet,
                bundle.max_count_override,
            )
            .ok_or(Error::Artifact(ArtifactError::InvalidEditManifest(
                "typed answer count policy unavailable",
            )))?;
        let batch_size = NonZeroUsize::new(usize::try_from(batch_size).unwrap_or(usize::MAX))
            .ok_or(Error::Artifact(ArtifactError::InvalidEditManifest(
                "typed answer count policy unavailable",
            )))?;
        drop(rtxn);
        let session = batches::BatchedSheetSession {
            session,
            batch_size,
            resources,
        };
        let source = self
            .read_blob_artifact_version(artifact_id, version)?
            .ok_or(Error::EntityNotFound)?;
        if *blake3::hash(&source).as_bytes() != frontier {
            return Err(Error::CorruptedIndex("answered workbook base hash"));
        }
        // Verify the source independently of the edit session, including any
        // caller-supplied before values, before the agent edits a copy.
        verify_sheet_answer_bytes(&bundle, Some(&source), None)?;
        let outcome = self.propose_blob_artifact_edit_at(
            artifact_id,
            version,
            &session,
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
    /// call per row under the run's deadline. The caller retains paid answers
    /// before staging them on a copy for Keep. A row with no cell to read
    /// abstains without a call; an answer cell holding a formula is refused.
    pub fn ask_blob_artifact_sheet_rows(
        &self,
        artifact: &EntityId,
        request: &SheetRowsAsk<'_>,
    ) -> Result<ArtifactAskRun> {
        request.ask.validate()?;
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
        let mut selected = request
            .only_rows
            .map(|only| only.iter_within(rows.start.row, rows.end.row));
        let mut all = rows.start.row..=rows.end.row;
        let mut row_iter = std::iter::from_fn(move || match selected.as_mut() {
            Some(selected) => selected.next(),
            None => all.next(),
        });
        let mut run = ArtifactAskRun {
            proposal: None,
            sheet_answers: None,
            deferred_floor: None,
            abstained: Vec::new(),
            refused: Vec::new(),
            read_rows: Vec::new(),
            next_sheet_row: row_iter.next(),
        };
        if run.next_sheet_row.is_none() {
            return Ok(run);
        }
        // Traverse within the answer share; staging keeps the whole-ask deadline.
        let started = Instant::now();
        let clock = crate::retrieval_depth::RetrievalDeadline::hard(
            started,
            request.ask.deadline.saturating_duration_since(started),
        );
        let work_until = started + clock.decision_time_left();
        let ask = ArtifactAsk {
            deadline: work_until,
            ..request.ask
        };
        let resources = crate::office_body::document_resources_until(Some(work_until));
        if sheet_ask_checkpoint(&resources, work_until).is_err() {
            return Ok(run);
        }
        // Live reads and byte acquisition retain their existing source pins.
        let live = self.live_head_cells(artifact, request.sheet)?;
        if sheet_ask_checkpoint(&resources, work_until).is_err() {
            return Ok(run);
        }
        let base_live = live.as_ref().map(|(pin, _)| pin.clone());
        let (version, bytes, read_rows) = self.office_head(artifact, OfficeFormat::Xlsx)?;
        run.read_rows = read_rows;
        if sheet_ask_checkpoint(&resources, work_until).is_err() {
            return Ok(run);
        }
        let frontier = *blake3::hash(&bytes).as_bytes();
        let in_rows = |row: u32| {
            (rows.start.row..=rows.end.row).contains(&row)
                && request.only_rows.is_none_or(|only| only.contains(&row))
        };
        let header_row = request.header_row;
        let loaded = match named_sheet_cells_until(
            &bytes,
            request.sheet,
            &|cell: &CellRef| {
                let read_col = (rows.start.col..=rows.end.col).contains(&cell.col);
                (read_col && (in_rows(cell.row) || Some(cell.row) == header_row))
                    || (cell.col == answer_col && in_rows(cell.row))
            },
            self.docedit_package_limits()?,
            &resources,
            work_until,
        ) {
            Ok(cells) => cells,
            Err(error) if sheet_ask_timed_out(&error) => return Ok(run),
            Err(error) => return Err(error),
        };
        let cells = &loaded.cells;
        let shown = live.as_ref().map_or(cells, |(_, live)| live);
        // Index only stored cells, not the rectangle's potentially billions
        // of absent columns. The same sparse index serves headers and rows.
        let mut index_memory = resources.allocation();
        let mut by_row = BTreeMap::new();
        for (cell, value) in shown {
            if let Err(refusal) = sheet_ask_checkpoint(&resources, work_until) {
                if refusal == ResourceRefusal::Deadline {
                    return Ok(run);
                }
                return Err(crate::office_body::machine_memory_refused(refusal));
            }
            if cell.col != answer_col
                && (rows.start.col..=rows.end.col).contains(&cell.col)
                && (in_rows(cell.row) || Some(cell.row) == header_row)
            {
                if let Err(refusal) = index_memory.grow(
                    oneiron_docedit::resource::bytes_of::<((u32, u32), &CellValue)>(3),
                    0,
                ) {
                    let error = crate::office_body::machine_memory_refused(refusal);
                    if sheet_ask_timed_out(&error) {
                        return Ok(run);
                    }
                    return Err(error);
                }
                by_row.insert((cell.row, cell.col), value);
                index_memory.materialized(oneiron_docedit::resource::bytes_of::<(
                    (u32, u32),
                    &CellValue,
                )>(by_row.len().saturating_mul(3)));
            }
        }
        let headers = match header_row {
            Some(row) => match sheet_row_state(&by_row, row, &resources, work_until) {
                Ok(headers) => headers,
                Err(ResourceRefusal::Deadline) => return Ok(run),
                Err(refusal) => return Err(crate::office_body::machine_memory_refused(refusal)),
            },
            None => SheetRowState {
                values: Map::new(),
                _memory: resources.allocation(),
            },
        };
        let sources = [EvidenceVersion {
            id: *artifact,
            body_hash: frontier,
        }];
        let mut answer_memory = resources.allocation();
        let mut abstention_memory = resources.allocation();
        let mut refusal_memory = resources.allocation();
        let mut answers = Vec::new();
        while let Some(row) = run.next_sheet_row {
            if Instant::now() >= work_until {
                break;
            }
            let prepared = (|| -> std::result::Result<(), SheetRowFailure> {
                sheet_ask_checkpoint(&resources, work_until)?;
                // Prepare each possible outcome slot before asking a model;
                // never lose a completed decision to a later vector grow.
                sheet_outcome_slot(&mut answers, answer_memory.as_mut())?;
                sheet_outcome_slot(&mut run.abstained, abstention_memory.as_mut())?;
                sheet_outcome_slot(&mut run.refused, refusal_memory.as_mut())?;
                let target = CellRef {
                    col: answer_col,
                    row,
                };
                let unit = json!({"sheet": request.sheet, "row": row, "cell": target.to_a1()});
                let before = cells.get(&target).cloned().unwrap_or(CellValue::Blank);
                if matches!(before, CellValue::Formula { .. }) {
                    run.refused.push(UnitRefusal {
                        unit,
                        reason: "answer_cell_formula".into(),
                        judged_live: base_live.clone(),
                    });
                    return Ok(());
                }
                let read = sheet_row_state(&by_row, row, &resources, work_until)?;
                if read.values.is_empty() {
                    run.abstained.push(UnitAbstention {
                        unit,
                        decision: None,
                        judged_live: base_live.clone(),
                    });
                    return Ok(());
                }
                let state =
                    json!({"unit": unit.clone(), "headers": headers.values, "cells": read.values});
                sheet_ask_checkpoint(&resources, work_until)?;
                let Some(decision) = ask.decide(&state, &sources, &[])? else {
                    run.refused.push(UnitRefusal {
                        unit,
                        reason: "evidence_budget".into(),
                        judged_live: base_live.clone(),
                    });
                    return Ok(());
                };
                let value = answer_cell(&decision.answer)?;
                if value.is_none() {
                    keep_artifact_unit_ask(self, &sources[0], &unit, &decision);
                    run.abstained.push(UnitAbstention {
                        unit,
                        decision: Some(decision.clone()),
                        judged_live: base_live.clone(),
                    });
                }
                answers.push(SheetCellAnswer {
                    cell: target,
                    before: Some(before),
                    value,
                    decision,
                    source: None,
                    judged_version: Some(version),
                    judged_live: None,
                });
                Ok(())
            })();
            match prepared {
                Ok(()) => run.next_sheet_row = row_iter.next(),
                Err(SheetRowFailure::Resource(ResourceRefusal::Deadline)) => break,
                Err(SheetRowFailure::Resource(refusal @ ResourceRefusal::MemoryFloor { .. }))
                    if answers.iter().any(|answer| answer.value.is_some()) =>
                {
                    run.deferred_floor = Some(refusal);
                    break;
                }
                Err(SheetRowFailure::Resource(refusal)) => {
                    return Err(crate::office_body::machine_memory_refused(refusal));
                }
                Err(SheetRowFailure::Ask(error)) if sheet_ask_timed_out(&error) => break,
                Err(SheetRowFailure::Ask(error)) => return Err(error),
            }
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
            base_live,
        };
        drop(by_row);
        drop(index_memory);
        drop(headers);
        drop(loaded);
        drop(live);
        drop(bytes);
        if bundle.answers.iter().any(|answer| answer.value.is_some()) {
            run.sheet_answers = Some(SheetAnswerWork::new(
                bundle,
                Some(answer_memory),
                version,
                frontier,
                request.ask.deadline,
                run.next_sheet_row,
            ));
        }
        Ok(run)
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
        resources: Resources,
    ) -> Result<Option<EditProposal>> {
        if bundle.answers.iter().all(|answer| answer.value.is_none()) {
            return Ok(None);
        }
        let session = NativeCellSession {
            limits: self.docedit_package_limits()?,
            resources: resources.clone(),
        };
        session
            .resources
            .checkpoint()
            .map_err(crate::office_body::document_refused)?;
        match self.propose_sheet_answers_at(
            artifact, &session, bundle, run_ref, version, frontier, &resources,
        )? {
            EditOutcome::Proposed(proposal) => {
                if proposal.base_version != Some(version) || proposal.base_content_hash != frontier
                {
                    return Err(Error::CorruptedIndex("answered proposal base"));
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
    resources: Resources,
}

impl EditSession for NativeCellSession {
    fn recalc_resources(&self) -> Option<oneiron_docedit::resource::Resources> {
        Some(self.resources.clone())
    }

    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        let failed = || {
            Error::Artifact(ArtifactError::EditRoundtripFailed(
                "typed answers could not be written to the workbook copy",
            ))
        };
        let book = read_xlsx_cells(&doc.bytes, self.limits, &self.resources).map_err(|error| {
            // A resource refusal is the engine's error (FIX 10587), never a failed write.
            if let Some(refusal) = error.resource() {
                crate::office_body::document_refused(refusal)
            } else {
                failed()
            }
        })?;
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
        let bytes = project_xlsx(&doc.bytes, &changes, self.limits, &self.resources, None)
            .map_err(|error| {
                // A resource refusal is the engine's error (FIX 10587), never a failed write.
                if let Some(refusal) = error.resource() {
                    crate::office_body::document_refused(refusal)
                } else {
                    failed()
                }
            })?
            .bytes;
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

#[derive(Debug, thiserror::Error)]
enum SheetRowFailure {
    #[error(transparent)]
    Resource(#[from] ResourceRefusal),
    #[error(transparent)]
    Ask(#[from] Error),
}

fn sheet_ask_checkpoint(
    resources: &oneiron_docedit::resource::Resources,
    deadline: Instant,
) -> std::result::Result<(), ResourceRefusal> {
    if Instant::now() >= deadline {
        return Err(ResourceRefusal::Deadline);
    }
    resources.checkpoint()
}

fn sheet_ask_timed_out(error: &Error) -> bool {
    matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut)
}

/// The map and its allocation scope travel together to the caller. Field
/// order frees the map before the scope, including without live readings.
struct SheetRowState {
    values: Map<String, Value>,
    _memory: Box<dyn oneiron_docedit::resource::ResourceAllocation>,
}

fn sheet_row_state(
    cells: &BTreeMap<(u32, u32), &CellValue>,
    row: u32,
    resources: &oneiron_docedit::resource::Resources,
    deadline: Instant,
) -> std::result::Result<SheetRowState, ResourceRefusal> {
    let mut memory = resources.allocation();
    let mut values = Map::new();
    let mut live_bytes: u64 = 0;
    for ((_, col), value) in cells.range((row, 0)..=(row, u32::MAX)) {
        sheet_ask_checkpoint(resources, deadline)?;
        fn text_bytes(value: &CellValue) -> (u64, u64) {
            match value {
                CellValue::Text(text) | CellValue::Error(text) => {
                    let bytes = oneiron_docedit::resource::wide(text.len());
                    (bytes, bytes)
                }
                CellValue::Formula { cached, .. } => cached.as_deref().map_or((0, 0), text_bytes),
                _ => (oneiron_docedit::resource::bytes_of::<CellValue>(1), 0),
            }
        }
        let (bytes, measured) = text_bytes(value);
        let node = oneiron_docedit::resource::bytes_of::<(String, Value)>(3);
        memory.grow(bytes.saturating_add(node), measured)?;
        if let Some(text) = cell_text(value) {
            let key = super::address::column_to_letters(*col);
            live_bytes = live_bytes
                .saturating_add(node)
                .saturating_add(oneiron_docedit::resource::wide(key.capacity()))
                .saturating_add(oneiron_docedit::resource::wide(text.capacity()));
            values.insert(key, Value::String(text));
        }
        memory.materialized(live_bytes);
    }
    Ok(SheetRowState {
        values,
        _memory: memory,
    })
}

/// Reserve vector growth before it allocates, then name the resulting
/// capacity once. Each output vector owns a separate allocation scope.
fn sheet_outcome_slot<T>(
    values: &mut Vec<T>,
    memory: &mut dyn oneiron_docedit::resource::ResourceAllocation,
) -> std::result::Result<(), ResourceRefusal> {
    if values.len() == values.capacity() {
        let capacity = values
            .len()
            .saturating_add(1)
            .max(values.capacity().saturating_mul(2));
        memory.grow(
            oneiron_docedit::resource::bytes_of::<T>(capacity - values.capacity()),
            0,
        )?;
        values.reserve_exact(capacity - values.len());
        memory.materialized(oneiron_docedit::resource::bytes_of::<T>(values.capacity()));
    }
    Ok(())
}
