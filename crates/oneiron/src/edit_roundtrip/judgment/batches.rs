//! Ordered answer-write batches over one proposal's edit session.

use std::num::NonZeroUsize;

use oneiron_docedit::resource::{Hold, Resources};
use oneiron_xlsx_formula::{DocumentLocation, RecalcClock};

use crate::blob_artifact::CalcEngineStamp;
use crate::edit_roundtrip::{AppliedEdit, EditOp, EditPlan, EditSession, OfficeDoc, RecalcPolicy};
use crate::error::{Error, Result};

use super::{clone_plan_cell, clone_plan_text};

pub(super) struct BatchedSheetSession<'a, S> {
    pub session: &'a S,
    pub batch_size: NonZeroUsize,
    pub resources: &'a Resources,
}

impl<S: EditSession> EditSession for BatchedSheetSession<'_, S> {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        let refused = crate::office_body::machine_memory_refused;
        self.resources.checkpoint().map_err(refused)?;
        if plan.ops.len() <= self.batch_size.get() {
            return self.session.apply_edits(doc, plan);
        }
        let mut result_backing = self.resources.hold();
        let mut current = None;
        let mut applied_ops = Vec::new();
        let mut warnings = Vec::new();
        let mut chunks = plan.ops.chunks(self.batch_size.get()).peekable();
        while let Some(ops) = chunks.next() {
            self.resources.checkpoint().map_err(refused)?;
            // The hold covers this temporary batch and its validated cell
            // payloads, not the retained result or native workbook allocations.
            let mut scratch = self.resources.hold();
            scratch.take_len::<EditOp>(ops.len()).map_err(refused)?;
            let mut batch_ops = Vec::new();
            batch_ops.try_reserve_exact(ops.len()).map_err(|error| {
                Error::Io(std::io::Error::new(std::io::ErrorKind::OutOfMemory, error))
            })?;
            if batch_ops.capacity() > ops.len() {
                scratch
                    .take_len::<EditOp>(batch_ops.capacity() - ops.len())
                    .map_err(refused)?;
            }
            for op in ops {
                batch_ops.push(match op {
                    EditOp::SetCell {
                        sheet,
                        cell,
                        before,
                        after,
                    } => EditOp::SetCell {
                        sheet: clone_plan_text(sheet, Some(&mut scratch))?,
                        cell: *cell,
                        before: before
                            .as_ref()
                            .map(|value| clone_plan_cell(value, Some(&mut scratch)))
                            .transpose()?,
                        after: clone_plan_cell(after, Some(&mut scratch))?,
                    },
                    op => op.clone(),
                });
            }
            let batch = EditPlan {
                ops: batch_ops,
                request_recalc: plan.request_recalc,
            };
            let applied = self
                .session
                .apply_edits(current.as_ref().unwrap_or(doc), &batch)?;
            reserve_result(
                &mut applied_ops,
                applied.applied_ops.len(),
                &mut result_backing,
            )?;
            reserve_result(&mut warnings, applied.warnings.len(), &mut result_backing)?;
            applied_ops.extend(applied.applied_ops);
            warnings.extend(applied.warnings);
            if chunks.peek().is_none() {
                return Ok(AppliedEdit {
                    bytes: applied.bytes,
                    applied_ops,
                    warnings,
                });
            }
            let package = super::super::opc::read(&applied.bytes)?;
            current = Some(OfficeDoc::new(doc.format, applied.bytes, package));
        }
        unreachable!("a plan larger than a nonzero batch has a batch")
    }

    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        self.session.recalc(doc)
    }

    fn document_resources(&self) -> Option<Resources> {
        Some((*self.resources).clone())
    }

    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        self.session.recalc_engine()
    }

    fn supports_recalc(&self) -> bool {
        self.session.supports_recalc()
    }

    fn recalc_policy(&self) -> RecalcPolicy {
        self.session.recalc_policy()
    }

    fn recalc_clock(&self) -> Option<RecalcClock> {
        self.session.recalc_clock()
    }

    fn recalc_location(&self) -> Option<DocumentLocation> {
        self.session.recalc_location()
    }
}

fn reserve_result<T>(values: &mut Vec<T>, more: usize, backing: &mut Hold) -> Result<()> {
    let length = values.len().saturating_add(more);
    if length > values.capacity() {
        backing
            .take_len::<T>(length - values.capacity())
            .map_err(crate::office_body::machine_memory_refused)?;
        values.try_reserve_exact(more).map_err(|error| {
            Error::Io(std::io::Error::new(std::io::ErrorKind::OutOfMemory, error))
        })?;
        if values.capacity() > length {
            backing
                .take_len::<T>(values.capacity() - length)
                .map_err(crate::office_body::machine_memory_refused)?;
        }
    }
    Ok(())
}
