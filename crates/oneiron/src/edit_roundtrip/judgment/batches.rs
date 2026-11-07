//! Ordered answer-write batches over one proposal's edit session.

use std::num::NonZeroUsize;

use oneiron_docedit::resource::Resources;
use oneiron_xlsx_formula::{DocumentLocation, RecalcClock};

use crate::blob_artifact::CalcEngineStamp;
use crate::edit_roundtrip::{AppliedEdit, EditOp, EditPlan, EditSession, OfficeDoc, RecalcPolicy};
use crate::error::Result;

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
        let mut current = None;
        let mut applied_ops = Vec::new();
        let mut warnings = Vec::new();
        let mut chunks = plan.ops.chunks(self.batch_size.get()).peekable();
        while let Some(ops) = chunks.next() {
            self.resources.checkpoint().map_err(refused)?;
            // This hold covers the temporary plan vector, not the retained
            // result or the strings and native workbook allocations.
            let mut scratch = self.resources.hold();
            scratch.take_len::<EditOp>(ops.len()).map_err(refused)?;
            let batch = EditPlan {
                ops: ops.to_vec(),
                request_recalc: plan.request_recalc,
            };
            let applied = self
                .session
                .apply_edits(current.as_ref().unwrap_or(doc), &batch)?;
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

    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        self.session.recalc_engine()
    }

    fn supports_recalc(&self) -> bool {
        self.session.supports_recalc()
    }

    fn recalc_policy(&self) -> RecalcPolicy {
        self.session.recalc_policy()
    }

    fn recalc_resources(&self) -> Option<Resources> {
        self.session.recalc_resources()
    }

    fn recalc_clock(&self) -> Option<RecalcClock> {
        self.session.recalc_clock()
    }

    fn recalc_location(&self) -> Option<DocumentLocation> {
        self.session.recalc_location()
    }
}
