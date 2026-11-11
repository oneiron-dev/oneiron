//! Stage-3 default: in-process xlsx recalculation over the host session.

use std::cell::RefCell;

use oneiron_docedit::resource::Resources;
use oneiron_docedit::retained_opc::Limits;
use oneiron_xlsx_formula::engine::FormualizerEngine;
use oneiron_xlsx_formula::{FormulaError, RecalcClock};

use super::{AppliedEdit, EditPlan, EditSession, OfficeDoc, OfficeFormat};
use crate::blob_artifact::CalcEngineStamp;
use crate::error::{ArtifactError, Error, Result};

/// The [`RecalcPolicy::NativeFirst`](super::RecalcPolicy::NativeFirst) wrap.
/// It keeps the host's narrow editor, recalculates supported local workbooks
/// in process on the session's clock ([`EditSession::recalc_clock`], else the
/// host's clock at recalc time) and at the session's location
/// ([`EditSession::recalc_location`]), and uses the host's recalc as the
/// precision fallback.
///
/// The host must preserve external-link parts. Every host output is checked
/// against its input before the pipeline can propose it. A destructive
/// external-link round trip is refused, not silently accepted.
///
/// One wrap belongs to one serial pipeline run. Its last successful recalc
/// supplies the engine stamp the pipeline records. Applying another plan
/// clears that stamp until a recalc succeeds.
pub(super) struct NativeFirst<'a, S> {
    host: &'a S,
    engine: FormualizerEngine,
    limits: Limits,
    resources: Resources,
    stamp: RefCell<Option<CalcEngineStamp>>,
}

impl<'a, S: EditSession> NativeFirst<'a, S> {
    /// Wrap `host`, reading packages under the document ceilings `limits`.
    pub(super) fn new(host: &'a S, limits: Limits) -> Self {
        Self {
            host,
            engine: FormualizerEngine::new(),
            limits,
            resources: host
                .recalc_resources()
                .unwrap_or_else(crate::office_body::document_resources),
            stamp: RefCell::new(None),
        }
    }

    fn host_recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        if !self.host.supports_recalc() {
            return Err(failed("workbook needs a recalc-capable precision fallback"));
        }
        self.resources
            .checkpoint()
            .map_err(crate::office_body::document_refused)?;
        let output = self.host.recalc(doc)?;
        self.resources
            .checkpoint()
            .map_err(crate::office_body::document_refused)?;
        oneiron_xlsx_formula::preserve_external_links(
            &doc.bytes,
            &output,
            self.limits,
            &self.resources,
        )
        .map_err(preservation_failed)?;
        *self.stamp.borrow_mut() = self.host.recalc_engine();
        Ok(output)
    }
}

impl<S: EditSession> EditSession for NativeFirst<'_, S> {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        *self.stamp.borrow_mut() = None;
        self.resources
            .checkpoint()
            .map_err(crate::office_body::document_refused)?;
        let applied = self.host.apply_edits(doc, plan)?;
        oneiron_xlsx_formula::preserve_external_links(
            &doc.bytes,
            &applied.bytes,
            self.limits,
            &self.resources,
        )
        .map_err(preservation_failed)?;
        Ok(applied)
    }

    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        *self.stamp.borrow_mut() = None;
        if doc.format != OfficeFormat::Xlsx {
            return Err(failed("native formula recalc requires XLSX"));
        }
        self.resources
            .checkpoint()
            .map_err(crate::office_body::document_refused)?;
        let clock = self.host.recalc_clock().unwrap_or_else(RecalcClock::system);
        let location = self.host.recalc_location();
        match self.engine.recalculate_xlsx(
            &doc.bytes,
            self.limits,
            &clock,
            location.as_ref(),
            &self.resources,
        ) {
            Ok(report) => {
                let stamp = CalcEngineStamp::new(report.engine.engine, report.engine.version)?;
                *self.stamp.borrow_mut() = Some(stamp);
                Ok(report.bytes)
            }
            Err(FormulaError::Package(_)) => Err(failed("workbook package refused")),
            Err(FormulaError::InvalidWorkbook(reason)) => Err(failed(reason)),
            Err(FormulaError::Resource(refusal)) => {
                Err(crate::office_body::document_refused(refusal))
            }
            // Precision fallback is still available, but never renews an
            // expired resource clock or turns its refusal into a workbook result.
            Err(_) => {
                self.resources
                    .checkpoint()
                    .map_err(crate::office_body::document_refused)?;
                self.host_recalc(doc)
            }
        }
    }

    fn recalc_resources(&self) -> Option<Resources> {
        Some(self.resources.clone())
    }

    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        self.stamp.borrow().clone()
    }
}

fn preservation_failed(error: FormulaError) -> Error {
    match error {
        FormulaError::Resource(refusal) => crate::office_body::document_refused(refusal),
        FormulaError::InvalidWorkbook(reason) => failed(reason),
        _ => failed("external-link preservation failed"),
    }
}

fn failed(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::EditRoundtripFailed(reason))
}
