//! Explicit opt-in recalc adapter for the core's edit round-trip seam.
use std::cell::RefCell;

use oneiron::blob_artifact::CalcEngineStamp;
use oneiron::edit_roundtrip::{AppliedEdit, EditPlan, EditSession, OfficeDoc, OfficeFormat};
use oneiron::error::{ArtifactError, Error, Result};
use oneiron_docedit::retained_opc::{Limits, Package};

use crate::engine::FormualizerEngine;
use crate::{FormulaError, route_workbook};

/// Keep the caller's narrow editor and precision fallback, but recalculate
/// supported local workbooks in process. Constructing this is an explicit
/// experiment opt-in: there is no `Default` implementation or global selection.
///
/// `fallback` must preserve external-link parts. Every fallback output is
/// checked against its input before the pipeline can propose it. A destructive
/// external-link round trip is refused, not silently accepted.
///
/// One adapter belongs to one serial edit session. Its last successful recalc
/// supplies the engine stamp the pipeline records. Applying another plan
/// clears that stamp until a recalc succeeds.
pub struct InProcessSession<S> {
    fallback: S,
    engine: FormualizerEngine,
    limits: Limits,
    stamp: RefCell<Option<CalcEngineStamp>>,
}

impl<S> InProcessSession<S> {
    /// Opt in over `fallback`, reading packages under the host's document
    /// ceilings (`Vault::docedit_package_limits`).
    #[must_use]
    pub fn opt_in(fallback: S, limits: Limits) -> Self {
        Self {
            fallback,
            engine: FormualizerEngine::new(),
            limits,
            stamp: RefCell::new(None),
        }
    }
}

impl<S: EditSession> InProcessSession<S> {
    fn fallback_recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        if !self.fallback.supports_recalc() {
            return Err(failed("workbook needs a recalc-capable precision fallback"));
        }
        let output = self.fallback.recalc(doc)?;
        preserve_external_parts(&doc.bytes, &output, self.limits)?;
        *self.stamp.borrow_mut() = self.fallback.recalc_engine();
        Ok(output)
    }
}

impl<S: EditSession> EditSession for InProcessSession<S> {
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        *self.stamp.borrow_mut() = None;
        let applied = self.fallback.apply_edits(doc, plan)?;
        preserve_external_parts(&doc.bytes, &applied.bytes, self.limits)?;
        Ok(applied)
    }

    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        *self.stamp.borrow_mut() = None;
        if doc.format != OfficeFormat::Xlsx {
            return Err(failed("native formula recalc requires XLSX"));
        }
        match self.engine.recalculate_xlsx(&doc.bytes, self.limits) {
            Ok(report) => {
                let stamp = CalcEngineStamp::new(report.engine.engine, report.engine.version)?;
                *self.stamp.borrow_mut() = Some(stamp);
                Ok(report.bytes)
            }
            Err(FormulaError::UnsupportedWorkbook(_)) => self.fallback_recalc(doc),
            Err(FormulaError::Package(_)) => Err(failed("workbook package refused")),
            Err(FormulaError::InvalidWorkbook(reason)) => Err(failed(reason)),
            Err(_) => Err(failed("in-process formula evaluation failed")),
        }
    }

    fn recalc_engine(&self) -> Option<CalcEngineStamp> {
        self.stamp.borrow().clone()
    }
}

fn failed(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::EditRoundtripFailed(reason))
}

fn preserve_external_parts(before: &[u8], after: &[u8], limits: Limits) -> Result<()> {
    let before = Package::open(before, limits).map_err(|_| failed("unreadable input package"))?;
    let after = Package::open(after, limits).map_err(|_| failed("unreadable output package"))?;
    for name in before.names() {
        let link_part = name.starts_with("xl/externalLinks/");
        if !link_part && !name.ends_with(".rels") {
            continue;
        }
        let part = before
            .part(name)
            .map_err(|_| failed("unreadable input part"))?
            .ok_or(failed("missing external-link input part"))?;
        let protected =
            link_part || !route_workbook([], [part.as_slice()], [], limits.xml).is_in_process();
        if protected
            && after
                .part(name)
                .map_err(|_| failed("unreadable output part"))?
                .as_ref()
                != Some(&part)
        {
            return Err(failed("fallback altered or dropped an external-link part"));
        }
    }
    let before_formulas = crate::workbook::external_formulas(&before)
        .map_err(|_| failed("cannot inspect external formula links"))?;
    if !before_formulas.is_empty() {
        let after_formulas = crate::workbook::external_formulas(&after)
            .map_err(|_| failed("cannot inspect output external formula links"))?;
        if before_formulas
            .iter()
            .any(|(cell, formula)| after_formulas.get(cell) != Some(formula))
        {
            return Err(failed(
                "fallback altered or dropped an external formula link",
            ));
        }
    }
    Ok(())
}
