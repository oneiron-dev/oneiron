//! Explicit opt-in recalc adapter for the actual document round-trip seam.
use std::cell::RefCell;

use oneiron_docedit::opc::{Limits, Package};
use oneiron_docedit::roundtrip::{AppliedEdit, EditPlan, EditSession, OfficeDoc, OfficeFormat};
use oneiron_docedit::{Error, Result};

use crate::engine::{EngineId, FormualizerEngine};
use crate::{FormulaError, route_workbook};

/// Keep the caller's narrow editor and precision fallback, but recalculate
/// supported local workbooks in process. Constructing this is an explicit
/// experiment opt-in: there is no `Default` implementation or global selection.
///
/// `fallback` must preserve external-link parts. Every fallback output is
/// checked against its input before the pipeline can propose it. A destructive
/// LibreOffice external-link round trip is refused, not silently accepted.
///
/// One adapter belongs to one serial edit-session. Its last successful recalc
/// supplies the engine stamp consumed by `run_edit_roundtrip` and storage.
/// Applying another plan resets that stamp to `none` until recalc succeeds.
pub struct InProcessSession<S> {
    fallback: S,
    engine: FormualizerEngine,
    stamp: RefCell<EngineId>,
}

impl<S> InProcessSession<S> {
    #[must_use]
    pub fn opt_in(fallback: S) -> Self {
        Self {
            fallback,
            engine: FormualizerEngine::new(),
            stamp: RefCell::new(EngineId::none()),
        }
    }

    fn fallback_recalc<E: From<Error>>(&self, doc: &OfficeDoc) -> std::result::Result<Vec<u8>, E>
    where
        S: EditSession<E>,
    {
        if !self.fallback.supports_recalc() {
            return Err(
                Error::EditFailed("workbook needs a recalc-capable precision fallback").into(),
            );
        }
        let output = self.fallback.recalc(doc)?;
        preserve_external_parts(&doc.bytes, &output)?;
        *self.stamp.borrow_mut() = self.fallback.engine_id();
        Ok(output)
    }
}

impl<S: EditSession<E>, E: From<Error>> EditSession<E> for InProcessSession<S> {
    fn engine_id(&self) -> EngineId {
        self.stamp.borrow().clone()
    }

    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> std::result::Result<AppliedEdit, E> {
        *self.stamp.borrow_mut() = EngineId::none();
        let applied = self.fallback.apply_edits(doc, plan)?;
        preserve_external_parts(&doc.bytes, &applied.bytes)?;
        Ok(applied)
    }

    fn recalc(&self, doc: &OfficeDoc) -> std::result::Result<Vec<u8>, E> {
        if doc.format != OfficeFormat::Xlsx {
            return Err(Error::EditFailed("native formula recalc requires XLSX").into());
        }
        match self.engine.recalculate_xlsx(&doc.bytes) {
            Ok(report) => {
                *self.stamp.borrow_mut() = report.engine;
                Ok(report.bytes)
            }
            Err(FormulaError::UnsupportedWorkbook(_)) => self.fallback_recalc::<E>(doc),
            Err(FormulaError::Package(error)) => Err(error.into()),
            Err(FormulaError::InvalidWorkbook(reason)) => Err(Error::InvalidPackage(reason).into()),
            Err(_) => Err(Error::EditFailed("in-process formula evaluation failed").into()),
        }
    }
}

fn preserve_external_parts(before: &[u8], after: &[u8]) -> Result<()> {
    let before = Package::open(before, Limits::default())?;
    let after = Package::open(after, Limits::default())?;
    for name in before.names() {
        let part = before
            .part(name)
            .ok_or(Error::InvalidPackage("missing external-link input part"))?;
        let protected = name.starts_with("xl/externalLinks/")
            || (name.ends_with(".rels") && !route_workbook([], [part], []).is_in_process());
        if protected && after.part(name) != Some(part) {
            return Err(Error::EditFailed(
                "fallback altered or dropped an external-link part",
            ));
        }
    }
    let before_formulas = crate::workbook::external_formulas(&before)
        .map_err(|_| Error::InvalidPackage("cannot inspect external formula links"))?;
    if !before_formulas.is_empty() {
        let after_formulas = crate::workbook::external_formulas(&after)
            .map_err(|_| Error::InvalidPackage("cannot inspect output external formula links"))?;
        if before_formulas
            .iter()
            .any(|(cell, formula)| after_formulas.get(cell) != Some(formula))
        {
            return Err(Error::EditFailed(
                "fallback altered or dropped an external formula link",
            ));
        }
    }
    Ok(())
}
