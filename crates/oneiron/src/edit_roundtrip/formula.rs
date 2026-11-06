//! Serialize post-2007 spreadsheet functions with Excel's OOXML prefix.

use super::{CellValue, EditOp, EditPlan};
use oneiron_docedit::xlfn::storage_form;
use std::borrow::Cow;

/// Return a plan with modern function calls prefixed before the session sees
/// them. The returned ops (rather than the caller's input) become the manifest.
/// Borrow the original plan when no formula field needs storage conversion.
pub(super) fn serialize_plan(plan: &EditPlan) -> Cow<'_, EditPlan> {
    if !plan.ops.iter().any(|op| match op {
        EditOp::SetCell { after, .. } => matches!(after, CellValue::Formula { .. }),
        EditOp::SetRange { writes, .. } => writes
            .iter()
            .any(|write| matches!(&write.after, CellValue::Formula { .. })),
        EditOp::AddFormulaColumn { .. } => true,
        _ => false,
    }) {
        return Cow::Borrowed(plan);
    }
    let mut plan = plan.clone();
    for op in &mut plan.ops {
        match op {
            EditOp::SetCell { after, .. } => serialize_value(after),
            EditOp::SetRange { writes, .. } => {
                for write in writes {
                    serialize_value(&mut write.after);
                }
            }
            EditOp::AddFormulaColumn { formula, .. } => *formula = storage_form(formula),
            _ => {}
        }
    }
    Cow::Owned(plan)
}

fn serialize_value(value: &mut CellValue) {
    if let CellValue::Formula { expr, .. } = value {
        *expr = storage_form(expr);
    }
}
