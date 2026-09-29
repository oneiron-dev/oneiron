//! Serialize post-2007 spreadsheet functions with Excel's OOXML prefix.

use super::{CellValue, EditOp, EditPlan};
use oneiron_docedit::xlfn::storage_form;

/// Return a plan with modern function calls prefixed before the session sees
/// them. The returned ops (rather than the caller's input) become the manifest.
pub(super) fn serialize_plan(plan: &EditPlan) -> EditPlan {
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
    plan
}

fn serialize_value(value: &mut CellValue) {
    if let CellValue::Formula { expr, .. } = value {
        *expr = storage_form(expr);
    }
}
