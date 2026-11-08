//! A workbook body's edits as the version sweep's operations (FIX 2460).

use oneiron_docedit::xlsx_body::{XlsxAxis, XlsxAxisEdit};

use super::super::model::ReanchorOp;
use super::{Units, text_of};

/// The version sweep's operations for a workbook body's edits between two
/// frontiers: the row and column edits the later one added, then each sheet
/// removed and each renamed, through a name no sheet holds so swapped names
/// stay apart. `None` when the later log does not begin with the earlier.
pub(super) fn sheet_ops(
    before: &Units,
    was: &[(String, XlsxAxisEdit)],
    after: &Units,
    now: &[(String, XlsxAxisEdit)],
) -> Option<Vec<ReanchorOp>> {
    let added = now.strip_prefix(was)?;
    let mut ops: Vec<ReanchorOp> = added
        .iter()
        .filter_map(|(key, edit)| Some(axis_op(text_of(before, key)?.to_owned(), *edit)))
        .collect();
    let mut renamed = Vec::new();
    for (index, (key, name)) in before.iter().enumerate() {
        match text_of(after, key) {
            None => ops.push(ReanchorOp::RemoveSheet {
                sheet: name.clone(),
            }),
            Some(new) if new != name.as_str() => {
                let parked = format!("\u{0}{index}");
                ops.push(ReanchorOp::RenameSheet {
                    from: name.clone(),
                    to: parked.clone(),
                });
                renamed.push(ReanchorOp::RenameSheet {
                    from: parked,
                    to: new.to_owned(),
                });
            }
            Some(_) => {}
        }
    }
    ops.extend(renamed);
    Some(ops)
}

fn axis_op(sheet: String, edit: XlsxAxisEdit) -> ReanchorOp {
    let (at, count) = (edit.at, edit.count);
    match (edit.axis, edit.delete) {
        (XlsxAxis::Row, false) => ReanchorOp::InsertRows {
            sheet,
            at_row: at,
            count,
        },
        (XlsxAxis::Row, true) => ReanchorOp::DeleteRows {
            sheet,
            at_row: at,
            count,
        },
        (XlsxAxis::Column, false) => ReanchorOp::InsertCols {
            sheet,
            at_col: at,
            count,
        },
        (XlsxAxis::Column, true) => ReanchorOp::DeleteCols {
            sheet,
            at_col: at,
            count,
        },
    }
}
