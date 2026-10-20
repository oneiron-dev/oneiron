//! A table at export, by row and column identity: a bound table's grid
//! rewritten where its rows, columns or merges changed, then its changed
//! cells written; a live-born table written through the native writer with
//! the merges it draws; and the binding a table's export takes, so the next
//! export finds each row's and column's own XML by its identity.

use super::{TABLE_CELL, Work, shape_at};
use crate::design_plan::{Cell, Column, ColumnKind, Dataset, Rect};
use crate::live::LiveError;
use crate::live::conversion::Conversion;
use crate::live::held::table as held_table;
use crate::live::pptx::{
    DeckNode, NodeId, NodePayload, TableBinding, TableBody, UNBOUND_GRID, WRITTEN_FRAME,
    WRITTEN_TABLE,
};
use crate::live::reshape;
use crate::native_patch::{Frame, NativeEdit, native_patch};
use crate::ooxml::XmlTree;

/// The binding a table frame's export takes: its rows and columns in the
/// order the export wrote them.
pub(super) fn binding(node: &DeckNode) -> Option<TableBinding> {
    match &node.payload {
        Some(NodePayload::Table(table)) => Some(TableBinding::of(table)),
        _ => None,
    }
}

/// Write a bound table's model over its retained `a:tbl`, the frame at `at`
/// in `tree` (`part`'s slide as it reads now). Rows, columns and merges as
/// its binding and its XML hold them write nothing; otherwise the grid is
/// rewritten by identity ([`reshape::table`]), the merges it does not draw
/// named. Then each cell whose text differs is written through the native
/// writer, a cell a merge covers included: its text stays under the merge,
/// as PowerPoint keeps it (the Engine ruling of 10-20).
pub(super) fn project(
    work: &mut Work,
    id: NodeId,
    node: &DeckNode,
    (part, native): (&str, u32),
    at: usize,
    tree: &XmlTree,
    table: &TableBody,
) -> Result<(), LiveError> {
    let bound = node
        .binding
        .as_ref()
        .and_then(|binding| binding.table.as_ref())
        .ok_or(LiveError::Invalid(UNBOUND_GRID))?;
    let tbl = held_table::table_of(tree, at).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let same = table.rows == bound.rows
        && table.columns == bound.columns
        && table.corners() == held_table::spans(tree, tbl);
    let have = if same {
        held_table::table_cells(tree, at).ok_or(LiveError::Invalid(WRITTEN_FRAME))?
    } else {
        let effective = table.effective();
        let fit = node.geometry.extent.is_none();
        if let Some(extent) = reshape::table(
            work.next_mut(),
            part,
            native,
            table,
            bound,
            &effective.spans(),
            fit,
        )? {
            work.converted(id, [Conversion::TableFrameFitted { extent }]);
        }
        work.converted(
            id,
            effective
                .faults
                .into_iter()
                .map(|(merge, fault)| Conversion::TableMergeDeactivated { merge, fault }),
        );
        work.changed.insert(part.to_owned());
        let view = work.view()?;
        let at = shape_at(&view, part, native)
            .ok_or(LiveError::UnknownNode)?
            .node
            .index;
        let tree = work.slide_tree(part)?;
        held_table::table_cells(&tree, at).ok_or(LiveError::Invalid(WRITTEN_FRAME))?
    };
    for (row, (was, now)) in have.iter().zip(table.grid()).enumerate() {
        for (col, (was, now)) in was.iter().zip(&now).enumerate() {
            if was == now {
                continue;
            }
            let report = native_patch(
                work.next_mut(),
                &NativeEdit::SetTableCell {
                    slide: part,
                    table: native,
                    row,
                    col,
                    expected: was,
                    value: now,
                },
            )?;
            work.changed.extend(report.changed_parts);
        }
    }
    Ok(())
}

/// Write a live-born table through the native writer as frame `id` at
/// `offset` in `part`: its first row the header, then its rows, with the
/// merges it draws, at its own extent or two inches per column by 0.4 inch
/// per row. Each cell keeps its own text, a cell a merge covers included,
/// under the merge as PowerPoint keeps it; the merges the table does not
/// draw are named.
pub(super) fn born(
    work: &mut Work,
    live: NodeId,
    node: &DeckNode,
    (part, id): (&str, u32),
    (x, y): (i64, i64),
    table: &TableBody,
) -> Result<(), LiveError> {
    let grid = table.grid();
    let Some((header, rows)) = grid.split_first() else {
        return Err(LiveError::Invalid(WRITTEN_TABLE));
    };
    if header.is_empty() {
        return Err(LiveError::Invalid(WRITTEN_TABLE));
    }
    let effective = table.effective();
    let done: Vec<Conversion> = effective
        .faults
        .iter()
        .map(|&(merge, fault)| Conversion::TableMergeDeactivated { merge, fault })
        .collect();
    let spans = effective.spans();
    let data = Dataset {
        id: String::new(),
        columns: header
            .iter()
            .map(|name| Column {
                name: name.clone(),
                kind: ColumnKind::Text,
                unit: None,
                format: None,
            })
            .collect(),
        rows: rows
            .iter()
            .map(|line| {
                line.iter()
                    .map(|text| {
                        if text.is_empty() {
                            Cell::Missing
                        } else {
                            Cell::Text(text.clone())
                        }
                    })
                    .collect()
            })
            .collect(),
        missing: None,
        sources: Vec::new(),
        merges: Vec::new(),
    };
    let count = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    let (cx, cy) = node.geometry.extent.unwrap_or((
        TABLE_CELL.0.saturating_mul(count(header.len())),
        TABLE_CELL.1.saturating_mul(count(grid.len())),
    ));
    let name = node.name.clone().unwrap_or_else(|| "Table".to_owned());
    let report = native_patch(
        work.next_mut(),
        &NativeEdit::CreateTable {
            frame: Frame {
                slide: part,
                id,
                name: &name,
                bounds: Rect { x, y, cx, cy },
                placeholder: None,
            },
            dataset: &data,
            merges: &spans,
        },
    )?;
    work.changed.extend(report.changed_parts);
    work.converted(live, done);
    Ok(())
}
