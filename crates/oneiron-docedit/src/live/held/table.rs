//! A retained table as the live model reads it (ARCH-0077: a table keeps
//! its `a:tbl`, `a:tblGrid`, row heights and `gridSpan`, `rowSpan`,
//! `hMerge` and `vMerge`, anchors told from continuations): its rows' and
//! columns' identities, minted once in retained order, each cell's text, and
//! each anchor cell's span as a merge rectangle.

use super::{FRAME_DATA, children, paragraphs};
use crate::deck::{ShapeKind, ShapeView};
use crate::edit::xml::{self, A};
use crate::live::pptx::{NodeId, TableBinding, TableBody, TableMerge};
use crate::ooxml::{Node, XmlTree};
use std::collections::{BTreeMap, BTreeSet};

/// A table frame's `a:tbl`.
pub(crate) fn table_of(tree: &XmlTree, frame: usize) -> Option<usize> {
    let data = xml::path(tree, frame, FRAME_DATA)?;
    xml::child(tree, data, A, "tbl")
}

/// A table frame's rows of cell text, top row first, each cell read as
/// `NativeEdit::SetTableCell` reads it: the `a:t` text of each paragraph,
/// joined by `\n`. `None` when the frame holds no table.
pub(crate) fn table_cells(tree: &XmlTree, frame: usize) -> Option<Vec<Vec<String>>> {
    let tbl = table_of(tree, frame)?;
    Some(
        cell_grid(tree, tbl)
            .iter()
            .map(|line| line.iter().map(|&tc| cell_text(tree, tc)).collect())
            .collect(),
    )
}

fn cell_text(tree: &XmlTree, tc: usize) -> String {
    xml::child(tree, tc, A, "txBody").map_or_else(String::new, |body| paragraphs(tree, body))
}

/// Each `a:tr`'s `a:tc` elements, in order.
fn cell_grid(tree: &XmlTree, tbl: usize) -> Vec<Vec<usize>> {
    children(tree, tbl, A, "tr")
        .map(|tr| children(tree, tr, A, "tc").collect())
        .collect()
}

/// The table's columns: its `a:tblGrid`'s, or its widest row's when it
/// declares none.
fn width(tree: &XmlTree, tbl: usize, grid: &[Vec<usize>]) -> usize {
    let declared = xml::child(tree, tbl, A, "tblGrid")
        .map_or(0, |at| children(tree, at, A, "gridCol").count());
    if declared > 0 {
        declared
    } else {
        grid.iter().map(Vec::len).max().unwrap_or(0)
    }
}

/// Whether a merge flag (`hMerge`, `vMerge`) is set, as the native writer
/// reads it.
pub(crate) fn flag(node: &Node, name: &str) -> bool {
    matches!(node.attr(name), Some("1" | "true"))
}

/// A span (`gridSpan`, `rowSpan`): 1 when absent or unreadable.
pub(crate) fn span(node: &Node, name: &str) -> usize {
    node.attr(name)
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|span| *span >= 1)
        .unwrap_or(1)
}

/// The merges a retained table's XML draws, as grid corners (first row,
/// first column, last row, last column): each anchor cell's `rowSpan` and
/// `gridSpan`, clamped to the grid, over more than one cell. A continuation
/// cell (`hMerge`, `vMerge`) anchors none.
pub(crate) fn spans(tree: &XmlTree, tbl: usize) -> BTreeSet<(usize, usize, usize, usize)> {
    let grid = cell_grid(tree, tbl);
    let (rows, cols) = (grid.len(), width(tree, tbl, &grid));
    let mut out = BTreeSet::new();
    for (row, line) in grid.iter().enumerate() {
        for (col, &tc) in line.iter().enumerate().take(cols) {
            let node = &tree.nodes[tc];
            if flag(node, "hMerge") || flag(node, "vMerge") {
                continue;
            }
            let last_row = row.saturating_add(span(node, "rowSpan") - 1).min(rows - 1);
            let last_col = col.saturating_add(span(node, "gridSpan") - 1).min(cols - 1);
            if (last_row, last_col) != (row, col) {
                out.insert((row, col, last_row, last_col));
            }
        }
    }
    out
}

/// A retained table frame's live table, with the binding its XML's rows and
/// columns take: each row's and then each column's identity drawn from
/// `mint` in retained order, each cell's text as [`table_cells`] reads it (a
/// continuation cell keeps its own), and [`spans`] as merges. `None` when
/// the shape is not a table frame, or its table has no row or no column.
pub(crate) fn import(
    tree: &XmlTree,
    shape: &ShapeView,
    mut mint: impl FnMut() -> NodeId,
) -> Option<(TableBody, TableBinding)> {
    if shape.kind != ShapeKind::GraphicFrame {
        return None;
    }
    let tbl = table_of(tree, shape.node.index)?;
    let grid = cell_grid(tree, tbl);
    let cols = width(tree, tbl, &grid);
    if grid.is_empty() || cols == 0 {
        return None;
    }
    let rows: Vec<NodeId> = grid.iter().map(|_| mint()).collect();
    let columns: Vec<NodeId> = (0..cols).map(|_| mint()).collect();
    let mut cells: BTreeMap<NodeId, BTreeMap<NodeId, String>> = BTreeMap::new();
    for (row, line) in rows.iter().zip(&grid) {
        for (column, &tc) in columns.iter().zip(line) {
            let text = cell_text(tree, tc);
            if !text.is_empty() {
                cells.entry(*row).or_default().insert(*column, text);
            }
        }
    }
    let merges = spans(tree, tbl)
        .into_iter()
        .map(|(row, col, last_row, last_col)| TableMerge {
            first_row: rows[row],
            first_column: columns[col],
            last_row: rows[last_row],
            last_column: columns[last_col],
        })
        .collect();
    let mut table = TableBody {
        rows,
        columns,
        cells,
        merges,
    };
    table.merges.sort_unstable();
    let binding = TableBinding::of(&table);
    Some((table, binding))
}
