//! A live table (ARCH-0077, "One deck, one document": "Movable lists of
//! stable ids. Key cells by row and column ids; validate merge rectangles
//! after concurrent edits."). Its rows and columns are ordered lists of
//! identities that a move keeps and a removal never frees; each cell's text
//! is keyed by its row and its column; a merge is a rectangle named by its
//! corner rows and columns, drawn over whatever lies between them in the
//! current order. A merge the current order breaks is not drawn, and its
//! cells keep their text and properties (CALLS, the invalid-merge rule).

use super::{DeckNode, NodeId, NodePayload, WRITTEN_TABLE};
use crate::live::LiveError;
use crate::live::conversion::Conversion;
use crate::native_patch::Merge;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A table's binding names a grid its retained XML does not have.
pub(crate) const UNBOUND_GRID: &str = "a table's binding does not match its retained grid";

/// A table: its rows top to bottom and its columns left to right, each by
/// identity; each cell's text by row and column (a cell it does not hold is
/// empty; `\n` between a cell's paragraphs); and its merge rectangles. The
/// first row is the header a new table is written with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TableBody {
    pub rows: Vec<NodeId>,
    pub columns: Vec<NodeId>,
    #[serde(default)]
    pub cells: BTreeMap<NodeId, BTreeMap<NodeId, String>>,
    #[serde(default)]
    pub merges: Vec<TableMerge>,
}

/// A merge rectangle by its corner rows and columns: every row from
/// `first_row` to `last_row` and every column from `first_column` to
/// `last_column` in the table's current order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct TableMerge {
    pub first_row: NodeId,
    pub first_column: NodeId,
    pub last_row: NodeId,
    pub last_column: NodeId,
}

/// One edit to a table by identity: PowerPoint's Insert and Delete Rows
/// and Columns, a row or column moved, a cell's text, Merge Cells and Split
/// Cells over a merge. A row or column is placed after the one `after`
/// names, first when it names none, or last when the table no longer holds
/// the one named. An edit naming a row or column the table no longer holds
/// does nothing: a concurrent delete wins, and a cell never brings its row
/// or column back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TableEdit {
    /// A new, empty row; `id` names it, or its writer names a fresh one.
    InsertRow {
        #[serde(default)]
        id: Option<NodeId>,
        #[serde(default)]
        after: Option<NodeId>,
    },
    /// A new, empty column; `id` names it, or its writer names a fresh one.
    InsertColumn {
        #[serde(default)]
        id: Option<NodeId>,
        #[serde(default)]
        after: Option<NodeId>,
    },
    /// A row and its cells go; its identity is never used again.
    DeleteRow { row: NodeId },
    /// A column and its cells go; its identity is never used again.
    DeleteColumn { column: NodeId },
    /// A row moves with its cells, height and formatting.
    MoveRow {
        row: NodeId,
        #[serde(default)]
        after: Option<NodeId>,
    },
    /// A column moves with its cells, width and formatting.
    MoveColumn {
        column: NodeId,
        #[serde(default)]
        after: Option<NodeId>,
    },
    /// One cell's text; empty clears it.
    SetCell {
        row: NodeId,
        column: NodeId,
        text: String,
    },
    /// Merge the cells of a rectangle.
    Merge(TableMerge),
    /// Split one merge back into its cells.
    Unmerge(TableMerge),
}

/// Why a table does not draw a merge it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeFault {
    /// A corner row or column is gone.
    MissingCorner,
    /// The current order puts one corner past the other.
    Reversed,
    /// It covers one cell.
    Collapsed,
    /// It overlaps a merge that comes first in corner order.
    Overlaps,
}

impl MergeFault {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::MissingCorner => "a corner row or column is gone",
            Self::Reversed => "a corner row or column moved past the other",
            Self::Collapsed => "it covers one cell",
            Self::Overlaps => "it overlaps a merge before it",
        }
    }
}

/// Which row and column identity each grid row and column of a bound
/// table's retained XML holds, as the import read it or the last landed
/// export wrote it: retained evidence, never the order to write. The next
/// export finds each identity's own row, column and cells by it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableBinding {
    pub rows: Vec<NodeId>,
    pub columns: Vec<NodeId>,
}

impl TableBinding {
    /// The binding `table` takes once it is written in its own order.
    #[must_use]
    pub fn of(table: &TableBody) -> Self {
        Self {
            rows: table.rows.clone(),
            columns: table.columns.clone(),
        }
    }
}

/// The merges a table draws, each with its grid span (its first row 0),
/// and the ones it does not, each with why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Effective {
    pub(crate) drawn: Vec<(TableMerge, Merge)>,
    pub(crate) faults: Vec<(TableMerge, MergeFault)>,
}

impl Effective {
    /// The grid spans drawn.
    pub(crate) fn spans(&self) -> Vec<Merge> {
        self.drawn.iter().map(|(_, span)| *span).collect()
    }
}

/// Where each identity sits in an order; a repeat keeps its first place.
/// The coordinate seam a retained binding is read through.
pub(crate) fn positions(ids: &[NodeId]) -> BTreeMap<NodeId, usize> {
    let mut out = BTreeMap::new();
    for (at, id) in ids.iter().enumerate() {
        out.entry(*id).or_insert(at);
    }
    out
}

/// Hold each identity once, at its first place.
pub(crate) fn dedupe(ids: &mut Vec<NodeId>) {
    let mut seen = BTreeSet::new();
    ids.retain(|id| seen.insert(*id));
}

impl TableBody {
    /// A table of `grid`'s text, one row per line, as wide as its widest
    /// line; each row and then each column named from `mint`.
    pub fn of_grid(grid: &[Vec<String>], mut mint: impl FnMut() -> NodeId) -> Self {
        let width = grid.iter().map(Vec::len).max().unwrap_or(0);
        let rows: Vec<NodeId> = grid.iter().map(|_| mint()).collect();
        let columns: Vec<NodeId> = (0..width).map(|_| mint()).collect();
        let mut cells: BTreeMap<NodeId, BTreeMap<NodeId, String>> = BTreeMap::new();
        for (row, line) in rows.iter().zip(grid) {
            for (column, text) in columns.iter().zip(line) {
                if !text.is_empty() {
                    cells.entry(*row).or_default().insert(*column, text.clone());
                }
            }
        }
        Self {
            rows,
            columns,
            cells,
            merges: Vec::new(),
        }
    }

    /// The text of the cell at `row` and `column`; empty when it holds none.
    #[must_use]
    pub fn cell(&self, row: NodeId, column: NodeId) -> &str {
        self.cells
            .get(&row)
            .and_then(|line| line.get(&column))
            .map_or("", String::as_str)
    }

    /// The table's text in grid order: one line per row, one cell per
    /// column.
    #[must_use]
    pub fn grid(&self) -> Vec<Vec<String>> {
        self.rows
            .iter()
            .map(|row| {
                self.columns
                    .iter()
                    .map(|column| self.cell(*row, *column).to_owned())
                    .collect()
            })
            .collect()
    }

    /// Its size: rows by columns.
    #[must_use]
    pub fn shape(&self) -> (usize, usize) {
        (self.rows.len(), self.columns.len())
    }

    /// The table in its one written form, and what that did: a repeated row
    /// or column is held once (the first), a cell outside its rows and
    /// columns or with no text is not held, and each merge is held once, in
    /// corner order; a merge naming a row or column the table does not hold
    /// is dropped, its cells keeping their text. A table of no row or no
    /// column refuses: PowerPoint deletes a table whose last row or column
    /// goes, which `RemoveNode` does.
    pub(crate) fn settle(&mut self) -> Result<Vec<Conversion>, LiveError> {
        dedupe(&mut self.rows);
        dedupe(&mut self.columns);
        if self.rows.is_empty() || self.columns.is_empty() {
            return Err(LiveError::Invalid(WRITTEN_TABLE));
        }
        let rows: BTreeSet<NodeId> = self.rows.iter().copied().collect();
        let columns: BTreeSet<NodeId> = self.columns.iter().copied().collect();
        self.cells.retain(|row, line| {
            line.retain(|column, text| columns.contains(column) && !text.is_empty());
            rows.contains(row) && !line.is_empty()
        });
        self.merges.sort_unstable();
        self.merges.dedup();
        let mut done = Vec::new();
        self.merges.retain(|merge| {
            let held = rows.contains(&merge.first_row)
                && rows.contains(&merge.last_row)
                && columns.contains(&merge.first_column)
                && columns.contains(&merge.last_column);
            if !held {
                done.push(Conversion::TableMergeDeactivated {
                    merge: *merge,
                    fault: MergeFault::MissingCorner,
                });
            }
            held
        });
        Ok(done)
    }

    /// `self` settled as a payload written over `was`, the table the node
    /// held (none for a new one), with what that did: the merges it no
    /// longer draws.
    pub(crate) fn settled(
        &self,
        was: Option<&TableBody>,
    ) -> Result<(TableBody, Vec<Conversion>), LiveError> {
        let mut table = self.clone();
        let mut done = table.settle()?;
        done.extend(deactivated(was, &table));
        Ok((table, done))
    }

    /// The merges the table draws in its current order, as grid spans, and
    /// those it does not, with why: one whose corner row or column is gone,
    /// whose corners the order puts past each other, or that covers one
    /// cell is not drawn; of two that overlap, the first in corner order is
    /// drawn. None is removed: a move or an unmerge may let it draw again.
    pub(crate) fn effective(&self) -> Effective {
        let rows = positions(&self.rows);
        let columns = positions(&self.columns);
        let mut merges = self.merges.clone();
        merges.sort_unstable();
        merges.dedup();
        let mut out = Effective::default();
        for merge in merges {
            let (Some(&row), Some(&col), Some(&last_row), Some(&last_col)) = (
                rows.get(&merge.first_row),
                columns.get(&merge.first_column),
                rows.get(&merge.last_row),
                columns.get(&merge.last_column),
            ) else {
                out.faults.push((merge, MergeFault::MissingCorner));
                continue;
            };
            let fault = if last_row < row || last_col < col {
                Some(MergeFault::Reversed)
            } else if (last_row, last_col) == (row, col) {
                Some(MergeFault::Collapsed)
            } else if out.drawn.iter().any(|(_, span)| {
                span.row <= last_row
                    && row < span.row + span.rows
                    && span.col <= last_col
                    && col < span.col + span.cols
            }) {
                Some(MergeFault::Overlaps)
            } else {
                None
            };
            match fault {
                Some(fault) => out.faults.push((merge, fault)),
                None => out.drawn.push((
                    merge,
                    Merge {
                        row,
                        col,
                        rows: last_row - row + 1,
                        cols: last_col - col + 1,
                    },
                )),
            }
        }
        out
    }

    /// Every merge the table holds whose corners it holds, as grid corners
    /// (first row, first column, last row, last column) wherever the order
    /// puts them: what a retained table's spans are compared with, so a
    /// table whose merges are as read writes none.
    pub(crate) fn corners(&self) -> BTreeSet<(usize, usize, usize, usize)> {
        let rows = positions(&self.rows);
        let columns = positions(&self.columns);
        self.merges
            .iter()
            .filter_map(|merge| {
                Some((
                    *rows.get(&merge.first_row)?,
                    *columns.get(&merge.first_column)?,
                    *rows.get(&merge.last_row)?,
                    *columns.get(&merge.last_column)?,
                ))
            })
            .collect()
    }
}

/// The merges `now` does not draw that `was` drew or did not hold: what an
/// edit deactivated, for its effects.
pub(crate) fn deactivated(was: Option<&TableBody>, now: &TableBody) -> Vec<Conversion> {
    let before: BTreeSet<TableMerge> = match was {
        Some(was) => was
            .effective()
            .faults
            .into_iter()
            .map(|(merge, _)| merge)
            .collect(),
        None => BTreeSet::new(),
    };
    now.effective()
        .faults
        .into_iter()
        .filter(|(merge, _)| !before.contains(merge))
        .map(|(merge, fault)| Conversion::TableMergeDeactivated { merge, fault })
        .collect()
}

/// The cells both sides of a fork wrote differently, when the base, the
/// head and the proposal all hold a table: a table's other units (rows and
/// columns inserted, deleted or moved, merges made or unmade, a cell only
/// one side wrote, a cell of a row or column one side deleted) join without
/// conflict. `None` when one of them holds no table.
pub(crate) fn conflicts(
    base: &DeckNode,
    head: &DeckNode,
    proposal: &DeckNode,
) -> Option<Vec<(NodeId, NodeId)>> {
    let (Some(NodePayload::Table(b)), Some(NodePayload::Table(h)), Some(NodePayload::Table(p))) =
        (&base.payload, &head.payload, &proposal.payload)
    else {
        return None;
    };
    if base.preset != head.preset || base.preset != proposal.preset {
        return None;
    }
    let set = |ids: &[NodeId]| -> BTreeSet<NodeId> { ids.iter().copied().collect() };
    let (head_rows, head_columns) = (set(&h.rows), set(&h.columns));
    let (proposal_rows, proposal_columns) = (set(&p.rows), set(&p.columns));
    let mut keys: BTreeSet<(NodeId, NodeId)> = BTreeSet::new();
    for table in [b, h, p] {
        for (row, line) in &table.cells {
            keys.extend(line.keys().map(|column| (*row, *column)));
        }
    }
    Some(
        keys.into_iter()
            .filter(|(row, column)| {
                let both = head_rows.contains(row)
                    && proposal_rows.contains(row)
                    && head_columns.contains(column)
                    && proposal_columns.contains(column);
                let (was, head, proposal) = (
                    b.cell(*row, *column),
                    h.cell(*row, *column),
                    p.cell(*row, *column),
                );
                both && was != head && was != proposal && head != proposal
            })
            .collect(),
    )
}
