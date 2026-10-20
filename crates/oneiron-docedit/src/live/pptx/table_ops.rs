//! Table edits applied by identity; a whole table written over the table a
//! node holds lowered to the edits that make it, before it is logged; and
//! the row and column identities a writer names before an edit is logged,
//! so every replay inserts the same rows and columns.

use super::table::{TableBody, TableEdit, TableMerge, deactivated, dedupe};
use super::{DeckOp, LiveDeck, NodeId, NodePayload};
use crate::live::LiveError;
use crate::live::conversion::Conversion;
use std::collections::{BTreeMap, BTreeSet};

const NO_TABLE: &str = "the node holds no table";
const TAKEN: &str = "the row or column identity is taken";

impl TableEdit {
    /// How many identities applying this edit mints: one for an insertion
    /// that names none.
    pub(super) fn unnamed(&self) -> u64 {
        u64::from(matches!(
            self,
            Self::InsertRow { id: None, .. } | Self::InsertColumn { id: None, .. }
        ))
    }

    /// Name an insertion that names no identity, from `mint`.
    pub(super) fn name(&mut self, mint: &mut impl FnMut() -> NodeId) {
        if let Self::InsertRow { id, .. } | Self::InsertColumn { id, .. } = self
            && id.is_none()
        {
            *id = Some(mint());
        }
    }
}

impl TableBody {
    /// Apply one edit; an insertion that names no identity takes one from
    /// `mint`.
    fn edit(
        &mut self,
        edit: &TableEdit,
        mint: &mut impl FnMut() -> NodeId,
    ) -> Result<(), LiveError> {
        match edit {
            TableEdit::InsertRow { id, after } => {
                let id = match id {
                    Some(id) => *id,
                    None => mint(),
                };
                insert(&mut self.rows, id, *after)?;
            }
            TableEdit::InsertColumn { id, after } => {
                let id = match id {
                    Some(id) => *id,
                    None => mint(),
                };
                insert(&mut self.columns, id, *after)?;
            }
            TableEdit::DeleteRow { row } => {
                self.rows.retain(|held| held != row);
                self.cells.remove(row);
            }
            TableEdit::DeleteColumn { column } => {
                self.columns.retain(|held| held != column);
                for line in self.cells.values_mut() {
                    line.remove(column);
                }
            }
            TableEdit::MoveRow { row, after } => place(&mut self.rows, *row, *after),
            TableEdit::MoveColumn { column, after } => place(&mut self.columns, *column, *after),
            TableEdit::SetCell { row, column, text } => {
                if self.rows.contains(row) && self.columns.contains(column) {
                    if text.is_empty() {
                        if let Some(line) = self.cells.get_mut(row) {
                            line.remove(column);
                        }
                    } else {
                        self.cells
                            .entry(*row)
                            .or_default()
                            .insert(*column, text.clone());
                    }
                }
            }
            TableEdit::Merge(merge) => {
                if !self.merges.contains(merge) {
                    self.merges.push(*merge);
                }
            }
            TableEdit::Unmerge(merge) => self.merges.retain(|held| held != merge),
        }
        Ok(())
    }
}

/// Insert `id` after `after` (first for none, last when it is gone). An
/// identity the order holds refuses: identities are never reused.
fn insert(ids: &mut Vec<NodeId>, id: NodeId, after: Option<NodeId>) -> Result<(), LiveError> {
    if ids.contains(&id) {
        return Err(LiveError::Invalid(TAKEN));
    }
    let at = slot(ids, after);
    ids.insert(at, id);
    Ok(())
}

/// Move a held `id` after `after`; one the order does not hold stays gone.
fn place(ids: &mut Vec<NodeId>, id: NodeId, after: Option<NodeId>) {
    if after == Some(id) {
        return;
    }
    let Some(from) = ids.iter().position(|held| *held == id) else {
        return;
    };
    ids.remove(from);
    let at = slot(ids, after);
    ids.insert(at, id);
}

/// The index right after `after`: 0 for none, the end when it is gone.
fn slot(ids: &[NodeId], after: Option<NodeId>) -> usize {
    match after {
        None => 0,
        Some(after) => ids
            .iter()
            .position(|held| *held == after)
            .map_or(ids.len(), |at| at + 1),
    }
}

/// Apply `edits` to the table `node` holds, returning what they did
/// PowerPoint's way: the merges they leave undrawn. A bound table whose
/// rows or columns change in number takes its grid's size at export, as
/// PowerPoint lays it out: its own extent clears.
pub(super) fn edit_table(
    deck: &mut LiveDeck,
    node: NodeId,
    edits: &[TableEdit],
) -> Result<Vec<Conversion>, LiveError> {
    let found = deck.nodes.get(&node).ok_or(LiveError::UnknownNode)?;
    let Some(NodePayload::Table(held)) = &found.payload else {
        return Err(LiveError::Invalid(NO_TABLE));
    };
    let (held, bound) = (held.clone(), found.binding.is_some());
    let mut table = held.clone();
    let mut mint = || deck.mint();
    for edit in edits {
        table.edit(edit, &mut mint)?;
    }
    let mut done = table.settle()?;
    done.extend(deactivated(Some(&held), &table));
    let found = deck.nodes.get_mut(&node).ok_or(LiveError::UnknownNode)?;
    if bound && held.shape() != table.shape() {
        found.geometry.extent = None;
    }
    found.payload = Some(NodePayload::Table(table));
    Ok(done)
}

impl LiveDeck {
    /// `op` as its writer logs it. A whole table written over the table a
    /// node holds is lowered to the table edits that make it, by identity,
    /// so it joins concurrent table work rather than replacing it: a row or
    /// column it names that the held table does not hold is new and takes a
    /// fresh identity from `mint`, never one an export's positions suggest.
    /// Any other operation is logged as written.
    pub fn lower(&self, op: &DeckOp, mut mint: impl FnMut() -> NodeId) -> DeckOp {
        if let DeckOp::SetPayload {
            node,
            payload: NodePayload::Table(wanted),
        } = op
            && let Some(NodePayload::Table(held)) = self
                .nodes
                .get(node)
                .and_then(|found| found.payload.as_ref())
        {
            return DeckOp::EditTable {
                node: *node,
                edits: lower_table(held, wanted, &mut mint),
            };
        }
        op.clone()
    }
}

/// The edits that make `held` into `wanted`: the rows and columns `wanted`
/// drops deleted, the rest placed in its order (a new one inserted under a
/// fresh identity, a held one moved only where it is out of place), each
/// cell's text set where it differs, and its merges made and unmade.
fn lower_table(
    held: &TableBody,
    wanted: &TableBody,
    mint: &mut impl FnMut() -> NodeId,
) -> Vec<TableEdit> {
    let mut wanted = wanted.clone();
    let rows = rename(&mut wanted.rows, &held.rows, mint);
    let columns = rename(&mut wanted.columns, &held.columns, mint);
    let named = |map: &BTreeMap<NodeId, NodeId>, id: NodeId| map.get(&id).copied().unwrap_or(id);
    wanted.cells = std::mem::take(&mut wanted.cells)
        .into_iter()
        .map(|(row, line)| {
            let line: BTreeMap<NodeId, String> = line
                .into_iter()
                .map(|(column, text)| (named(&columns, column), text))
                .collect();
            (named(&rows, row), line)
        })
        .collect();
    for merge in &mut wanted.merges {
        *merge = TableMerge {
            first_row: named(&rows, merge.first_row),
            first_column: named(&columns, merge.first_column),
            last_row: named(&rows, merge.last_row),
            last_column: named(&columns, merge.last_column),
        };
    }
    let mut edits = Vec::new();
    order(
        &held.rows,
        &wanted.rows,
        &mut edits,
        [
            |id, _| TableEdit::DeleteRow { row: id },
            |id, after| TableEdit::MoveRow { row: id, after },
            |id, after| TableEdit::InsertRow {
                id: Some(id),
                after,
            },
        ],
    );
    order(
        &held.columns,
        &wanted.columns,
        &mut edits,
        [
            |id, _| TableEdit::DeleteColumn { column: id },
            |id, after| TableEdit::MoveColumn { column: id, after },
            |id, after| TableEdit::InsertColumn {
                id: Some(id),
                after,
            },
        ],
    );
    for row in &wanted.rows {
        for column in &wanted.columns {
            let text = wanted.cell(*row, *column);
            if held.cell(*row, *column) != text {
                edits.push(TableEdit::SetCell {
                    row: *row,
                    column: *column,
                    text: text.to_owned(),
                });
            }
        }
    }
    let had: BTreeSet<TableMerge> = held.merges.iter().copied().collect();
    let has: BTreeSet<TableMerge> = wanted.merges.iter().copied().collect();
    edits.extend(had.difference(&has).copied().map(TableEdit::Unmerge));
    edits.extend(has.difference(&had).copied().map(TableEdit::Merge));
    edits
}

/// `ids` held once each, with every identity `held` does not hold renamed
/// fresh from `mint`; the renames, by the name written.
fn rename(
    ids: &mut Vec<NodeId>,
    held: &[NodeId],
    mint: &mut impl FnMut() -> NodeId,
) -> BTreeMap<NodeId, NodeId> {
    dedupe(ids);
    let held: BTreeSet<NodeId> = held.iter().copied().collect();
    let mut renamed = BTreeMap::new();
    for id in &mut *ids {
        if !held.contains(id) {
            let fresh = mint();
            renamed.insert(*id, fresh);
            *id = fresh;
        }
    }
    renamed
}

/// One edit-making function per kind: delete, move, insert, each given the
/// identity and the one it goes after.
type Makers = [fn(NodeId, Option<NodeId>) -> TableEdit; 3];

/// The deletes, moves and inserts that make the order `held` into
/// `wanted`, each placed after the identity before it in `wanted`.
fn order(
    held: &[NodeId],
    wanted: &[NodeId],
    edits: &mut Vec<TableEdit>,
    [delete, moved, inserted]: Makers,
) {
    let keep: BTreeSet<NodeId> = wanted.iter().copied().collect();
    let mut now = Vec::with_capacity(held.len());
    for id in held {
        if keep.contains(id) {
            now.push(*id);
        } else {
            edits.push(delete(*id, None));
        }
    }
    for (index, id) in wanted.iter().enumerate() {
        if now.get(index) == Some(id) {
            continue;
        }
        let after = index.checked_sub(1).map(|before| wanted[before]);
        match now.iter().position(|held| held == id) {
            Some(from) => {
                now.remove(from);
                now.insert(index, *id);
                edits.push(moved(*id, after));
            }
            None => {
                now.insert(index, *id);
                edits.push(inserted(*id, after));
            }
        }
    }
}

impl DeckOp {
    /// How many identities applying this operation mints: an unnamed
    /// creation's, and each row or column a table edit inserts unnamed.
    #[must_use]
    pub fn unnamed(&self) -> u64 {
        match self {
            DeckOp::AddSlide { id: None } | DeckOp::AddNode { id: None, .. } => 1,
            DeckOp::EditTable { edits, .. } => edits.iter().map(TableEdit::unnamed).sum(),
            _ => 0,
        }
    }

    /// Name what this operation leaves unnamed, in order, from `mint`: a
    /// creation's identity, and each row or column a table edit inserts.
    /// What a writer records so every replay makes the same node, row and
    /// column.
    pub fn name_creation(&mut self, mut mint: impl FnMut() -> NodeId) {
        match self {
            DeckOp::AddSlide { id } | DeckOp::AddNode { id, .. } => {
                if id.is_none() {
                    *id = Some(mint());
                }
            }
            DeckOp::EditTable { edits, .. } => {
                for edit in edits {
                    edit.name(&mut mint);
                }
            }
            _ => {}
        }
    }
}
