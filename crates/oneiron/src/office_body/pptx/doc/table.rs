//! A table frame's table in the body's `tables` root, keyed by the frame's
//! identity (ARCH-0077: "Movable lists of stable ids. Key cells by row and
//! column ids; validate merge rectangles after concurrent edits."). Its
//! frame's `payload` holds only [`MARK`]. Each entry holds `rows` and
//! `columns`, movable lists of identities; `cells`, a map from row identity
//! to a map from column identity to that cell's rich text, diffed on write;
//! and `merges`, one key per merge rectangle (its four corner identities),
//! so concurrent writers' rows, columns, cells, characters and merges all
//! join. The joined table is read as it stands: which merges it draws is
//! derived when it is drawn ([`TableBody`]), never written back by a
//! reader.

use super::{child_list, child_map, invalid, keys, loro, node_id, order};
use crate::error::Result;
use loro::{Container, LoroMap, LoroText, UpdateOptions, ValueOrContainer};
use oneiron_docedit::live::{LiveDeck, NodeId, NodePayload, TableBody, TableMerge};
use std::collections::{BTreeMap, BTreeSet};

/// A table frame's `payload` value: its table is the `tables` entry.
pub(super) const MARK: &str = "table";
const ROWS: &str = "rows";
const COLUMNS: &str = "columns";
const CELLS: &str = "cells";
const MERGES: &str = "merges";

/// The table `tables` holds for the frame `id`. A row or column listed
/// twice is held once, at its first place; a cell of a row or column the
/// table no longer lists is not part of it.
pub(super) fn read(tables: &LoroMap, id: NodeId) -> Result<TableBody> {
    let entry = child_map(tables, &key(id)).ok_or_else(|| invalid("deck table body"))?;
    let axis = |name: &str| -> Result<Vec<NodeId>> {
        let mut ids = Vec::new();
        let mut seen = BTreeSet::new();
        if let Some(list) = child_list(&entry, name) {
            for held in order::ids(&list)? {
                let id = node_id(&held)?;
                if seen.insert(id) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    };
    let (rows, columns) = (axis(ROWS)?, axis(COLUMNS)?);
    let mut cells: BTreeMap<NodeId, BTreeMap<NodeId, String>> = BTreeMap::new();
    if let Some(map) = child_map(&entry, CELLS) {
        for row in &rows {
            let Some(line) = child_map(&map, &key(*row)) else {
                continue;
            };
            for column in &columns {
                if let Some(text) = child_text(&line, &key(*column)).map(|text| text.to_string())
                    && !text.is_empty()
                {
                    cells.entry(*row).or_default().insert(*column, text);
                }
            }
        }
    }
    let mut merges = Vec::new();
    if let Some(map) = child_map(&entry, MERGES) {
        for held in keys(&map) {
            merges.push(merge_of(&held)?);
        }
    }
    merges.sort_unstable();
    Ok(TableBody {
        rows,
        columns,
        cells,
        merges,
    })
}

/// Make `tables` hold `target`'s tables: an entry whose frame is gone or
/// holds no table any more is deleted, and each table is written unit by
/// unit ([`sync_table`]).
pub(super) fn sync(tables: &LoroMap, target: &LiveDeck) -> Result<()> {
    for held in keys(tables) {
        if node_id(&held).map_or(true, |id| table_of(target, id).is_none()) {
            tables.delete(&held).map_err(loro)?;
        }
    }
    for id in target.nodes.keys() {
        if let Some(body) = table_of(target, *id) {
            sync_table(&tables.ensure_mergeable_map(&key(*id)).map_err(loro)?, body)?;
        }
    }
    Ok(())
}

/// The table the node `id` holds.
fn table_of(deck: &LiveDeck, id: NodeId) -> Option<&TableBody> {
    match deck.nodes.get(&id)?.payload.as_ref()? {
        NodePayload::Table(table) => Some(table),
        _ => None,
    }
}

/// One table with the fewest writes: its row and column lists placed in
/// order ([`order::sync`]); a deleted row's cells and a deleted column's
/// cells dropped; each cell's text diffed, so another writer's characters
/// in it survive (an emptied cell keeps its text container, emptied); and
/// each merge made or unmade by its own key.
fn sync_table(entry: &LoroMap, body: &TableBody) -> Result<()> {
    let names = |ids: &[NodeId]| -> Vec<String> { ids.iter().map(|id| key(*id)).collect() };
    let (rows, columns) = (names(&body.rows), names(&body.columns));
    order::sync(
        &entry.ensure_mergeable_movable_list(ROWS).map_err(loro)?,
        &rows,
    )?;
    order::sync(
        &entry.ensure_mergeable_movable_list(COLUMNS).map_err(loro)?,
        &columns,
    )?;
    let cells = entry.ensure_mergeable_map(CELLS).map_err(loro)?;
    let row_keys: BTreeSet<&str> = rows.iter().map(String::as_str).collect();
    let column_keys: BTreeSet<&str> = columns.iter().map(String::as_str).collect();
    for held in keys(&cells) {
        if !row_keys.contains(held.as_str()) {
            cells.delete(&held).map_err(loro)?;
        }
    }
    for (row, row_key) in body.rows.iter().zip(&rows) {
        let wanted = body.cells.get(row);
        let line = match child_map(&cells, row_key) {
            Some(line) => line,
            None if wanted.is_some_and(|line| !line.is_empty()) => {
                cells.ensure_mergeable_map(row_key).map_err(loro)?
            }
            None => continue,
        };
        for held in keys(&line) {
            if !column_keys.contains(held.as_str()) {
                line.delete(&held).map_err(loro)?;
            }
        }
        for (column, column_key) in body.columns.iter().zip(&columns) {
            let text = wanted
                .and_then(|line| line.get(column))
                .map_or("", String::as_str);
            let held = match child_text(&line, column_key) {
                Some(held) => held,
                None if !text.is_empty() => line.ensure_mergeable_text(column_key).map_err(loro)?,
                None => continue,
            };
            if held.to_string() != text {
                held.update(text, UpdateOptions::default())
                    .map_err(|_| invalid("deck table cell text update"))?;
            }
        }
    }
    let merges = entry.ensure_mergeable_map(MERGES).map_err(loro)?;
    let wanted: BTreeSet<String> = body.merges.iter().map(merge_key).collect();
    for held in keys(&merges) {
        if !wanted.contains(&held) {
            merges.delete(&held).map_err(loro)?;
        }
    }
    for merge in &wanted {
        if merges.get(merge).is_none() {
            merges.insert(merge, true).map_err(loro)?;
        }
    }
    Ok(())
}

fn key(id: NodeId) -> String {
    id.0.to_string()
}

/// A merge's key: its corners' identities, first row, first column, last
/// row, last column.
fn merge_key(merge: &TableMerge) -> String {
    format!(
        "{}:{}:{}:{}",
        merge.first_row.0, merge.first_column.0, merge.last_row.0, merge.last_column.0
    )
}

fn merge_of(held: &str) -> Result<TableMerge> {
    let corners: Vec<NodeId> = held.split(':').map(node_id).collect::<Result<_>>()?;
    let [first_row, first_column, last_row, last_column] = corners[..] else {
        return Err(invalid("deck table merge"));
    };
    Ok(TableMerge {
        first_row,
        first_column,
        last_row,
        last_column,
    })
}

fn child_text(map: &LoroMap, key: &str) -> Option<LoroText> {
    match map.get(key)? {
        ValueOrContainer::Container(Container::Text(text)) => Some(text),
        _ => None,
    }
}
