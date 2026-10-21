//! A worksheet's cells written in place (FIX 7987): a written cell keeps
//! its own attributes and children (its extension list, its format), only
//! its value and value type replaced; a new cell goes in column order in
//! its row, a new row in row order; a row's other children and every byte
//! the write does not name keep their bytes. Empty elements open through
//! the shared [`xml::insert_end`].

use super::super::NativeRefusal;
use super::{CellKey, SML, Stored, cell_ref, cell_xml, number};
use crate::design_plan::Cell;
use crate::edit::xml::{self, Splice};
use crate::ooxml::{XmlTree, escape_text};
use std::collections::BTreeMap;

/// The value children a written cell takes, `prefix` its own.
fn value_xml(prefix: &str, value: &Cell) -> Result<String, NativeRefusal> {
    Ok(match value {
        Cell::Missing => String::new(),
        Cell::Number(n) if n.is_finite() => format!("<{prefix}v>{}</{prefix}v>", number(*n)),
        Cell::Number(_) => return Err(NativeRefusal::Invalid("a number must be finite")),
        // Only a created workbook takes a date; a written one keeps text.
        Cell::Text(text) | Cell::Date(text) => format!(
            "<{prefix}is><{prefix}t xml:space=\"preserve\">{}</{prefix}t></{prefix}is>",
            escape_text(text)
        ),
    })
}

/// The splices that write `value` into the stored cell `cell`: its value
/// children (`v`, `is`) replaced, its `t` set to the value's type, every
/// other attribute and child kept. A self-closed cell opens to hold its
/// value ([`xml::insert_end`]).
fn patched_cell(
    bytes: &[u8],
    tree: &XmlTree,
    cell: usize,
    value: &Cell,
) -> Result<Vec<Splice>, NativeRefusal> {
    let node = &tree.nodes[cell];
    let prefix = node.qualified.strip_suffix('c').unwrap_or("");
    let inner = value_xml(prefix, value)?;
    let mut edits = Vec::new();
    match (node.attr_spans.get("t"), value) {
        (_, Cell::Text(_) | Cell::Date(_)) => {
            edits.push(xml::set_attribute(bytes, node, "t", "inlineStr"));
        }
        (Some(t), _) => edits.push((t.clone(), Vec::new())),
        (None, _) => {}
    }
    let mut extension = None;
    for (at, child) in tree.children(cell) {
        if child.namespace != SML {
            continue;
        }
        match child.name.as_str() {
            "v" | "is" => edits.push((child.span.clone(), Vec::new())),
            "extLst" => extension = extension.or(Some(at)),
            _ => {}
        }
    }
    if !inner.is_empty() {
        // CT_Cell: f?, v?, is?, extLst?.
        edits.push(match extension {
            Some(at) => {
                let at = tree.nodes[at].span.start;
                (at..at, inner.into_bytes())
            }
            None => xml::insert_end(bytes, node, inner.as_bytes()),
        });
    }
    Ok(edits)
}

/// A worksheet `bytes` with each written cell in place: a stored cell
/// patched ([`patched_cell`]), a new one in column order in its row, a new
/// row in row order; a new cell takes no format unless its stored one had
/// one (`styles`).
pub(super) fn rewrite(
    bytes: &[u8],
    tree: &XmlTree,
    writes: &[&(CellKey, Cell)],
    styles: &BTreeMap<(u32, u32), Stored>,
) -> Result<Vec<u8>, NativeRefusal> {
    let (data, data_node) =
        tree.child(0, SML, "sheetData")?
            .ok_or(NativeRefusal::AmbiguousChartData(
                "worksheet has no sheetData",
            ))?;
    let mut touched: BTreeMap<u32, BTreeMap<u32, &Cell>> = BTreeMap::new();
    for (key, value) in writes {
        touched.entry(key.row).or_default().insert(key.col, value);
    }
    let mut edits: Vec<Splice> = Vec::new();
    let mut inserted: BTreeMap<usize, String> = BTreeMap::new();
    let mut rows: BTreeMap<u32, usize> = BTreeMap::new();
    for (index, row) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
        let number = row.attr("r").and_then(|r| r.parse::<u32>().ok()).ok_or(
            NativeRefusal::AmbiguousChartData("a worksheet row has no number"),
        )?;
        rows.insert(number, index);
    }
    let new_cell = |name: &str, col: u32, row: u32, value: &Cell| {
        let key = CellKey {
            sheet: String::new(),
            col,
            row,
        };
        let style = styles.get(&(col, row)).and_then(|s| s.style.as_deref());
        cell_xml(name, &key, style, value)
    };
    for (number, cells) in &touched {
        let Some(&row) = rows.get(number) else {
            continue;
        };
        let row_node = &tree.nodes[row];
        let mut stored: BTreeMap<u32, usize> = BTreeMap::new();
        for (at, cell) in tree.children(row).filter(|(_, node)| node.is(SML, "c")) {
            let col =
                cell.attr("r")
                    .and_then(cell_ref)
                    .ok_or(NativeRefusal::AmbiguousChartData(
                        "a worksheet cell has no reference",
                    ))?;
            stored.insert(col.0, at);
        }
        let cell_name = row_node.child_name("c");
        let mut fresh = String::new();
        for (&col, value) in cells {
            match stored.get(&col) {
                Some(&cell) => edits.extend(patched_cell(bytes, tree, cell, *value)?),
                None => {
                    let xml = new_cell(&cell_name, col, *number, *value)?;
                    match stored.range(col..).next() {
                        Some((_, &next)) => inserted
                            .entry(tree.nodes[next].span.start)
                            .or_default()
                            .push_str(&xml),
                        None => fresh.push_str(&xml),
                    }
                }
            }
        }
        if fresh.is_empty() {
            continue;
        }
        // CT_Row: c*, extLst?: cells past the last go after it.
        match stored.values().next_back() {
            Some(&last) => inserted
                .entry(tree.nodes[last].span.end)
                .or_default()
                .push_str(&fresh),
            None if row_node.empty => {
                edits.push(xml::insert_end(bytes, row_node, fresh.as_bytes()));
            }
            None => inserted
                .entry(row_node.open_end)
                .or_default()
                .push_str(&fresh),
        }
    }
    let row_name = data_node.child_name("row");
    let cell_name = data_node.child_name("c");
    let mut tail = String::new();
    for (number, cells) in &touched {
        if rows.contains_key(number) {
            continue;
        }
        let mut out = format!("<{row_name} r=\"{number}\">");
        for (&col, value) in cells {
            out.push_str(&new_cell(&cell_name, col, *number, *value)?);
        }
        out.push_str(&format!("</{row_name}>"));
        match rows.range(*number..).next() {
            Some((_, &next)) => inserted
                .entry(tree.nodes[next].span.start)
                .or_default()
                .push_str(&out),
            None => tail.push_str(&out),
        }
    }
    if !tail.is_empty() {
        if data_node.empty {
            edits.push(xml::insert_end(bytes, data_node, tail.as_bytes()));
        } else {
            inserted
                .entry(data_node.content.end)
                .or_default()
                .push_str(&tail);
        }
    }
    edits.extend(
        inserted
            .into_iter()
            .map(|(at, xml)| (at..at, xml.into_bytes())),
    );
    xml::splice(bytes, edits).map_err(|_| NativeRefusal::Invalid("overlapping cell writes"))
}
