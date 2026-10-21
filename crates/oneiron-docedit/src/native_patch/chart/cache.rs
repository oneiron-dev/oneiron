//! A series cache written in place (FIX 7987): only the points whose
//! values the write changes, and the count when it changes, are spliced in
//! the retained bytes, through the shared splice helpers
//! ([`xml::replace_text`], [`xml::insert_end`]). The cache's own attributes
//! and namespace bindings, its format code, extensions and unknown
//! children, and each kept point's attributes keep their bytes.

use super::super::NativeRefusal;
use super::super::workbook::number;
use super::{C, Model, points};
use crate::design_plan::Cell;
use crate::edit::xml::{self, Splice};
use crate::ooxml::escape_text;
use std::collections::BTreeMap;

/// A point's text as a cache holds it, unescaped; `None` for a missing
/// point.
fn text(cell: &Cell) -> Option<String> {
    match cell {
        Cell::Missing => None,
        Cell::Number(value) => Some(number(*value)),
        Cell::Text(text) | Cell::Date(text) => Some(text.clone()),
    }
}

/// The splices that make the cache element at `cache`, holding `old`,
/// hold `new`: a changed point's value written into its own `c:v`, a point
/// gone removed, a new one inserted in index order, the count set when it
/// changes. A self-closed cache opens to hold its points. A point whose
/// text does not read as XML refuses.
pub(super) fn patched(
    model: &Model,
    cache: usize,
    old: &[Cell],
    new: &[Cell],
) -> Result<Vec<Splice>, NativeRefusal> {
    let (tree, bytes) = (&model.tree, model.bytes.as_slice());
    let node = &tree.nodes[cache];
    let p = node
        .qualified
        .rsplit_once(':')
        .map_or(String::new(), |(prefix, _)| format!("{prefix}:"));
    if node.empty {
        return Ok(vec![xml::insert_end(
            bytes,
            node,
            points(&p, new).as_bytes(),
        )]);
    }
    let child = |name: &str| {
        tree.children(cache)
            .find(|(_, child)| child.is(C, name))
            .map(|(at, _)| at)
    };
    let mut edits = Vec::new();
    let mut inserted: BTreeMap<usize, String> = BTreeMap::new();
    let after_count = match child("ptCount") {
        Some(at) => {
            if old.len() != new.len() {
                edits.push(xml::set_attribute(
                    bytes,
                    &tree.nodes[at],
                    "val",
                    &new.len().to_string(),
                ));
            }
            tree.nodes[at].span.end
        }
        None => {
            let at = child("formatCode").map_or(node.open_end, |at| tree.nodes[at].span.end);
            inserted
                .entry(at)
                .or_default()
                .push_str(&format!(r#"<{p}ptCount val="{}"/>"#, new.len()));
            at
        }
    };
    let held: BTreeMap<usize, usize> = tree
        .children(cache)
        .filter(|(_, child)| child.is(C, "pt"))
        .filter_map(|(at, pt)| Some((pt.attr("idx")?.trim().parse().ok()?, at)))
        .collect();
    for (&idx, &pt) in &held {
        let point = &tree.nodes[pt];
        let Some(value) = new.get(idx).and_then(text) else {
            edits.push((point.span.clone(), Vec::new()));
            continue;
        };
        if old.get(idx) == new.get(idx) {
            continue;
        }
        let v = tree
            .children(pt)
            .find(|(_, child)| child.is(C, "v"))
            .map(|(at, _)| &tree.nodes[at]);
        match v {
            Some(v) => edits.extend(xml::replace_text(bytes, v, &value).ok_or(
                NativeRefusal::AmbiguousChartData("an unreadable cache point"),
            )?),
            None => edits.push(xml::insert_end(
                bytes,
                point,
                format!("<{p}v>{}</{p}v>", escape_text(&value)).as_bytes(),
            )),
        }
    }
    for (idx, cell) in new.iter().enumerate() {
        if held.contains_key(&idx) {
            continue;
        }
        let Some(value) = text(cell) else {
            continue;
        };
        let at = match held.range(idx..).next() {
            Some((_, &next)) => tree.nodes[next].span.start,
            None => held
                .values()
                .next_back()
                .map_or(after_count, |&last| tree.nodes[last].span.end),
        };
        inserted.entry(at).or_default().push_str(&format!(
            r#"<{p}pt idx="{idx}"><{p}v>{}</{p}v></{p}pt>"#,
            escape_text(&value)
        ));
    }
    edits.extend(
        inserted
            .into_iter()
            .map(|(at, xml)| (at..at, xml.into_bytes())),
    );
    Ok(edits)
}
