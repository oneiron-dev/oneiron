//! A series cache written in place (FIX 7987): only the points whose
//! values the write changes, and the count when it changes, are spliced in
//! the retained bytes. The cache's own attributes and namespace bindings,
//! its format code, extensions and unknown children, and each kept point's
//! attributes keep their bytes.

use super::super::workbook::number;
use super::{C, Model, points};
use crate::design_plan::Cell;
use crate::edit::xml::{self, Splice};
use crate::ooxml::escape_text;
use std::collections::BTreeMap;

/// A point's text as a cache holds it; `None` for a missing point.
fn text(cell: &Cell) -> Option<String> {
    match cell {
        Cell::Missing => None,
        Cell::Number(value) => Some(number(*value)),
        Cell::Text(text) | Cell::Date(text) => Some(escape_text(text)),
    }
}

/// The splices that make the cache element at `cache`, holding `old`,
/// hold `new`: a changed point's value written into its own `c:v`, a point
/// gone removed, a new one inserted in index order, the count set when it
/// changes. A self-closed cache opens to hold its points.
pub(super) fn patched(model: &Model, cache: usize, old: &[Cell], new: &[Cell]) -> Vec<Splice> {
    let (tree, bytes) = (&model.tree, model.bytes.as_slice());
    let node = &tree.nodes[cache];
    let p = node
        .qualified
        .rsplit_once(':')
        .map_or(String::new(), |(prefix, _)| format!("{prefix}:"));
    if node.empty {
        let mut out = xml::open_tag(bytes, node);
        out.extend(points(&p, new).into_bytes());
        out.extend(format!("</{}>", node.qualified).into_bytes());
        return vec![(node.span.clone(), out)];
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
            Some(v) if !v.empty => edits.push((v.content.clone(), value.into_bytes())),
            Some(v) => edits.push((
                v.span.clone(),
                format!("<{q}>{value}</{q}>", q = v.qualified).into_bytes(),
            )),
            None if point.empty => {
                let mut out = xml::open_tag(bytes, point);
                out.extend(format!("<{p}v>{value}</{p}v></{}>", point.qualified).into_bytes());
                edits.push((point.span.clone(), out));
            }
            None => edits.push((
                point.open_end..point.open_end,
                format!("<{p}v>{value}</{p}v>").into_bytes(),
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
            r#"<{p}pt idx="{idx}"><{p}v>{value}</{p}v></{p}pt>"#
        ));
    }
    edits.extend(
        inserted
            .into_iter()
            .map(|(at, xml)| (at..at, xml.into_bytes())),
    );
    edits
}
