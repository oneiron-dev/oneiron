//! A new series' format (OF-510, FIX 3493). A series a chart rewrite adds
//! is formatted after its template, a held series: its shape properties,
//! its marker where the family draws one, and its data labels' settings,
//! as PowerPoint's Edit Data formats a series it adds after the chart's.
//! Its colour is the next in the chart's accent cycle: each theme accent
//! the template names steps on as far as the new idx is from the
//! template's, so a new series is not drawn in its template's colour.
//! Bytes copied from the template carry the namespace bindings they use
//! that an ancestor below the part's root declares (FIX 6402), so a copy
//! stays well-formed in a fresh plot.

use super::{Writer, close, int, piece};
use crate::edit::xml;
use crate::live::held::{self, C};
use crate::live::pptx::ChartKind;
use crate::ooxml::{Node, XmlTree};
use std::collections::BTreeMap;

/// The theme accents a chart's colour style cycles through by series.
const ACCENTS: u8 = 6;

/// A series written new in a `kind` plot: its own `idx` and `order`, `tx`,
/// then `template`'s shape properties, marker (in a family that draws one)
/// and data label settings, its accents stepped on, then the category and
/// value slots and the family's `smooth`. Without a template, the family's
/// defaults.
pub(super) fn fresh(
    bytes: &[u8],
    tree: &XmlTree,
    template: Option<usize>,
    kind: ChartKind,
    writer: &Writer,
    (idx, order): (u32, u32),
    [tx, cat, val]: [&str; 3],
) -> Vec<u8> {
    let mut style = Vec::new();
    if let Some(ser) = template {
        let child = |name: &str| xml::child(tree, ser, C, name);
        if let Some(at) = child("spPr") {
            style.extend(copied(bytes, tree, at));
        }
        if matches!(
            kind,
            ChartKind::Line | ChartKind::Scatter | ChartKind::Radar
        ) && let Some(at) = child("marker")
        {
            style.extend(copied(bytes, tree, at));
        }
        if let Some(at) = child("dLbls") {
            let family = tree.nodes[ser]
                .parent
                .and_then(|plot| held::plot_family(&tree.nodes[plot].name));
            style.extend(labels(bytes, tree, at, family == Some(kind)));
        }
        let from = int(tree, ser, "idx").unwrap_or(idx);
        let step = (i64::from(idx) - i64::from(from)).rem_euclid(i64::from(ACCENTS));
        style = stepped(&style, u8::try_from(step).unwrap_or(0));
    }
    let smooth = if matches!(kind, ChartKind::Line | ChartKind::Scatter) {
        format!(r#"<{} val="0"/>"#, writer.el("smooth"))
    } else {
        String::new()
    };
    let ser = writer.el("ser");
    let mut out = format!(
        r#"<{ser}><{i} val="{idx}"/><{o} val="{order}"/>{tx}"#,
        i = writer.el("idx"),
        o = writer.el("order"),
    )
    .into_bytes();
    out.extend(style);
    out.extend(format!("{cat}{val}{smooth}</{ser}>").into_bytes());
    out
}

/// A held `c:dLbls`'s settings for a new series: without its point labels
/// (`c:dLbl`) and extensions, which name the template's points and cells,
/// and without a label position when the template's family is not the new
/// series' (`same`). Nothing when no setting is left.
fn labels(bytes: &[u8], tree: &XmlTree, at: usize, same: bool) -> Vec<u8> {
    let node = &tree.nodes[at];
    if node.empty {
        return copied(bytes, tree, at);
    }
    let mut inner = Vec::new();
    for &child in &node.children {
        let element = &tree.nodes[child];
        if !(element.is(C, "dLbl")
            || element.is(C, "extLst")
            || (!same && element.is(C, "dLblPos")))
        {
            inner.extend_from_slice(piece(bytes, tree, child));
        }
    }
    if inner.is_empty() {
        return Vec::new();
    }
    let mut out = declared(
        &xml::open_tag(bytes, node),
        node,
        &bindings(bytes, tree, at),
    );
    out.extend(inner);
    out.extend(close(node));
    out
}

/// The namespace bindings in scope at `at` that an ancestor below the
/// part's root declares, the element itself does not, and its bytes use,
/// as attributes to declare on a copy of it: the nearest ancestor's where
/// two declare one prefix. The root's are in scope wherever the copy goes
/// in this part.
fn bindings(bytes: &[u8], tree: &XmlTree, at: usize) -> String {
    let node = &tree.nodes[at];
    let own = &bytes[node.span.clone()];
    let uses = |prefix: &str| {
        let wanted = format!("{prefix}:");
        own.windows(wanted.len() + 1).any(|window| {
            matches!(
                window[0],
                b'<' | b'/' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\''
            ) && window[1..] == *wanted.as_bytes()
        })
    };
    let mut found: BTreeMap<&str, &str> = BTreeMap::new();
    let mut up = node.parent;
    while let Some(parent) = up.filter(|&parent| parent != 0) {
        for (name, value) in &tree.nodes[parent].attrs {
            let prefix = match name.strip_prefix("xmlns:") {
                Some(prefix) => Some(prefix),
                None if name == "xmlns" => None,
                None => continue,
            };
            if node.attrs.contains_key(name) || prefix.is_some_and(|prefix| !uses(prefix)) {
                continue;
            }
            found.entry(name.as_str()).or_insert(value.as_str());
        }
        up = tree.nodes[parent].parent;
    }
    found
        .into_iter()
        .map(|(name, value)| format!(r#" {name}="{}""#, xml::escape_attribute(value)))
        .collect()
}

/// `bytes`, an element or its open tag, with `declarations` after its name.
fn declared(bytes: &[u8], node: &Node, declarations: &str) -> Vec<u8> {
    let at = (1 + node.qualified.len()).min(bytes.len());
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(declarations.as_bytes());
    out.extend_from_slice(&bytes[at..]);
    out
}

/// A template element's bytes as a copy writes them elsewhere: with the
/// bindings it needs from its ancestors ([`bindings`]).
fn copied(bytes: &[u8], tree: &XmlTree, at: usize) -> Vec<u8> {
    declared(
        piece(bytes, tree, at),
        &tree.nodes[at],
        &bindings(bytes, tree, at),
    )
}

/// `bytes` with each theme accent (`"accent1"` to `"accent6"`) stepped
/// `step` places round the cycle.
fn stepped(bytes: &[u8], step: u8) -> Vec<u8> {
    const ACCENT: &[u8] = b"\"accent";
    if step == 0 {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if let Some(rest) = bytes[at..].strip_prefix(ACCENT)
            && let [digit @ b'1'..=b'6', b'"', ..] = rest
        {
            out.extend_from_slice(ACCENT);
            out.push(b'1' + (*digit - b'1' + step) % ACCENTS);
            out.push(b'"');
            at += ACCENT.len() + 2;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    out
}
