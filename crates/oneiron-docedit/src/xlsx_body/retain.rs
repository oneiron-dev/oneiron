//! Writing into a stored cell or defined name (FIX 8571, FIX 8572): only
//! what a change names is written, and every other attribute, child and
//! byte of the element stays, rather than the element being written again
//! from what the body models.
use super::{Result, SML, XlsxChange, XlsxValue, drop_attribute, encode_escapes, refused, truthy};
use crate::edit::xml::{Splice, insert_end, replace_text, set_attribute};
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::xlfn::{storage_form, ui_form};

/// A cell's children its content is written as: formula, value, inline
/// string.
const CONTENT: &[&str] = &["f", "v", "is"];
/// A cell's attributes a content write sets: its reference, its format, its
/// value's type and its rich value's metadata.
const MANAGED: &[&str] = &["r", "s", "t", "vm"];

fn content(node: &Node) -> bool {
    node.namespace == SML && CONTENT.contains(&node.name.as_str())
}

/// The splices that write `change` into the stored cell `cell` (its index
/// in `tree`): its format, its value's type and its content (formula `f`,
/// value `v`, inline string `is`), as a new cell is written. The content
/// element of the kind it writes keeps its own attributes (a shared
/// member's group ones go), and the reference's spelling, every other
/// attribute and child (an extension list, a phonetic flag) and the bytes
/// between them stay. The rich value metadata (`vm`) describes the old
/// value and goes with it. A blank cell with no format and nothing else
/// kept goes.
pub(super) fn patch_cell(
    bytes: &[u8],
    tree: &XmlTree,
    cell: usize,
    change: &XlsxChange,
) -> Result<Vec<Splice>> {
    let XlsxChange::Cell {
        value,
        formula,
        style,
        ..
    } = change
    else {
        return Err(refused("not a cell change"));
    };
    let node = &tree.nodes[cell];
    // The content element, its text and the value's type.
    let (kind, text, kind_type) = match (formula, value) {
        (Some(formula), _) => (Some("f"), storage_form(formula), None),
        (None, XlsxValue::Blank) => (None, String::new(), None),
        (None, XlsxValue::Number(number)) => (Some("v"), number.to_string(), None),
        (None, XlsxValue::Text(text)) => (Some("is"), encode_escapes(text), Some("inlineStr")),
        (None, XlsxValue::Bool(flag)) => (Some("v"), u8::from(*flag).to_string(), Some("b")),
        (None, XlsxValue::Error(error)) => (Some("v"), error.clone(), Some("e")),
    };
    let held: Vec<&Node> = tree
        .children(cell)
        .map(|(_, child)| child)
        .filter(|child| content(child))
        .collect();
    let keeps = tree.children(cell).any(|(_, child)| !content(child))
        || node
            .attrs
            .keys()
            .any(|name| !MANAGED.contains(&name.as_str()));
    if kind.is_none() && style.is_none() && !keeps {
        return Ok(vec![(node.span.clone(), Vec::new())]);
    }
    let attribute = |name: &str, value: Option<&str>| match value {
        Some(value) if node.attr(name) == Some(value) => None,
        Some(value) => Some(set_attribute(bytes, node, name, value)),
        None => drop_attribute(bytes, node, name),
    };
    let style = style.map(|style| style.to_string());
    let mut edits: Vec<Splice> = [
        attribute("s", style.as_deref()),
        attribute("t", kind_type),
        attribute("vm", None),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut placed = false;
    for child in &held {
        if placed || Some(child.name.as_str()) != kind {
            edits.push((child.span.clone(), Vec::new()));
            continue;
        }
        placed = true;
        if child.name == "is" {
            edits.push((child.span.clone(), inline_string(node, &text)));
            continue;
        }
        if child.attr("t") == Some("shared") {
            for attr in ["t", "si", "ref"] {
                edits.extend(drop_attribute(bytes, child, attr));
            }
        }
        edits.extend(
            replace_text(bytes, child, &text)
                .ok_or(refused("a worksheet cell could not be rewritten"))?,
        );
    }
    if let (Some(kind), false) = (kind, placed) {
        let element = if kind == "is" {
            inline_string(node, &text)
        } else {
            let name = node.child_name(kind);
            format!("<{name}>{}</{name}>", escape_text(&text)).into_bytes()
        };
        // In the place of the content it replaces, else before the cell's
        // other children, else at its end.
        let point = held.first().map(|child| child.span.start).or_else(|| {
            tree.children(cell)
                .next()
                .map(|(_, child)| child.span.start)
        });
        edits.push(match point {
            Some(at) => (at..at, element),
            None => insert_end(bytes, node, &element),
        });
    }
    Ok(edits)
}

/// An inline string element for `cell`, its text already `_xHHHH_`
/// escaped.
fn inline_string(cell: &Node, text: &str) -> Vec<u8> {
    let (item, run) = (cell.child_name("is"), cell.child_name("t"));
    format!(
        "<{item}><{run} xml:space=\"preserve\">{}</{run}></{item}>",
        escape_text(text)
    )
    .into_bytes()
}

/// A defined name as a change writes it.
pub(super) struct NameWrite<'a> {
    pub(super) name: &'a str,
    pub(super) formula: &'a str,
    pub(super) hidden: bool,
}

impl NameWrite<'_> {
    /// A new `definedName` element called `element`, local to the sheet at
    /// `local`.
    pub(super) fn xml(&self, element: &str, local: Option<usize>) -> String {
        let local = local.map_or_else(String::new, |at| format!(" localSheetId=\"{at}\""));
        let hidden = if self.hidden { " hidden=\"1\"" } else { "" };
        format!(
            "<{element} name=\"{}\"{local}{hidden}>{}</{element}>",
            escape_text(self.name),
            escape_text(&storage_form(self.formula)),
        )
    }
}

/// The splices that write `write` into the stored `definedName` `node`: its
/// name's spelling, its hidden flag and its formula's text, each where it
/// differs. Its other attributes (a comment, a description, a scope the
/// write keeps) and markup stay.
pub(super) fn name_patch(bytes: &[u8], node: &Node, write: &NameWrite<'_>) -> Result<Vec<Splice>> {
    let mut edits = Vec::new();
    if node.attr("name") != Some(write.name) {
        edits.push(set_attribute(bytes, node, "name", write.name));
    }
    let hidden = node.attr("hidden").is_some_and(truthy);
    if write.hidden && !hidden {
        edits.push(set_attribute(bytes, node, "hidden", "1"));
    } else if !write.hidden && hidden {
        edits.extend(drop_attribute(bytes, node, "hidden"));
    }
    if ui_form(&node.text) != write.formula {
        edits.extend(
            replace_text(bytes, node, &storage_form(write.formula))
                .ok_or(refused("the workbook part could not be rewritten"))?,
        );
    }
    Ok(edits)
}
