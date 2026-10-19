//! The new XML the text mapping writes: a run with new text, a run of the
//! paragraph's end properties, and new paragraphs shaped like their
//! neighbour or bare. A line break (U+000B) in new text is written as an
//! `a:br` carrying the properties of the run it lands in.

use super::{BREAK, Kind, Paragraph, bare_runs};
use crate::edit::EditRefusal;
use crate::edit::xml::{self, A, Splice};
use crate::ooxml::{XmlTree, escape_text};

/// A run's bytes with its `a:t` text replaced.
pub(super) fn run_bytes(
    bytes: &[u8],
    tree: &XmlTree,
    run: usize,
    text: &str,
) -> Result<Vec<u8>, EditRefusal> {
    let node = &tree.nodes[run];
    let t = xml::child(tree, run, A, "t").ok_or(EditRefusal::TextMapping("a run without text"))?;
    let t_node = &tree.nodes[t];
    let escaped = escape_text(text);
    let mut out = bytes[node.span.start..t_node.span.start].to_vec();
    if t_node.empty {
        out.extend(xml::open_tag(bytes, t_node));
        out.extend(format!("{escaped}</{}>", t_node.qualified).into_bytes());
    } else {
        out.extend_from_slice(&bytes[t_node.span.start..t_node.content.start]);
        out.extend(escaped.into_bytes());
        out.extend_from_slice(&bytes[t_node.content.end..t_node.span.end]);
    }
    out.extend_from_slice(&bytes[t_node.span.end..node.span.end]);
    Ok(out)
}

/// A run's bytes with `text` as its text, each U+000B in it an `a:br`
/// carrying the run's own `a:rPr`: the text between breaks goes into copies
/// of the run, and an empty piece writes no run.
pub(super) fn broken_run(
    bytes: &[u8],
    tree: &XmlTree,
    run: usize,
    text: &str,
) -> Result<Vec<u8>, EditRefusal> {
    if !text.contains(BREAK) {
        return run_bytes(bytes, tree, run, text);
    }
    let properties = xml::child(tree, run, A, "rPr").map_or_else(String::new, |r_pr| {
        String::from_utf8_lossy(&bytes[tree.nodes[r_pr].span.clone()]).into_owned()
    });
    let line_break = soft_break(xml::prefix(&tree.nodes[run]), &properties);
    let mut out = Vec::new();
    for (at, piece) in text.split(BREAK).enumerate() {
        if at > 0 {
            out.extend_from_slice(line_break.as_bytes());
        }
        if !piece.is_empty() {
            out.extend(run_bytes(bytes, tree, run, piece)?);
        }
    }
    Ok(out)
}

/// An `a:br` carrying `properties`, an `a:rPr` element or nothing.
fn soft_break(prefix: &str, properties: &str) -> String {
    let br = xml::qualify(prefix, "br");
    if properties.is_empty() {
        format!("<{br}/>")
    } else {
        format!("<{br}>{properties}</{br}>")
    }
}

/// `text` written between its line breaks: each U+000B as `line_break`,
/// each nonempty piece as `run` makes it.
fn broken(text: &str, line_break: &str, run: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    for (at, piece) in text.split(BREAK).enumerate() {
        if at > 0 {
            out.push_str(line_break);
        }
        if !piece.is_empty() {
            out.push_str(&run(piece));
        }
    }
    out
}

/// A new run carrying the paragraph's end properties as its own.
pub(super) fn new_run(bytes: &[u8], tree: &XmlTree, paragraph: &Paragraph, text: &str) -> String {
    let node = &tree.nodes[paragraph.node];
    let prefix = xml::prefix(node);
    let properties = xml::child(tree, paragraph.node, A, "endParaRPr")
        .map_or_else(String::new, |end| {
            renamed(bytes, &tree.nodes[end], &xml::qualify(prefix, "rPr"))
        });
    let (r, t) = (xml::qualify(prefix, "r"), xml::qualify(prefix, "t"));
    broken(text, &soft_break(prefix, &properties), |piece| {
        format!("<{r}>{properties}<{t}>{}</{t}></{r}>", escape_text(piece))
    })
}

/// An element's bytes under another qualified name (`a:endParaRPr` as
/// `a:rPr`: both are `CT_TextCharacterProperties`).
fn renamed(bytes: &[u8], node: &crate::ooxml::Node, name: &str) -> String {
    let text = String::from_utf8_lossy(&bytes[node.span.clone()]).into_owned();
    let open = format!("<{}", node.qualified);
    let close = format!("</{}>", node.qualified);
    let mut out = text.replacen(&open, &format!("<{name}"), 1);
    if out.ends_with(&close) {
        out.truncate(out.len() - close.len());
        out.push_str(&format!("</{name}>"));
    }
    out
}

/// New paragraphs at index `at`, shaped like the paragraph before them.
pub(super) fn insert_paragraphs(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    old: &[Paragraph],
    at: usize,
    added: &[&[char]],
) -> Result<Splice, EditRefusal> {
    let template = at
        .checked_sub(1)
        .or((!old.is_empty()).then_some(0))
        .map(|i| &old[i]);
    let mut out = String::new();
    for text in added {
        let text: String = text.iter().collect();
        out.push_str(&match template {
            Some(template) => paragraph_like(bytes, tree, template, &text),
            None => {
                let prefix = xml::child(tree, body, A, "bodyPr")
                    .map(|at| xml::prefix(&tree.nodes[at]).to_owned())
                    .ok_or(EditRefusal::Missing("text body properties"))?;
                bare_paragraph(&prefix, &text)
            }
        });
    }
    let position = match at.checked_sub(1) {
        Some(before) => tree.nodes[old[before].node].span.end,
        None => match old.first() {
            Some(first) => tree.nodes[first.node].span.start,
            None => return Ok(xml::insert_last(bytes, &tree.nodes[body], &out)),
        },
    };
    Ok((position..position, out.into_bytes()))
}

fn paragraph_like(bytes: &[u8], tree: &XmlTree, template: &Paragraph, text: &str) -> String {
    let node = &tree.nodes[template.node];
    let prefix = xml::prefix(node);
    let element = |name| {
        xml::child(tree, template.node, A, name).map_or_else(String::new, |at| {
            String::from_utf8_lossy(&bytes[tree.nodes[at].span.clone()]).into_owned()
        })
    };
    let run_properties = template
        .items
        .iter()
        .find(|item| item.kind == Kind::Run)
        .and_then(|item| xml::child(tree, item.node, A, "rPr"))
        .map(|at| String::from_utf8_lossy(&bytes[tree.nodes[at].span.clone()]).into_owned())
        .or_else(|| {
            xml::child(tree, template.node, A, "endParaRPr")
                .map(|at| renamed(bytes, &tree.nodes[at], &xml::qualify(prefix, "rPr")))
        })
        .unwrap_or_default();
    let (r, t) = (xml::qualify(prefix, "r"), xml::qualify(prefix, "t"));
    let run = broken(text, &soft_break(prefix, &run_properties), |piece| {
        format!(
            "<{r}>{run_properties}<{t}>{}</{t}></{r}>",
            escape_text(piece)
        )
    });
    format!(
        "<{p}>{}{run}{}</{p}>",
        element("pPr"),
        element("endParaRPr"),
        p = xml::qualify(prefix, "p"),
    )
}

fn bare_paragraph(prefix: &str, text: &str) -> String {
    let p = xml::qualify(prefix, "p");
    let runs = broken(text, &soft_break(prefix, ""), |piece| {
        bare_runs(prefix, piece)
    });
    format!("<{p}>{runs}</{p}>")
}
