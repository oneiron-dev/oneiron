//! Paragraph text as the generic deck mapping or the native cell reader counts it.
use super::xml::A;
use super::{BREAK, Item, Kind, Paragraph, run_text};
use crate::ooxml::XmlTree;

pub(in crate::edit) fn paragraphs(tree: &XmlTree, body: usize) -> Vec<Paragraph> {
    parse(tree, body, false)
}

pub(super) fn cell_paragraphs(tree: &XmlTree, body: usize) -> Vec<Paragraph> {
    parse(tree, body, true)
}

/// The paragraphs of a text body, with their text as the mapping counts it.
fn parse(tree: &XmlTree, body: usize, cell: bool) -> Vec<Paragraph> {
    tree.nodes[body]
        .children
        .iter()
        .copied()
        .filter(|&at| tree.nodes[at].is(A, "p"))
        .map(|at| {
            let mut paragraph = Paragraph {
                node: at,
                items: Vec::new(),
                text: Vec::new(),
                opaque: false,
            };
            for &child in &tree.nodes[at].children {
                let node = &tree.nodes[child];
                let (kind, text) = match (node.namespace.as_str(), node.name.as_str()) {
                    (A, "r") => (Kind::Run, run_text(tree, child)),
                    (A, "fld") => (Kind::Field, run_text(tree, child)),
                    (A, "br") => (Kind::Break, BREAK.to_string()),
                    (A, "pPr" | "endParaRPr") => continue,
                    _ if cell => {
                        let text: String = tree
                            .nodes
                            .iter()
                            .skip(child + 1)
                            .take_while(|descendant| descendant.span.start < node.span.end)
                            .filter(|descendant| descendant.is(A, "t"))
                            .map(|descendant| descendant.text.as_str())
                            .collect();
                        if text.is_empty() {
                            continue;
                        }
                        (Kind::Opaque, text)
                    }
                    _ => {
                        if holds_text(tree, child) {
                            paragraph.opaque = true;
                        }
                        continue;
                    }
                };
                let start = paragraph.text.len();
                paragraph.text.extend(text.chars());
                paragraph.items.push(Item {
                    node: child,
                    kind,
                    start,
                    end: paragraph.text.len(),
                });
            }
            paragraph
        })
        .collect()
}

/// Whether the element's subtree holds an `a:t` with text (FIX 10385): an
/// unknown paragraph child holding none passes through the mapping
/// unchanged, as alternate content and math do.
fn holds_text(tree: &XmlTree, at: usize) -> bool {
    tree.nodes[at].children.iter().any(|&child| {
        let node = &tree.nodes[child];
        (node.is(A, "t") && !node.text.is_empty()) || holds_text(tree, child)
    })
}
