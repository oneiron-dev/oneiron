//! `set_text`, `replace_run_text` and `set_run_props`.
//!
//! The declared mapping for a whole-body write: paragraphs are aligned by
//! their common head and tail, and the changed ones in between are paired in
//! order. A paired paragraph keeps its `a:pPr`, `a:endParaRPr` and every
//! run, field and break outside the changed span (the common prefix and
//! suffix of its text). Inside the span, whole runs, fields and breaks are
//! removed and partly covered runs are trimmed; the new text goes into the
//! first run it replaces, else the run it touches before, else the run it
//! touches after, else a new run with the paragraph's end properties. So a
//! word replaced in a linked or bold run stays linked or bold, and nothing
//! outside the change is rewritten. A field's text is computed: a change
//! that cuts into one or writes text in its place is refused (deleting it
//! whole is allowed), as is new text holding a line break. Extra paragraphs
//! copy the `a:pPr`, first run properties and `a:endParaRPr` of the
//! paragraph before them; surplus ones are removed.
use super::check::Declared;
use super::xml::{self, A, P, Splice};
use super::{EditRefusal, FitUnverified, RunProps, Written};
use crate::deck::{ShapeView, SlideView, TargetRole, TextRange};
use crate::ooxml::{XmlTree, escape_text};
use crate::retained_opc::Package;

/// U+000B: an `a:br` in paragraph text, as PowerPoint writes it.
pub(super) const BREAK: char = '\u{b}';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Run,
    Field,
    Break,
}

#[derive(Debug, Clone, Copy)]
struct Item {
    node: usize,
    kind: Kind,
    /// Character offsets in the paragraph text.
    start: usize,
    end: usize,
}

#[derive(Debug, Clone)]
pub(super) struct Paragraph {
    node: usize,
    items: Vec<Item>,
    pub(super) text: Vec<char>,
    /// A child the mapping does not know (not `pPr`, `r`, `br`, `fld` or
    /// `endParaRPr`): such a paragraph is never rewritten.
    opaque: bool,
}

/// The paragraphs of a text body, with their text as the mapping counts it.
pub(super) fn paragraphs(tree: &XmlTree, body: usize) -> Vec<Paragraph> {
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
                    _ => {
                        paragraph.opaque = true;
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

fn run_text(tree: &XmlTree, run: usize) -> String {
    xml::child(tree, run, A, "t").map_or_else(String::new, |t| tree.nodes[t].text.clone())
}

/// The requested body as paragraphs of characters.
pub(super) fn split(text: &str) -> Result<Vec<Vec<char>>, EditRefusal> {
    if text.contains('\r') || !xml::writable(&text.replace(BREAK, "")) {
        return Err(EditRefusal::Invalid(
            "text holds a character XML cannot carry",
        ));
    }
    Ok(text.split('\n').map(|p| p.chars().collect()).collect())
}

pub(super) fn set_text(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    text: &str,
) -> Result<Written, EditRefusal> {
    let id = shape.id.ok_or(EditRefusal::Missing("shape id"))?;
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let body = xml::child(&tree, shape.node.index, P, "txBody")
        .ok_or(EditRefusal::Missing("text body"))?;
    let new = split(text)?;
    let (edits, structure) = rewrite_body(&bytes, &tree, body, &new)?;
    let old = paragraphs(&tree, body);
    let lengths = structure.is_some()
        || old
            .iter()
            .zip(&new)
            .any(|(old, new)| old.text.len() != new.len());
    check_animation(slide, &tree, id, structure, lengths)?;
    finish(next, slide, id, &bytes, edits)
}

pub(super) fn replace_run_text(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    (paragraph, run): (usize, usize),
    expected: &str,
    text: &str,
) -> Result<Written, EditRefusal> {
    let id = shape.id.ok_or(EditRefusal::Missing("shape id"))?;
    if text.contains(['\n', '\r', BREAK]) || !xml::writable(text) {
        return Err(EditRefusal::Invalid(
            "run text holds a break or a character XML cannot carry",
        ));
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let body = xml::child(&tree, shape.node.index, P, "txBody")
        .ok_or(EditRefusal::Missing("text body"))?;
    let paragraphs = paragraphs(&tree, body);
    let item = paragraphs
        .get(paragraph)
        .ok_or(EditRefusal::Missing("paragraph"))?
        .items
        .iter()
        .filter(|item| item.kind != Kind::Break)
        .nth(run)
        .copied()
        .ok_or(EditRefusal::Missing("run"))?;
    if item.kind == Kind::Field {
        return Err(EditRefusal::TextMapping("a field's text is computed"));
    }
    if run_text(&tree, item.node) != expected {
        return Err(EditRefusal::TargetChanged);
    }
    let lengths = text.chars().count() != expected.chars().count();
    check_animation(slide, &tree, id, None, lengths)?;
    let edits = if text == expected {
        Vec::new()
    } else {
        vec![(
            tree.nodes[item.node].span.clone(),
            run_bytes(&bytes, &tree, item.node, text)?,
        )]
    };
    finish(next, slide, id, &bytes, edits)
}

/// Run properties over the characters `range` of paragraph `paragraph`,
/// counted over its runs and fields as [`DeckView`] reads them (breaks hold
/// none). A run the range covers part of is split at the range's edges, each
/// piece keeping the run's own properties; a field formats whole or not at
/// all. Only the declared properties are written into each covered `a:rPr`;
/// the text and every other property are kept.
///
/// [`DeckView`]: crate::deck::DeckView
pub(super) fn set_run_props(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    paragraph: usize,
    range: (usize, usize),
    expected: &str,
    props: &RunProps<'_>,
) -> Result<Written, EditRefusal> {
    let id = shape.id.ok_or(EditRefusal::Missing("shape id"))?;
    if props
        .latin
        .is_some_and(|face| face.is_empty() || !xml::writable(face))
    {
        return Err(EditRefusal::Invalid(
            "a typeface XML cannot carry, or an empty one",
        ));
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let body = xml::child(&tree, shape.node.index, P, "txBody")
        .ok_or(EditRefusal::Missing("text body"))?;
    let paragraphs = paragraphs(&tree, body);
    let held = paragraphs
        .get(paragraph)
        .ok_or(EditRefusal::Missing("paragraph"))?;
    if held.opaque {
        return Err(EditRefusal::TextMapping(
            "the paragraph holds content the mapping does not know",
        ));
    }
    let items: Vec<_> = held
        .items
        .iter()
        .filter(|item| item.kind != Kind::Break)
        .collect();
    let text: Vec<char> = items
        .iter()
        .flat_map(|item| held.text[item.start..item.end].iter().copied())
        .collect();
    if text.iter().collect::<String>() != expected {
        return Err(EditRefusal::TargetChanged);
    }
    let (start, end) = range;
    if start >= end || end > text.len() {
        return Err(EditRefusal::Invalid(
            "a run-property range outside the paragraph",
        ));
    }
    let mut edits = Vec::new();
    let mut at = 0;
    for item in items {
        let (from, to) = (at, at + (item.end - item.start));
        at = to;
        if to <= start || from >= end {
            continue;
        }
        let node = &tree.nodes[item.node];
        if from >= start && to <= end {
            edits.push((
                node.span.clone(),
                restyled(&bytes, &tree, item.node, None, props)?,
            ));
            continue;
        }
        if item.kind == Kind::Field {
            return Err(EditRefusal::TextMapping("a field formats whole"));
        }
        let own: Vec<char> = held.text[item.start..item.end].to_vec();
        let (cut_in, cut_out) = (start.max(from) - from, end.min(to) - from);
        let mut out = Vec::new();
        for (piece, styled) in [
            (&own[..cut_in], false),
            (&own[cut_in..cut_out], true),
            (&own[cut_out..], false),
        ] {
            if piece.is_empty() {
                continue;
            }
            let piece: String = piece.iter().collect();
            let declared = if styled { *props } else { RunProps::default() };
            out.extend(restyled(&bytes, &tree, item.node, Some(&piece), &declared)?);
        }
        edits.push((node.span.clone(), out));
    }
    finish(next, slide, id, &bytes, edits)
}

/// `a:rPr` children that follow `a:latin` in `CT_TextCharacterProperties`.
const AFTER_LATIN: &[&str] = &[
    "ea",
    "cs",
    "sym",
    "hlinkClick",
    "hlinkMouseOver",
    "rtl",
    "extLst",
];

/// A run's or field's bytes with the declared `props` in its `a:rPr` and,
/// when given, `text` as its `a:t`.
fn restyled(
    bytes: &[u8],
    tree: &XmlTree,
    run: usize,
    text: Option<&str>,
    props: &RunProps<'_>,
) -> Result<Vec<u8>, EditRefusal> {
    let node = &tree.nodes[run];
    let prefix = xml::prefix(node);
    let flag = |on: bool| if on { "1" } else { "0" };
    let attributes: Vec<(&str, String)> = [
        props.bold.map(|on| ("b", flag(on).to_owned())),
        props.italic.map(|on| ("i", flag(on).to_owned())),
        props.size.map(|size| ("sz", size.to_string())),
    ]
    .into_iter()
    .flatten()
    .collect();
    let latin = props.latin.map(|face| {
        format!(
            r#"<{} typeface="{}"/>"#,
            xml::qualify(prefix, "latin"),
            xml::escape_attribute(face)
        )
    });
    let mut edits: Vec<Splice> = Vec::new();
    match xml::child(tree, run, A, "rPr") {
        Some(r_pr) => {
            let r_pr_node = &tree.nodes[r_pr];
            for (name, value) in &attributes {
                edits.push(xml::set_attribute(bytes, r_pr_node, name, value));
            }
            if let (Some(face), Some(element)) = (props.latin, latin) {
                match xml::child(tree, r_pr, A, "latin") {
                    Some(held) => {
                        edits.push(xml::set_attribute(
                            bytes,
                            &tree.nodes[held],
                            "typeface",
                            face,
                        ));
                    }
                    None if r_pr_node.empty => {
                        let close = r_pr_node.span.end - 2;
                        if bytes.get(close..r_pr_node.span.end) != Some(b"/>".as_slice()) {
                            return Err(EditRefusal::TextMapping(
                                "an empty a:rPr not closed by />",
                            ));
                        }
                        let tail = format!(">{element}</{}>", r_pr_node.qualified);
                        edits.push((close..r_pr_node.span.end, tail.into_bytes()));
                    }
                    None => {
                        let before = r_pr_node.children.iter().copied().find(|&at| {
                            tree.nodes[at].namespace == A
                                && AFTER_LATIN.contains(&tree.nodes[at].name.as_str())
                        });
                        edits.push(match before {
                            Some(at) => {
                                let point = tree.nodes[at].span.start;
                                (point..point, element.into_bytes())
                            }
                            None => xml::insert_last(bytes, r_pr_node, &element),
                        });
                    }
                }
            }
        }
        None if !attributes.is_empty() || latin.is_some() => {
            let r_pr = xml::qualify(prefix, "rPr");
            let mut element = format!("<{r_pr}");
            for (name, value) in &attributes {
                element.push_str(&format!(r#" {name}="{value}""#));
            }
            match latin {
                Some(latin) => element.push_str(&format!(">{latin}</{r_pr}>")),
                None => element.push_str("/>"),
            }
            edits.push(xml::insert_first(bytes, node, &element));
        }
        None => {}
    }
    if let Some(text) = text {
        let t =
            xml::child(tree, run, A, "t").ok_or(EditRefusal::TextMapping("a run without text"))?;
        let t_node = &tree.nodes[t];
        let escaped = escape_text(text);
        edits.push(if t_node.empty {
            let mut value = xml::open_tag(bytes, t_node);
            value.extend(format!("{escaped}</{}>", t_node.qualified).into_bytes());
            (t_node.span.clone(), value)
        } else {
            (t_node.content.clone(), escaped.into_bytes())
        });
    }
    let base = node.span.start;
    let local = edits
        .into_iter()
        .map(|(range, value)| (range.start - base..range.end - base, value))
        .collect();
    xml::splice(&bytes[node.span.clone()], local)
}

fn finish(
    next: &mut Package,
    slide: &SlideView,
    id: u32,
    bytes: &[u8],
    edits: Vec<Splice>,
) -> Result<Written, EditRefusal> {
    let changed = !edits.is_empty();
    if changed {
        next.replace_xml_part(&slide.part, xml::splice(bytes, edits)?)?;
    }
    Ok(Written {
        allowed: vec![slide.part.clone()],
        declared: vec![Declared::element(&slide.part, Some(id), &[(P, "txBody")])],
        relationships: Vec::new(),
        created: Vec::new(),
        effects: Vec::new(),
        fit: changed.then(|| FitUnverified {
            part: slide.part.clone(),
            shape: id,
        }),
    })
}

/// The splices that turn the body's paragraphs into `new`, and the paragraph
/// index from which paragraphs are added or removed, if any are.
pub(super) fn rewrite_body(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    new: &[Vec<char>],
) -> Result<(Vec<Splice>, Option<usize>), EditRefusal> {
    let old = paragraphs(tree, body);
    let mut head = 0;
    while head < old.len() && head < new.len() && old[head].text == new[head] {
        head += 1;
    }
    let mut tail = 0;
    while tail < old.len() - head
        && tail < new.len() - head
        && old[old.len() - 1 - tail].text == new[new.len() - 1 - tail]
    {
        tail += 1;
    }
    let (old_end, new_end) = (old.len() - tail, new.len() - tail);
    let paired = (old_end - head).min(new_end - head);
    let mut edits = Vec::new();
    for i in head..head + paired {
        if let Some(edit) = rewrite_paragraph(bytes, tree, &old[i], &new[i])? {
            edits.push(edit);
        }
    }
    let at = head + paired;
    for removed in &old[at..old_end] {
        edits.push((tree.nodes[removed.node].span.clone(), Vec::new()));
    }
    if at < new_end {
        let added: Vec<&[char]> = new[at..new_end].iter().map(Vec::as_slice).collect();
        edits.push(insert_paragraphs(bytes, tree, body, &old, at, &added)?);
    }
    let structure = (old.len() != new.len()).then_some(at);
    Ok((edits, structure))
}

/// What the mapping does to one item of a paired paragraph.
enum Action {
    Keep,
    Remove,
    /// A run partly inside the changed span keeps its text outside it.
    Trim(String, String),
}

/// One paired paragraph: keep everything outside the changed span.
fn rewrite_paragraph(
    bytes: &[u8],
    tree: &XmlTree,
    paragraph: &Paragraph,
    new: &[char],
) -> Result<Option<Splice>, EditRefusal> {
    let old = &paragraph.text;
    if old.as_slice() == new {
        return Ok(None);
    }
    if paragraph.opaque {
        return Err(EditRefusal::TextMapping(
            "the paragraph holds content the mapping does not know",
        ));
    }
    let mut a = 0;
    while a < old.len() && a < new.len() && old[a] == new[a] {
        a += 1;
    }
    let mut b = 0;
    while b < old.len() - a && b < new.len() - a && old[old.len() - 1 - b] == new[new.len() - 1 - b]
    {
        b += 1;
    }
    let (s, e) = (a, old.len() - b);
    let inserted: String = new[a..new.len() - b].iter().collect();
    if inserted.contains(BREAK) {
        return Err(EditRefusal::TextMapping("new text holds a line break"));
    }
    let text = |from: usize, to: usize| -> String { old[from..to].iter().collect() };
    let mut actions = Vec::with_capacity(paragraph.items.len());
    for item in &paragraph.items {
        actions.push(if item.end <= s || item.start >= e {
            Action::Keep
        } else if item.start >= s && item.end <= e {
            // A field's text is computed: it may be removed, never replaced.
            if item.kind == Kind::Field && !inserted.is_empty() {
                return Err(EditRefusal::TextMapping("new text replaces a field"));
            }
            Action::Remove
        } else if item.kind == Kind::Run {
            let head = text(item.start, s.max(item.start));
            let tail = text(e.min(item.end).max(item.start), item.end);
            Action::Trim(head, tail)
        } else {
            return Err(EditRefusal::TextMapping("the change cuts into a field"));
        });
    }
    let runs = || {
        paragraph
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.kind == Kind::Run)
    };
    let host = if inserted.is_empty() {
        None
    } else {
        runs()
            .find(|(_, item)| item.start < s && item.end > s)
            .or_else(|| runs().find(|(_, item)| s < e && item.start >= s && item.start < e))
            .or_else(|| runs().rfind(|(_, item)| item.end == s))
            .or_else(|| runs().find(|(_, item)| item.start == e))
            .map(|(index, _)| index)
    };
    let node = &tree.nodes[paragraph.node];
    let mut out = Vec::new();
    out.extend(xml::open_tag(bytes, node));
    let mut cursor = if node.empty {
        node.span.end
    } else {
        node.open_end
    };
    let mut pending = match host {
        None if !inserted.is_empty() => Some(new_run(bytes, tree, paragraph, &inserted)),
        _ => None,
    };
    for &child in &node.children {
        let element = &tree.nodes[child];
        let item = paragraph.items.iter().position(|item| item.node == child);
        let later = match item {
            Some(index) => {
                !matches!(actions[index], Action::Remove) && paragraph.items[index].start >= e
            }
            None => element.is(A, "endParaRPr"),
        };
        if later && let Some(run) = pending.take() {
            out.extend_from_slice(&bytes[cursor..element.span.start]);
            cursor = element.span.start;
            out.extend(run.into_bytes());
        }
        out.extend_from_slice(&bytes[cursor..element.span.start]);
        cursor = element.span.end;
        let Some(index) = item else {
            out.extend_from_slice(&bytes[element.span.clone()]);
            continue;
        };
        let it = paragraph.items[index];
        let written = match (&actions[index], host == Some(index)) {
            (Action::Keep, false) => {
                out.extend_from_slice(&bytes[element.span.clone()]);
                continue;
            }
            (Action::Keep, true) if it.end == s => format!("{}{inserted}", text(it.start, it.end)),
            (Action::Keep, true) => format!("{inserted}{}", text(it.start, it.end)),
            (Action::Remove, false) => continue,
            (Action::Remove, true) => inserted.clone(),
            (Action::Trim(head, tail), true) => format!("{head}{inserted}{tail}"),
            (Action::Trim(head, tail), false) => format!("{head}{tail}"),
        };
        if !written.is_empty() {
            out.extend(run_bytes(bytes, tree, child, &written)?);
        }
    }
    if let Some(run) = pending {
        if !node.empty {
            out.extend_from_slice(&bytes[cursor..node.content.end]);
            cursor = node.content.end;
        }
        out.extend(run.into_bytes());
    }
    if node.empty {
        out.extend(format!("</{}>", node.qualified).into_bytes());
    } else {
        out.extend_from_slice(&bytes[cursor..node.span.end]);
    }
    Ok(Some((node.span.clone(), out)))
}

/// A run's bytes with its `a:t` text replaced.
fn run_bytes(bytes: &[u8], tree: &XmlTree, run: usize, text: &str) -> Result<Vec<u8>, EditRefusal> {
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

/// A new run carrying the paragraph's end properties as its own.
fn new_run(bytes: &[u8], tree: &XmlTree, paragraph: &Paragraph, text: &str) -> String {
    let node = &tree.nodes[paragraph.node];
    let prefix = xml::prefix(node);
    let properties = xml::child(tree, paragraph.node, A, "endParaRPr")
        .map_or_else(String::new, |end| {
            renamed(bytes, &tree.nodes[end], &xml::qualify(prefix, "rPr"))
        });
    format!(
        "<{r}>{properties}<{t}>{}</{t}></{r}>",
        escape_text(text),
        r = xml::qualify(prefix, "r"),
        t = xml::qualify(prefix, "t"),
    )
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
fn insert_paragraphs(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    old: &[Paragraph],
    at: usize,
    added: &[&[char]],
) -> Result<Splice, EditRefusal> {
    if added.iter().any(|p| p.contains(&BREAK)) {
        return Err(EditRefusal::TextMapping("new text holds a line break"));
    }
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
    let run = if text.is_empty() {
        String::new()
    } else {
        format!(
            "<{r}>{run_properties}<{t}>{}</{t}></{r}>",
            escape_text(text),
            r = xml::qualify(prefix, "r"),
            t = xml::qualify(prefix, "t"),
        )
    };
    format!(
        "<{p}>{}{run}{}</{p}>",
        element("pPr"),
        element("endParaRPr"),
        p = xml::qualify(prefix, "p"),
    )
}

fn bare_paragraph(prefix: &str, text: &str) -> String {
    let p = xml::qualify(prefix, "p");
    format!("<{p}>{}</{p}>", bare_runs(prefix, text))
}

/// A property-less run, or nothing for empty text.
pub(super) fn bare_runs(prefix: &str, text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let (r, t) = (xml::qualify(prefix, "r"), xml::qualify(prefix, "t"));
    format!("<{r}><{t}>{}</{t}></{r}>", escape_text(text))
}

/// Text-range dependencies (ARCH-0077, "Animation dependencies"): paragraph
/// builds hold while no paragraph at or before their range is added or
/// removed; character ranges hold only while every paragraph keeps its
/// length. Nothing is remapped.
fn check_animation(
    slide: &SlideView,
    tree: &XmlTree,
    id: u32,
    structure: Option<usize>,
    lengths: bool,
) -> Result<(), EditRefusal> {
    for target in slide.animation.targets_of(id) {
        let moved = match target.text {
            Some(TextRange::Characters { .. }) => lengths,
            Some(TextRange::Paragraphs { end, .. }) => {
                structure.is_some_and(|at| end as usize >= at)
            }
            None => {
                target.role == TargetRole::Build
                    && structure.is_some()
                    && matches!(
                        tree.nodes[target.node.index].attr("build"),
                        Some("p" | "cust")
                    )
            }
        };
        if moved {
            return Err(EditRefusal::AnimatedTextStructureChanged);
        }
    }
    Ok(())
}
