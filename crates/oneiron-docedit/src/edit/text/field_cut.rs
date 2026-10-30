//! A table cell's field-aware cut (FIX 12227): where the retained text
//! mapping refuses because new text would replace an `a:fld`, the cell
//! writer first tries cutting each covered field whole and writing the new
//! text into an adjacent run, keeping that run's properties. Only a field
//! the changed span covers whole is cut; any other field keeps its bytes.
//! The cut applies only when the paragraph then reads exactly the requested
//! text, and each cut field's `type` rides back for the outcome, so the
//! receipt says the dynamic field became static text. Anything else keeps
//! the caller's own rebuild.
use super::build::{broken_run, insert_paragraphs, new_run};
use super::{Action, BREAK, Kind, Paragraph, paragraphs};
use crate::edit::xml::{self, A, Splice};
use crate::ooxml::XmlTree;

/// A table cell's text body with `value` (`\n` between paragraphs) as its
/// text (FIX 12227): first through the mapping `cell_text` uses, then,
/// where that refuses, through a field-aware cut that removes each field
/// the change covers whole and writes the new text into an adjacent run.
/// Each cut field's `type` rides back for the outcome; empty when the
/// mapping wrote the cell. `None` when the cut does not apply either; the
/// caller keeps its own rebuild then.
pub(crate) fn cell_text_cut(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    value: &str,
) -> Option<(Vec<u8>, Vec<String>)> {
    if let Some(out) = super::cell_text(bytes, tree, body, value) {
        return Some((out, Vec::new()));
    }
    // As `cell_text` builds it: a paragraph whose text reads as before,
    // its line breaks aside, keeps them.
    let old = paragraphs(tree, body);
    let new: Vec<Vec<char>> = value
        .split('\n')
        .enumerate()
        .map(|(at, line)| match old.get(at) {
            Some(held)
                if held
                    .text
                    .iter()
                    .copied()
                    .filter(|&c| c != BREAK)
                    .eq(line.chars()) =>
            {
                held.text.clone()
            }
            _ => line.chars().collect(),
        })
        .collect();
    let (edits, cut) = rewrite_body_cut(bytes, tree, body, &new)?;
    let out = xml::splice(bytes, edits).ok()?;
    Some((out, cut))
}

/// The splices that turn the body's paragraphs into `new`, cutting whole
/// fields where the mapping refuses (FIX 12227), with each cut field's
/// `type`. Paired paragraphs are written as the mapping writes them,
/// except covered fields go whole instead of refusing; added and removed
/// paragraphs are written as the mapping writes them. `None` when any
/// paired paragraph refuses the cut; the caller keeps its own rebuild then.
fn rewrite_body_cut(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    new: &[Vec<char>],
) -> Option<(Vec<Splice>, Vec<String>)> {
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
    let mut cut = Vec::new();
    for i in head..head + paired {
        let (edit, kinds) = rewrite_paragraph_cut(bytes, tree, &old[i], &new[i])?;
        if let Some(edit) = edit {
            edits.push(edit);
        }
        cut.extend(kinds);
    }
    let at = head + paired;
    for removed in &old[at..old_end] {
        edits.push((tree.nodes[removed.node].span.clone(), Vec::new()));
    }
    if at < new_end {
        let added: Vec<&[char]> = new[at..new_end].iter().map(Vec::as_slice).collect();
        edits.push(insert_paragraphs(bytes, tree, body, &old, at, &added).ok()?);
    }
    Some((edits, cut))
}

/// One paired paragraph with whole fields cut out (FIX 12227): as the
/// mapping's paired-paragraph rewrite, except a field the changed span
/// covers whole is removed, its `type` recorded, instead of refusing.
/// `None` when the cut does not apply: an opaque paragraph, a field the
/// span covers only partly (cutting it whole would lose kept text), new
/// text with no adjacent run to hold it, or a cut field without a `type`.
/// The written paragraph is checked to read exactly `new`.
fn rewrite_paragraph_cut(
    bytes: &[u8],
    tree: &XmlTree,
    paragraph: &Paragraph,
    new: &[char],
) -> Option<(Option<Splice>, Vec<String>)> {
    let old = &paragraph.text;
    if old.as_slice() == new {
        return Some((None, Vec::new()));
    }
    if paragraph.opaque {
        return None;
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
    // A U+000B in the new text is written as an `a:br` (see `build`).
    let inserted: String = new[a..new.len() - b].iter().collect();
    let text = |from: usize, to: usize| -> String { old[from..to].iter().collect() };
    let mut actions = Vec::with_capacity(paragraph.items.len());
    let mut cut = Vec::new();
    for item in &paragraph.items {
        actions.push(if item.end <= s || item.start >= e {
            Action::Keep
        } else if item.start >= s && item.end <= e {
            if item.kind == Kind::Field {
                // Whole: the span covers the field, so nothing outside the
                // change is lost. Its `type` names it in the outcome.
                cut.push(tree.nodes[item.node].attr("type")?.to_owned());
            }
            Action::Remove
        } else if item.kind == Kind::Run {
            let head = text(item.start, s.max(item.start));
            let tail = text(e.min(item.end).max(item.start), item.end);
            Action::Trim(head, tail)
        } else {
            // A field the span covers only partly: cutting it whole would
            // lose kept text, so the cut does not apply.
            return None;
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
    // The new text goes into an adjacent run, keeping that run's
    // properties; with no run to hold it the cut does not apply.
    if !inserted.is_empty() && host.is_none() {
        return None;
    }
    // The cut applies only when the paragraph then reads exactly `new`.
    let mut read = String::new();
    for (index, item) in paragraph.items.iter().enumerate() {
        match (&actions[index], host == Some(index)) {
            (Action::Keep, false) => read.push_str(&text(item.start, item.end)),
            (Action::Keep, true) if item.end == s => {
                read.push_str(&text(item.start, item.end));
                read.push_str(&inserted);
            }
            (Action::Keep, true) => {
                read.push_str(&inserted);
                read.push_str(&text(item.start, item.end));
            }
            (Action::Remove, false) => {}
            (Action::Remove, true) => read.push_str(&inserted),
            (Action::Trim(head, tail), true) => {
                read.push_str(head);
                read.push_str(&inserted);
                read.push_str(tail);
            }
            (Action::Trim(head, tail), false) => {
                read.push_str(head);
                read.push_str(tail);
            }
        }
    }
    if read.chars().collect::<Vec<_>>() != new {
        return None;
    }
    // As the mapping writes it; `pending` stays empty, since new text
    // always has an adjacent run above.
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
            out.extend(broken_run(bytes, tree, child, &written).ok()?);
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
    Some((Some((node.span.clone(), out)), cut))
}
