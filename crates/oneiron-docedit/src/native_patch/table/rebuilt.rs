//! Paragraph-preserving fallback for a native table cell text write.
use super::{DML, NativeRefusal, Node, XmlTree, escape_text, within};

/// Rebuild with the first paragraph/run template (else the first field's).
/// Same-count lines keep their same-index paragraph properties and
/// each direct run/field/br's properties on the common character prefix/suffix
/// as static runs and breaks; the first line's replacement keeps the global template,
/// later lines use their paragraph's first run/field (else global).
/// With different counts, unchanged common whole-paragraph prefix/suffix
/// lines and paired middle lines keep their original paragraph and static
/// run properties; each paired middle replacement keeps the global run
/// template. Unpaired added lines use the first template. Unsupported
/// coverage or properties use the actual one-template render for same-count
/// later lines, then first; same-count first, count-changed outer and paired
/// middle lines fall to first.
/// Copied properties keep namespace bindings; removed field types are reported.
/// Whole field-free opaque retained segments keep their original XML and
/// namespace bindings.
/// A whole unchanged field-free paragraph keeps its original paragraph XML
/// bytes in place under the same direct text body when its full native text
/// (direct breaks as U+000B) equals the requested line and it holds zero
/// descendant DrawingML fields; omitted breaks still drop through the
/// existing prefix/suffix path.
/// Same-count lines also keep each original field-free inter-paragraph gap's
/// exact bytes in place when zero DrawingML `fld` nodes sit wholly inside
/// that gap; count-changing lines keep only contiguous head+paired prefix
/// gaps wholly between two original prefix paragraphs and strict matched
/// tail gaps wholly between two original tail paragraphs under the same
/// gate. Gaps holding any such field, crossing added lines or nonconsecutive
/// original paragraphs, and other unmatched gaps keep the existing drop so
/// field-removal receipts stay truthful.
/// Zero-text whole direct children with zero actual DrawingML `fld` (own or
/// descendant) strictly inside a retained head/tail interval carry their original
/// span bytes as-is under the same rebuilt paragraph tag and body ancestors;
/// edited, boundary, leading, trailing or field-holding empties keep the existing drop.
/// Field-free paragraph edge gaps carry only beside actually emitted original
/// neighbors: positive retained text at the first/last nonempty direct child,
/// and an original first pPr or last endParaRPr. Skipped children block bridges.
/// A wholly retained nonempty ordinary run or direct break in a field-free
/// paragraph keeps its original XML once; partial segments stay static.
pub(super) fn rebuilt(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    paragraphs: &[(usize, &Node)],
    value: &str,
) -> Result<Vec<u8>, NativeRefusal> {
    let (first, first_node) = paragraphs[0];
    let last_node = paragraphs[paragraphs.len() - 1].1;
    let piece = |node: Option<(usize, &Node)>| {
        node.map_or("", |(_, node)| {
            std::str::from_utf8(&bytes[node.span.clone()]).unwrap_or("")
        })
    };
    let source_run = within(tree, body)
        .find(|(_, node)| node.is(DML, "r"))
        .or_else(|| within(tree, body).find(|(_, node)| node.is(DML, "fld")));
    let run_xml = |selected: Option<(usize, &Node)>,
                   para_node: &Node,
                   text: &str|
     -> Result<String, NativeRefusal> {
        let r_pr = piece(
            selected
                .map(|(run, _)| tree.child(run, DML, "rPr"))
                .transpose()?
                .flatten(),
        );
        let (r, t, run_bindings) = match selected {
            Some((at, node)) => (
                node.child_name("r"),
                node.child_name("t"),
                format!(
                    "{}{}",
                    crate::edit::xml::inherited_bindings(bytes, tree, at),
                    crate::edit::xml::own_bindings(bytes, node),
                ),
            ),
            None => (
                para_node.child_name("r"),
                para_node.child_name("t"),
                String::new(),
            ),
        };
        let static_run = |part: &str| {
            format!(
                "<{r}{run_bindings}>{r_pr}<{t}>{}</{t}></{r}>",
                escape_text(part)
            )
        };
        if text.is_empty() {
            Ok(String::new())
        } else if !text.contains('\u{b}') {
            Ok(static_run(text))
        } else {
            let br = match selected {
                Some((_, node)) => node.child_name("br"),
                None => para_node.child_name("br"),
            };
            let line_break = format!("<{br}{run_bindings}>{r_pr}</{br}>");
            let mut out = String::new();
            for (index, part) in text.split('\u{b}').enumerate() {
                if index > 0 {
                    out.push_str(&line_break);
                }
                if !part.is_empty() {
                    out.push_str(&static_run(part));
                }
            }
            Ok(out)
        }
    };
    let render = |paragraph: (usize, &Node),
                  selected: Option<(usize, &Node)>,
                  line: &str|
     -> Result<String, NativeRefusal> {
        let (para, para_node) = paragraph;
        let p_pr = piece(tree.child(para, DML, "pPr")?);
        let run = run_xml(selected, para_node, line)?;
        let end = piece(tree.child(para, DML, "endParaRPr")?);
        let p = para_node.qualified.as_str();
        let p_bindings = crate::edit::xml::own_bindings(bytes, para_node);
        Ok(format!("<{p}{p_bindings}>{p_pr}{run}{end}</{p}>"))
    };
    let styled = |paragraph: (usize, &Node),
                  selected: Option<(usize, &Node)>,
                  line: &str|
     -> Option<String> {
        let (para, para_node) = paragraph;
        let p_pr_node = tree.child(para, DML, "pPr").ok()?;
        let end_node = tree.child(para, DML, "endParaRPr").ok()?;
        let p_pr = piece(p_pr_node);
        let end = piece(end_node);
        let p = para_node.qualified.as_str();
        let p_attributes: String = para_node
            .attr_spans
            .values()
            .map(|span| format!(" {}", String::from_utf8_lossy(&bytes[span.clone()])))
            .collect();
        let segments: Vec<(usize, usize, &Node, Vec<char>)> = tree
            .children(para)
            .enumerate()
            .filter(|(_, (_, node))| !node.is(DML, "pPr") && !node.is(DML, "endParaRPr"))
            .map(|(ordinal, (at, node))| {
                let text = if node.is(DML, "br") {
                    vec!['\u{b}']
                } else {
                    within(tree, at)
                        .filter(|(_, node)| node.is(DML, "t"))
                        .flat_map(|(_, node)| node.text.chars())
                        .collect()
                };
                (ordinal, at, node, text)
            })
            .collect();
        let old: Vec<char> = within(tree, para)
            .flat_map(|(_, node)| {
                if node.is(DML, "br") && node.parent == Some(para) {
                    vec!['\u{b}']
                } else if node.is(DML, "t") {
                    node.text.chars().collect::<Vec<char>>()
                } else {
                    Vec::new()
                }
            })
            .collect();
        if !segments
            .iter()
            .flat_map(|(_, _, _, text)| text.iter())
            .eq(old.iter())
        {
            return None;
        }
        let new: Vec<char> = line.chars().collect();
        let field_free = !within(tree, para).any(|(_, node)| node.is(DML, "fld"));
        if old == new && field_free {
            return Some(
                std::str::from_utf8(&bytes[para_node.span.clone()])
                    .ok()?
                    .to_owned(),
            );
        }
        let mut prefix = 0;
        while prefix < old.len() && prefix < new.len() && old[prefix] == new[prefix] {
            prefix += 1;
        }
        let mut suffix = 0;
        while suffix < old.len() - prefix
            && suffix < new.len() - prefix
            && old[old.len() - 1 - suffix] == new[new.len() - 1 - suffix]
        {
            suffix += 1;
        }
        {
            let mut position = 0;
            for (_, at, node, text) in &segments {
                let start = position;
                let end = position + text.len();
                if !node.is(DML, "r")
                    && !node.is(DML, "fld")
                    && !node.is(DML, "br")
                    && !text.is_empty()
                {
                    if within(tree, *at).any(|(_, node)| node.is(DML, "fld")) {
                        return None;
                    }
                    if end > prefix && start < old.len() - suffix {
                        return None;
                    }
                }
                position = end;
            }
        }
        let retained_runs = |from: usize, to: usize| -> Option<String> {
            let mut runs = String::new();
            let mut position = 0;
            let mut previous: Option<(usize, &Node)> = None;
            for (ordinal, at, node, text) in &segments {
                // Only original neighbors inside this unchanged interval keep their gap.
                if let Some((prior, previous_node)) = previous {
                    if field_free && prior + 1 == *ordinal && from < position && position < to {
                        runs.push_str(
                            std::str::from_utf8(&bytes[previous_node.span.end..node.span.start])
                                .ok()?,
                        );
                    }
                }
                let start = position.max(from);
                let end = (position + text.len()).min(to);
                if text.is_empty()
                    && from < position
                    && position < to
                    && !node.is(DML, "fld")
                    && !within(tree, *at).any(|(_, node)| node.is(DML, "fld"))
                {
                    runs.push_str(std::str::from_utf8(&bytes[node.span.clone()]).ok()?);
                } else if start < end {
                    if field_free
                        && (node.is(DML, "r") || node.is(DML, "br"))
                        && start == position
                        && end == position + text.len()
                    {
                        runs.push_str(std::str::from_utf8(&bytes[node.span.clone()]).ok()?);
                    } else if node.is(DML, "r") || node.is(DML, "fld") || node.is(DML, "br") {
                        let part: String = text[start - position..end - position].iter().collect();
                        runs.push_str(&run_xml(Some((*at, *node)), para_node, &part).ok()?);
                    } else {
                        let raw = std::str::from_utf8(&bytes[node.span.clone()]).ok()?;
                        let mut owned = raw.to_owned();
                        let bindings = crate::edit::xml::inherited_bindings(bytes, tree, *at);
                        owned.insert_str(node.open_end - node.span.start - 1, &bindings);
                        runs.push_str(&owned);
                    }
                }
                position += text.len();
                previous = Some((*ordinal, *node));
            }
            Some(runs)
        };
        // Boundary gaps require the first/last original segment to be emitted.
        // An un-emitted zero-text child must not be bridged over.
        let raw_gap = |from: usize, to: usize| std::str::from_utf8(&bytes[from..to]).ok();
        let opening = match p_pr_node {
            Some((at, node)) if field_free && para_node.children.first() == Some(&at) => {
                raw_gap(para_node.content.start, node.span.start)?
            }
            _ => "",
        };
        let closing = match end_node {
            Some((at, node)) if field_free && para_node.children.last() == Some(&at) => {
                raw_gap(node.span.end, para_node.content.end)?
            }
            _ => "",
        };
        let leading = match segments.first() {
            Some((ordinal, _, node, text)) if field_free && prefix > 0 && !text.is_empty() => {
                let start = match p_pr_node {
                    Some((at, property))
                        if para_node.children.first() == Some(&at) && *ordinal == 1 =>
                    {
                        Some(property.span.end)
                    }
                    None if *ordinal == 0 => Some(para_node.content.start),
                    _ => None,
                };
                start.map_or(Some(""), |start| raw_gap(start, node.span.start))?
            }
            _ => "",
        };
        let trailing = match segments.last() {
            Some((ordinal, _, node, text)) if field_free && suffix > 0 && !text.is_empty() => {
                let end = match end_node {
                    Some((at, property))
                        if para_node.children.last() == Some(&at)
                            && *ordinal + 2 == para_node.children.len() =>
                    {
                        Some(property.span.start)
                    }
                    None if *ordinal + 1 == para_node.children.len() => Some(para_node.content.end),
                    _ => None,
                };
                end.map_or(Some(""), |end| raw_gap(node.span.end, end))?
            }
            _ => "",
        };
        let head = retained_runs(0, prefix)?;
        let middle = if prefix + suffix == new.len() {
            String::new()
        } else {
            let text: String = new[prefix..new.len() - suffix].iter().collect();
            run_xml(selected, para_node, &text).ok()?
        };
        let tail = retained_runs(old.len() - suffix, old.len())?;
        Some(format!(
            "<{p}{p_attributes}>{opening}{p_pr}{leading}{head}{middle}{tail}{trailing}{end}{closing}</{p}>"
        ))
    };
    let paragraph_run = |para: usize| {
        within(tree, para)
            .find(|(_, node)| node.is(DML, "r"))
            .or_else(|| within(tree, para).find(|(_, node)| node.is(DML, "fld")))
            .or(source_run)
    };
    let new_count = value.split('\n').count();
    let same_count = paragraphs.len() == new_count;
    let (head, tail) = if same_count {
        (0, 0)
    } else {
        let paragraph_text = |para: usize, include_breaks: bool| {
            within(tree, para)
                .filter(|(_, node)| {
                    node.is(DML, "t")
                        || include_breaks && node.is(DML, "br") && node.parent == Some(para)
                })
                .map(|(_, node)| {
                    if node.is(DML, "br") {
                        "\u{b}"
                    } else {
                        node.text.as_str()
                    }
                })
                .collect::<String>()
        };
        let mut head = 0;
        for ((para, _), line) in paragraphs.iter().zip(value.split('\n')) {
            if paragraph_text(*para, line.contains('\u{b}')) != line {
                break;
            }
            head += 1;
        }
        let mut tail = 0;
        let remaining = (paragraphs.len() - head).min(new_count - head);
        for ((para, _), line) in paragraphs
            .iter()
            .rev()
            .zip(value.split('\n').rev())
            .take(remaining)
        {
            if paragraph_text(*para, line.contains('\u{b}')) != line {
                break;
            }
            tail += 1;
        }
        (head, tail)
    };
    let paired = (paragraphs.len() - head - tail).min(new_count - head - tail);
    let mut out = bytes[..first_node.span.start].to_vec();
    for (index, line) in value.split('\n').enumerate() {
        let gap_index = if index > 0 && (same_count || index < head + paired) {
            Some(index)
        } else if !same_count && index > new_count - tail {
            Some(paragraphs.len() - (new_count - index))
        } else {
            None
        };
        if let Some(original) = gap_index {
            let gap_start = paragraphs[original - 1].1.span.end;
            let gap_end = paragraphs[original].1.span.start;
            let gap_has_field = within(tree, body).any(|(_, node)| {
                node.is(DML, "fld") && node.span.start >= gap_start && node.span.end <= gap_end
            });
            if !gap_has_field {
                out.extend_from_slice(&bytes[gap_start..gap_end]);
            }
        }
        let rendered = if same_count && index == 0 {
            match styled((first, first_node), source_run, line) {
                Some(xml) => xml,
                None => render((first, first_node), source_run, line)?,
            }
        } else if same_count && index > 0 {
            let actual = paragraphs[index];
            let actual_run = paragraph_run(actual.0);
            match styled(actual, actual_run, line) {
                Some(xml) => xml,
                None => match render(actual, actual_run, line) {
                    Ok(xml) => xml,
                    Err(_) => render((first, first_node), source_run, line)?,
                },
            }
        } else if !same_count && (index < head || index >= new_count - tail) {
            let actual = if index < head {
                paragraphs[index]
            } else {
                paragraphs[paragraphs.len() - (new_count - index)]
            };
            match styled(actual, paragraph_run(actual.0), line) {
                Some(xml) => xml,
                None => render((first, first_node), source_run, line)?,
            }
        } else if !same_count && index >= head && index < head + paired {
            match styled(paragraphs[index], source_run, line) {
                Some(xml) => xml,
                None => render((first, first_node), source_run, line)?,
            }
        } else {
            render((first, first_node), source_run, line)?
        };
        out.extend_from_slice(rendered.as_bytes());
    }
    out.extend_from_slice(&bytes[last_node.span.end..]);
    Ok(out)
}
