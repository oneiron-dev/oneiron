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
/// later lines, then first; same-count first uses first. Count-changed outer
/// and paired middle fallbacks keep their original wrapper and first's style.
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
/// edited, internal-boundary or field-holding empties keep the existing drop.
/// Field-free paragraph edges carry zero-text child clusters and their gaps beside
/// positive retained text at the first/last nonempty direct child, bounded by
/// an original first pPr or last endParaRPr. Skipped children block bridges.
/// A second render knows the exact original edge, whole-paragraph, whole-run,
/// native single-piece partial-run, interior-zero and opaque-child identity sources.
/// Fresh run and paragraph property template copies omit only XML-namespace id
/// attributes that survive in those original sources or an earlier fresh copy.
/// With no retained original, the first emitted fresh copy keeps its identity;
/// failed render attempts do not reserve a fresh property source. A successful
/// styled paragraph also owns its original pPr and endParaRPr sources; their original bytes stay.
/// Fallback renders of mapped originals keep their own paragraph name and attributes;
/// cloned first/global and added templates still copy only namespace declarations.
/// First-template properties moved under another original wrapper carry their
/// effective source bindings on each property, including shadowed prefixes.
/// Original identities, style and relationship refs stay.
/// A wholly retained nonempty ordinary run or direct break in a field-free
/// paragraph keeps its original XML once. A partial ordinary run keeps its own
/// attributes on its only retained piece, or on its source-start head piece
/// when it spans both intervals; the tail keeps the static style wrapper.
/// With native text elements, the owning piece keeps the original run XML
/// with each text element trimmed to its own retained character interval.
/// Unsupported native splices keep the same static attribute path on that piece.
pub(super) fn rebuilt(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    paragraphs: &[(usize, &Node)],
    value: &str,
) -> Result<Vec<u8>, NativeRefusal> {
    let (out, retained_sources) = rebuilt_pass(bytes, tree, body, paragraphs, value, &[])?;
    if retained_sources.is_empty() {
        Ok(out)
    } else {
        rebuilt_pass(bytes, tree, body, paragraphs, value, &retained_sources).map(|(out, _)| out)
    }
}

fn rebuilt_pass(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    paragraphs: &[(usize, &Node)],
    value: &str,
    retained_sources: &[std::ops::Range<usize>],
) -> Result<(Vec<u8>, Vec<std::ops::Range<usize>>), NativeRefusal> {
    let mut emitted_sources = Vec::new();
    let mut copied_sources = Vec::new();
    // Retained inter-paragraph gaps, emitted raw (review #6779 R2); they
    // join `emitted_sources` once `styled` no longer borrows it.
    let mut gap_sources = Vec::new();
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
    let template_property =
        |property: Option<(usize, &Node)>, copied_sources: &mut Vec<std::ops::Range<usize>>| {
            match property {
                Some((at, node))
                    if retained_sources
                        .iter()
                        .any(|span| span.start <= node.span.start && node.span.end <= span.end)
                        || copied_sources.contains(&node.span) =>
                {
                    copied_properties(bytes, tree, at)
                }
                Some((_, node)) => {
                    copied_sources.push(node.span.clone());
                    piece(property).to_owned()
                }
                None => String::new(),
            }
        };
    let run_xml = |selected: Option<(usize, &Node)>,
                   para_node: &Node,
                   text: &str,
                   clear_unbound_default: bool,
                   copied_sources: &mut Vec<std::ops::Range<usize>>|
     -> Result<String, NativeRefusal> {
        let property = selected
            .map(|(run, _)| tree.child(run, DML, "rPr"))
            .transpose()?
            .flatten();
        let (r, t, run_bindings) = match selected {
            Some((at, node)) => (
                node.child_name("r"),
                node.child_name("t"),
                format!(
                    "{}{}{}",
                    crate::edit::xml::inherited_bindings(bytes, tree, at),
                    crate::edit::xml::own_bindings(bytes, node),
                    if clear_unbound_default
                        && crate::edit::xml::default_namespace(tree, at).is_none()
                    {
                        " xmlns=\"\""
                    } else {
                        ""
                    },
                ),
            ),
            None => (
                para_node.child_name("r"),
                para_node.child_name("t"),
                String::new(),
            ),
        };
        let static_run = |part: &str, r_pr: &str| {
            format!(
                "<{r}{run_bindings}>{r_pr}<{t}>{}</{t}></{r}>",
                escape_text(part)
            )
        };
        if text.is_empty() {
            Ok(String::new())
        } else if !text.contains('\u{b}') {
            let r_pr = template_property(property, copied_sources);
            Ok(static_run(text, &r_pr))
        } else {
            let br = match selected {
                Some((_, node)) => node.child_name("br"),
                None => para_node.child_name("br"),
            };
            let mut out = String::new();
            for (index, part) in text.split('\u{b}').enumerate() {
                if index > 0 {
                    let r_pr = template_property(property, copied_sources);
                    out.push_str(&format!("<{br}{run_bindings}>{r_pr}</{br}>"));
                }
                if !part.is_empty() {
                    let r_pr = template_property(property, copied_sources);
                    out.push_str(&static_run(part, &r_pr));
                }
            }
            Ok(out)
        }
    };
    let render = |paragraph: (usize, &Node),
                  selected: Option<(usize, &Node)>,
                  line: &str,
                  original_wrapper: Option<(usize, &Node)>,
                  copied_sources: &mut Vec<std::ops::Range<usize>>|
     -> Result<String, NativeRefusal> {
        let mut pending_sources = copied_sources.clone();
        let (para, para_node) = paragraph;
        let (wrapper, wrapper_node) = original_wrapper.unwrap_or(paragraph);
        let moved_wrapper = wrapper != para;
        let clear_unbound_default = moved_wrapper
            && crate::edit::xml::default_namespace(tree, wrapper)
                .is_some_and(|namespace| !namespace.is_empty());
        let property_xml =
            |property: Option<(usize, &Node)>, copied_sources: &mut Vec<std::ops::Range<usize>>| {
                let mut xml = template_property(property, copied_sources);
                if moved_wrapper {
                    if let Some((at, node)) = property {
                        let mut bindings = crate::edit::xml::inherited_bindings(bytes, tree, at);
                        if clear_unbound_default
                            && crate::edit::xml::default_namespace(tree, at).is_none()
                        {
                            bindings.push_str(" xmlns=\"\"");
                        }
                        xml.insert_str(1 + node.qualified.len(), &bindings);
                    }
                }
                xml
            };
        let p_pr = property_xml(tree.child(para, DML, "pPr")?, &mut pending_sources);
        let run = run_xml(
            selected,
            wrapper_node,
            line,
            clear_unbound_default,
            &mut pending_sources,
        )?;
        let end = property_xml(tree.child(para, DML, "endParaRPr")?, &mut pending_sources);
        let p = wrapper_node.qualified.as_str();
        let p_attributes = if original_wrapper.is_some() {
            wrapper_node
                .attr_spans
                .values()
                .map(|span| format!(" {}", String::from_utf8_lossy(&bytes[span.clone()])))
                .collect()
        } else {
            crate::edit::xml::own_bindings(bytes, para_node)
        };
        *copied_sources = pending_sources;
        Ok(format!("<{p}{p_attributes}>{p_pr}{run}{end}</{p}>"))
    };
    let mut styled = |paragraph: (usize, &Node),
                      selected: Option<(usize, &Node)>,
                      line: &str,
                      copied_sources: &mut Vec<std::ops::Range<usize>>|
     -> Option<String> {
        let (para, para_node) = paragraph;
        let clear_unbound_default = crate::edit::xml::default_namespace(tree, para)
            .is_some_and(|namespace| !namespace.is_empty());
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
            let raw = std::str::from_utf8(&bytes[para_node.span.clone()])
                .ok()?
                .to_owned();
            emitted_sources.push(para_node.span.clone());
            return Some(raw);
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
        let mut original_sources = Vec::new();
        let mut pending_sources = copied_sources.clone();
        let mut retained_runs = |from: usize,
                                 to: usize,
                                 pending_sources: &mut Vec<std::ops::Range<usize>>|
         -> Option<String> {
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
                    // Emitted raw, field or not: an identity source (review #6779).
                    original_sources.push(node.span.clone());
                } else if start < end {
                    if field_free
                        && (node.is(DML, "r") || node.is(DML, "br"))
                        && start == position
                        && end == position + text.len()
                    {
                        runs.push_str(std::str::from_utf8(&bytes[node.span.clone()]).ok()?);
                        original_sources.push(node.span.clone());
                    } else if node.is(DML, "r") || node.is(DML, "fld") || node.is(DML, "br") {
                        let part: String = text[start - position..end - position].iter().collect();
                        let copied_before = pending_sources.len();
                        let mut run = run_xml(
                            Some((*at, *node)),
                            para_node,
                            &part,
                            clear_unbound_default,
                            pending_sources,
                        )
                        .ok()?;
                        // The source-start piece owns a split run's wrapper; the tail stays static.
                        if field_free
                            && node.is(DML, "r")
                            && (!(position < prefix && position + text.len() > old.len() - suffix)
                                || from == 0)
                        {
                            if let Some(original) =
                                partial_run(bytes, tree, *at, start - position..end - position)
                            {
                                run = original;
                                pending_sources.truncate(copied_before);
                                original_sources.push(node.span.clone());
                            } else {
                                let attributes: String = node
                                    .attr_spans
                                    .iter()
                                    .filter(|(name, _)| {
                                        name.as_str() != "xmlns" && !name.starts_with("xmlns:")
                                    })
                                    .map(|(_, span)| {
                                        format!(
                                            " {}",
                                            String::from_utf8_lossy(&bytes[span.clone()])
                                        )
                                    })
                                    .collect();
                                run.insert_str(1 + node.qualified.len(), &attributes);
                            }
                        }
                        runs.push_str(&run);
                    } else {
                        let raw = std::str::from_utf8(&bytes[node.span.clone()]).ok()?;
                        let mut owned = raw.to_owned();
                        let bindings = crate::edit::xml::inherited_bindings(bytes, tree, *at);
                        owned.insert_str(node.open_end - node.span.start - 1, &bindings);
                        runs.push_str(&owned);
                        original_sources.push(node.span.clone());
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
        let mut edges = Vec::new();
        let leading = match segments.iter().position(|(_, _, _, text)| !text.is_empty()) {
            Some(index) if field_free && prefix > 0 => {
                let (ordinal, _, _, _) = segments.first()?;
                let start = match p_pr_node {
                    Some((at, property))
                        if para_node.children.first() == Some(&at) && *ordinal == 1 =>
                    {
                        Some(property.span.end)
                    }
                    None if *ordinal == 0 => Some(para_node.content.start),
                    _ => None,
                };
                match start {
                    Some(start)
                        if segments[..=index]
                            .windows(2)
                            .all(|pair| pair[0].0 + 1 == pair[1].0) =>
                    {
                        let span = start..segments[index].2.span.start;
                        let raw = raw_gap(span.start, span.end)?;
                        if index > 0 {
                            edges.push(span);
                        }
                        raw
                    }
                    _ => "",
                }
            }
            _ => "",
        };
        let trailing = match segments
            .iter()
            .rposition(|(_, _, _, text)| !text.is_empty())
        {
            Some(index) if field_free && suffix > 0 => {
                let (ordinal, _, _, _) = segments.last()?;
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
                match end {
                    Some(end)
                        if segments[index..]
                            .windows(2)
                            .all(|pair| pair[0].0 + 1 == pair[1].0) =>
                    {
                        let span = segments[index].2.span.end..end;
                        let raw = raw_gap(span.start, span.end)?;
                        if index + 1 < segments.len() {
                            edges.push(span);
                        }
                        raw
                    }
                    _ => "",
                }
            }
            _ => "",
        };
        let head = retained_runs(0, prefix, &mut pending_sources)?;
        let middle = if prefix + suffix == new.len() {
            String::new()
        } else {
            let text: String = new[prefix..new.len() - suffix].iter().collect();
            run_xml(
                selected,
                para_node,
                &text,
                clear_unbound_default,
                &mut pending_sources,
            )
            .ok()?
        };
        let tail = retained_runs(old.len() - suffix, old.len(), &mut pending_sources)?;
        *copied_sources = pending_sources;
        original_sources.extend(
            [p_pr_node, end_node]
                .into_iter()
                .flatten()
                .map(|(_, node)| node.span.clone()),
        );
        emitted_sources.extend(edges);
        emitted_sources.extend(original_sources);
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
                // Emitted raw: an identity source for the second pass (review #6779 R2).
                gap_sources.push(gap_start..gap_end);
            }
        }
        let rendered = if same_count && index == 0 {
            match styled((first, first_node), source_run, line, &mut copied_sources) {
                Some(xml) => xml,
                None => render(
                    (first, first_node),
                    source_run,
                    line,
                    Some((first, first_node)),
                    &mut copied_sources,
                )?,
            }
        } else if same_count && index > 0 {
            let actual = paragraphs[index];
            let actual_run = paragraph_run(actual.0);
            match styled(actual, actual_run, line, &mut copied_sources) {
                Some(xml) => xml,
                None => match render(actual, actual_run, line, Some(actual), &mut copied_sources) {
                    Ok(xml) => xml,
                    Err(_) => render(
                        (first, first_node),
                        source_run,
                        line,
                        None,
                        &mut copied_sources,
                    )?,
                },
            }
        } else if !same_count && (index < head || index >= new_count - tail) {
            let actual = if index < head {
                paragraphs[index]
            } else {
                paragraphs[paragraphs.len() - (new_count - index)]
            };
            match styled(actual, paragraph_run(actual.0), line, &mut copied_sources) {
                Some(xml) => xml,
                None => render(
                    (first, first_node),
                    source_run,
                    line,
                    Some(actual),
                    &mut copied_sources,
                )?,
            }
        } else if !same_count && index >= head && index < head + paired {
            let actual = paragraphs[index];
            match styled(actual, source_run, line, &mut copied_sources) {
                Some(xml) => xml,
                None => render(
                    (first, first_node),
                    source_run,
                    line,
                    Some(actual),
                    &mut copied_sources,
                )?,
            }
        } else {
            render(
                (first, first_node),
                source_run,
                line,
                None,
                &mut copied_sources,
            )?
        };
        out.extend_from_slice(rendered.as_bytes());
    }
    out.extend_from_slice(&bytes[last_node.span.end..]);
    emitted_sources.extend(gap_sources);
    Ok((out, emitted_sources))
}

/// A later style copy does not repeat an identity carried by an original or fresh source.
fn copied_properties(bytes: &[u8], tree: &XmlTree, property: usize) -> String {
    let original = &tree.nodes[property];
    let mut identities = Vec::new();
    for (at, node) in std::iter::once((property, original)).chain(within(tree, property)) {
        for (name, span) in &node.attr_spans {
            let Some((prefix, "id")) = name.split_once(':') else {
                continue;
            };
            let binding = format!("xmlns:{prefix}");
            let namespace = std::iter::successors(Some(at), |&at| tree.nodes[at].parent)
                .find_map(|at| tree.nodes[at].attr(&binding))
                .or_else(|| (prefix == "xml").then_some("http://www.w3.org/XML/1998/namespace"));
            if namespace == Some("http://www.w3.org/XML/1998/namespace") {
                identities.push(span.clone());
            }
        }
    }
    identities.sort_by_key(|span| span.start);
    let mut out = Vec::new();
    let mut start = original.span.start;
    for span in identities {
        out.extend_from_slice(&bytes[start..span.start]);
        start = span.end;
    }
    out.extend_from_slice(&bytes[start..original.span.end]);
    String::from_utf8(out).unwrap_or_default()
}

/// Trim each text element to its own part of one retained original run interval.
fn partial_run(
    bytes: &[u8],
    tree: &XmlTree,
    run: usize,
    kept: std::ops::Range<usize>,
) -> Option<String> {
    let original = &tree.nodes[run];
    let mut edits = Vec::new();
    let mut position = 0;
    for (_, node) in within(tree, run).filter(|(_, node)| node.is(DML, "t")) {
        let text: Vec<char> = node.text.chars().collect();
        let start = kept.start.saturating_sub(position).min(text.len());
        let end = kept.end.saturating_sub(position).min(text.len());
        if start != 0 || end != text.len() {
            let part: String = text[start..end].iter().collect();
            edits.extend(crate::edit::xml::replace_text(bytes, node, &part)?);
        }
        position += text.len();
    }
    let edits = edits
        .into_iter()
        .map(|(range, value)| {
            (
                range.start - original.span.start..range.end - original.span.start,
                value,
            )
        })
        .collect();
    String::from_utf8(crate::edit::xml::splice(&bytes[original.span.clone()], edits).ok()?).ok()
}
