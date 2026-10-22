//! Byte-span writing over a parsed part: every edit is a list of splices on
//! the retained bytes, so whatever it does not name keeps its bytes.
use super::EditRefusal;
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::retained_opc::Package;
use quick_xml::events::Event;
use std::ops::Range;

pub(crate) const P: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";
pub(crate) const A: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
pub(crate) const R: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/// One replacement of a byte range.
pub(crate) type Splice = (Range<usize>, Vec<u8>);

/// Apply non-overlapping splices to `bytes`.
pub(crate) fn splice(bytes: &[u8], mut edits: Vec<Splice>) -> Result<Vec<u8>, EditRefusal> {
    edits.sort_by_key(|(range, _)| (range.start, range.end));
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    for (range, value) in edits {
        if range.start < at || range.end > bytes.len() || range.start > range.end {
            return Err(EditRefusal::Invalid("overlapping writes"));
        }
        out.extend_from_slice(&bytes[at..range.start]);
        out.extend_from_slice(&value);
        at = range.end;
    }
    out.extend_from_slice(&bytes[at..]);
    Ok(out)
}

/// Parse a part's current bytes.
pub(crate) fn read(package: &Package, part: &str) -> Result<(Vec<u8>, XmlTree), EditRefusal> {
    let bytes = package.part(part)?.ok_or(EditRefusal::Missing("part"))?;
    let tree = XmlTree::parse(&bytes, package.limits().xml)?;
    Ok((bytes, tree))
}

/// The first child with this expanded name.
pub(crate) fn child(tree: &XmlTree, at: usize, ns: &str, name: &str) -> Option<usize> {
    tree.nodes[at]
        .children
        .iter()
        .copied()
        .find(|&index| tree.nodes[index].is(ns, name))
}

/// Follow a path of expanded names from `at`.
pub(crate) fn path(tree: &XmlTree, at: usize, steps: &[(&str, &str)]) -> Option<usize> {
    steps
        .iter()
        .try_fold(at, |at, (ns, name)| child(tree, at, ns, name))
}

/// The prefix an element was written with (`a` for `a:p`), so a sibling
/// written next to it binds the same namespace.
pub(crate) fn prefix(node: &Node) -> &str {
    node.qualified
        .split_once(':')
        .map_or("", |(prefix, _)| prefix)
}

/// `prefix:name`, or `name` for a default-namespace element.
pub(crate) fn qualify(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}:{name}")
    }
}

/// Whether a qualified attribute name is a namespace declaration.
fn binds(name: &str) -> bool {
    name == "xmlns" || name.starts_with("xmlns:")
}

/// The namespace declarations `node`'s own open tag makes, as their source
/// bytes, each led by a space (` xmlns:x="..."`). Written on a new element
/// beside `node`, they keep bound what is copied out of it (FIX 8584).
pub(crate) fn own_bindings(bytes: &[u8], node: &Node) -> String {
    node.attr_spans
        .iter()
        .filter(|(name, _)| binds(name))
        .map(|(_, span)| format!(" {}", String::from_utf8_lossy(&bytes[span.clone()])))
        .collect()
}

/// The namespace declarations in scope at `node` that its own open tag does
/// not make, the nearest ancestor's winning, as their source bytes each led
/// by a space (FIX 8582). Written on a copy of `node` taken out of its part,
/// they keep every prefix bound as it was: in element and attribute names,
/// and in values an unknown or QName-valued attribute holds. The default
/// namespace and an undeclaration of it (`xmlns=""`) count as bindings.
pub(crate) fn inherited_bindings(bytes: &[u8], tree: &XmlTree, node: usize) -> String {
    let mut seen: std::collections::BTreeSet<&str> = tree.nodes[node]
        .attr_spans
        .keys()
        .map(String::as_str)
        .filter(|name| binds(name))
        .collect();
    let mut out = String::new();
    let mut at = tree.nodes[node].parent;
    while let Some(index) = at {
        let ancestor = &tree.nodes[index];
        for (name, span) in &ancestor.attr_spans {
            if binds(name) && seen.insert(name.as_str()) {
                out.push(' ');
                out.push_str(&String::from_utf8_lossy(&bytes[span.clone()]));
            }
        }
        at = ancestor.parent;
    }
    out
}

/// The default namespace in scope at `node`: the nearest `xmlns` on it or
/// an ancestor, `None` when none declares one.
pub(crate) fn default_namespace(tree: &XmlTree, node: usize) -> Option<&str> {
    std::iter::successors(Some(node), |&at| tree.nodes[at].parent)
        .find_map(|at| tree.nodes[at].attr("xmlns"))
}

/// Where a new attribute goes: before `>` or `/>` of the open tag.
fn attribute_point(bytes: &[u8], node: &Node) -> usize {
    let end = node.open_end;
    if node.empty && bytes.get(end.wrapping_sub(2)..end) == Some(b"/>".as_slice()) {
        end - 2
    } else {
        end - 1
    }
}

/// Set an unprefixed attribute: replace its `name="value"` bytes, or add it.
pub(crate) fn set_attribute(bytes: &[u8], node: &Node, name: &str, value: &str) -> Splice {
    let pair = format!(r#"{name}="{}""#, escape_attribute(value));
    match node.attr_spans.get(name) {
        Some(span) => (span.clone(), pair.into_bytes()),
        None => {
            let at = attribute_point(bytes, node);
            (at..at, format!(" {pair}").into_bytes())
        }
    }
}

/// `node`'s open tag, attributes and namespace bindings kept, written
/// open (`<x a="1">`) when the element is empty (`<x a="1"/>`).
pub(crate) fn open_tag(bytes: &[u8], node: &Node) -> Vec<u8> {
    if node.empty {
        let mut tag = bytes[node.span.start..attribute_point(bytes, node)]
            .trim_ascii_end()
            .to_vec();
        tag.push(b'>');
        tag
    } else {
        bytes[node.span.start..node.open_end].to_vec()
    }
}

/// Insert `inner` as the first child of `node`, opening it if it was empty.
pub(crate) fn insert_first(bytes: &[u8], node: &Node, inner: &str) -> Splice {
    if node.empty {
        let mut value = open_tag(bytes, node);
        value.extend(format!("{inner}</{}>", node.qualified).into_bytes());
        (node.span.clone(), value)
    } else {
        (node.open_end..node.open_end, inner.as_bytes().to_vec())
    }
}

/// Insert `inner` as the last child of `node`, opening it if it was empty.
pub(crate) fn insert_last(bytes: &[u8], node: &Node, inner: &str) -> Splice {
    if node.empty {
        insert_first(bytes, node, inner)
    } else {
        (
            node.content.end..node.content.end,
            inner.as_bytes().to_vec(),
        )
    }
}

/// Insert `inner` just before `node`'s close tag. An empty element opens
/// (`<x a="1"/>` to `<x a="1">inner</x>`) without rewriting its open tag,
/// so a splice of one of its attributes still applies beside this one.
pub(crate) fn insert_end(bytes: &[u8], node: &Node, inner: &[u8]) -> Splice {
    if node.empty {
        let mut value = b">".to_vec();
        value.extend_from_slice(inner);
        value.extend(format!("</{}>", node.qualified).into_bytes());
        (attribute_point(bytes, node)..node.span.end, value)
    } else {
        (node.content.end..node.content.end, inner.to_vec())
    }
}

/// The splices that make `text` (escaped here) `node`'s own character
/// data: its first run of text rewritten and every later run removed, while
/// the comments, processing instructions and child elements between them
/// keep their bytes and places. An empty element opens as
/// [`insert_end`] opens it. `None` when its content does not read as XML.
pub(crate) fn replace_text(bytes: &[u8], node: &Node, text: &str) -> Option<Vec<Splice>> {
    let escaped = escape_text(text).into_bytes();
    if node.empty {
        return Some(if escaped.is_empty() {
            Vec::new()
        } else {
            vec![insert_end(bytes, node, &escaped)]
        });
    }
    let mut runs = direct_text(bytes, node)?.into_iter();
    let mut edits = Vec::new();
    match runs.next() {
        Some(first) => edits.push((first, escaped)),
        None if escaped.is_empty() => {}
        None => edits.push((node.content.start..node.content.start, escaped)),
    }
    edits.extend(runs.map(|run| (run, Vec::new())));
    Some(edits)
}

/// The byte ranges of `node`'s own character data (text, references and
/// CDATA directly inside it, not inside a child), adjacent pieces joined.
fn direct_text(bytes: &[u8], node: &Node) -> Option<Vec<Range<usize>>> {
    let base = node.content.start;
    let content = std::str::from_utf8(bytes.get(node.content.clone())?).ok()?;
    let mut reader = quick_xml::Reader::from_str(content);
    let mut depth = 0_usize;
    let mut runs: Vec<Range<usize>> = Vec::new();
    loop {
        let start = reader.buffer_position() as usize;
        let event = reader.read_event().ok()?;
        let end = reader.buffer_position() as usize;
        match event {
            Event::Start(_) => depth += 1,
            Event::End(_) => depth = depth.checked_sub(1)?,
            Event::Text(_) | Event::GeneralRef(_) | Event::CData(_) if depth == 0 => {
                let run = base + start..base + end;
                match runs.last_mut() {
                    Some(last) if last.end == run.start => last.end = run.end,
                    _ => runs.push(run),
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Some(runs)
}

/// The splices renaming `node`'s open and close tags to `qualified`; its
/// attributes, namespace bindings and content keep their bytes.
#[allow(
    dead_code,
    reason = "the QName half of the shared retention helpers; L12-B's retyped chart axis (FIX 8587) renames in place with it"
)]
pub(crate) fn rename_element(node: &Node, qualified: &str) -> Vec<Splice> {
    let open = node.span.start + 1;
    let mut edits = vec![(
        open..open + node.qualified.len(),
        qualified.as_bytes().to_vec(),
    )];
    if !node.empty {
        let close = node.content.end + 2;
        edits.push((
            close..close + node.qualified.len(),
            qualified.as_bytes().to_vec(),
        ));
    }
    edits
}

pub(crate) fn escape_attribute(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(c),
        }
    }
    out
}

/// Text an edit may write into XML: XML 1.0 characters only (U+000B, the
/// line-break mark, is mapped before this check).
pub(crate) fn writable(text: &str) -> bool {
    text.chars().all(|c| {
        matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
    })
}

/// The `p:cNvPr` of a shape element.
pub(crate) fn c_nv_pr(tree: &XmlTree, shape: usize) -> Option<usize> {
    let nv = tree.nodes[shape]
        .children
        .iter()
        .copied()
        .find(|&at| tree.nodes[at].namespace == P && tree.nodes[at].name.starts_with("nv"))?;
    child(tree, nv, P, "cNvPr")
}

/// The next free part name `{stem}{n}{suffix}` above every existing one
/// (ASCII case-insensitive): names are never reused.
pub(crate) fn next_part(
    package: &Package,
    stem: &str,
    suffix: &str,
) -> Result<String, EditRefusal> {
    let stem_lower = stem.to_ascii_lowercase();
    let high = package
        .names()
        .filter_map(|name| {
            let lower = name.to_ascii_lowercase();
            let rest = lower.strip_prefix(&stem_lower)?;
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u64>().ok()
        })
        .max()
        .unwrap_or(0);
    let next = high.checked_add(1).ok_or(EditRefusal::IdSpaceExhausted)?;
    Ok(format!("{stem}{next}{suffix}"))
}
