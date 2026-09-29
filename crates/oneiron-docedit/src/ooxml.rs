//! Namespace-aware OOXML reader with byte offsets, for narrow retained edits
//! and package checks. It never reserializes: callers patch the source bytes
//! at the spans it reports, so unknown markup stays byte-identical.
//!
//! DTDs, unbound prefixes, duplicate expanded attributes, XML-invalid
//! characters and text outside the single root are refused, never skipped.
use std::collections::BTreeMap;
use std::ops::Range;

use quick_xml::{
    NsReader,
    events::{BytesStart, Event},
    name::ResolveResult,
};

use crate::retained_opc::XmlLimits;

/// SpreadsheetML main namespace.
pub const SPREADSHEET_MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
/// Package relationship parts (`.rels`).
pub const PACKAGE_RELATIONSHIPS: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships";
/// Relationship-id attributes inside document parts (`r:id`).
pub const DOCUMENT_RELATIONSHIPS: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
/// `[Content_Types].xml`.
pub const CONTENT_TYPES: &str = "http://schemas.openxmlformats.org/package/2006/content-types";

/// Why an XML part cannot be read safely. The reason is a stable phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid XML: {0}")]
pub struct XmlError(pub &'static str);

type Result<T> = std::result::Result<T, XmlError>;

/// One element, with the byte ranges a narrow edit needs.
#[derive(Debug)]
pub struct Node {
    pub namespace: String,
    pub name: String,
    pub qualified: String,
    /// Attribute values by qualified name, decoded and normalized.
    pub attrs: BTreeMap<String, String>,
    /// Attribute values by expanded `(namespace, local)` name.
    pub attrs_ns: BTreeMap<(String, String), String>,
    /// Source bytes of each `name="value"` pair, by qualified name.
    pub attr_spans: BTreeMap<String, Range<usize>>,
    /// The whole element, open tag to close tag.
    pub span: Range<usize>,
    /// End of the open tag.
    pub open_end: usize,
    /// Bytes between the open and close tags.
    pub content: Range<usize>,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub text: String,
    pub empty: bool,
}
impl Node {
    #[must_use]
    pub fn is(&self, ns: &str, name: &str) -> bool {
        self.namespace == ns && self.name == name
    }
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(String::as_str)
    }
    #[must_use]
    pub fn attr_ns(&self, ns: &str, name: &str) -> Option<&str> {
        self.attrs_ns
            .get(&(ns.to_owned(), name.to_owned()))
            .map(String::as_str)
    }
    /// A sibling element name with this element's prefix.
    #[must_use]
    pub fn child_name(&self, name: &str) -> String {
        self.qualified
            .rsplit_once(':')
            .map_or_else(|| name.into(), |(p, _)| format!("{p}:{name}"))
    }
}

/// A parsed part in document order; `nodes[0]` is the root element.
#[derive(Debug)]
pub struct XmlTree {
    pub nodes: Vec<Node>,
}
impl XmlTree {
    /// Parse one UTF-8 part under node and depth ceilings.
    pub fn parse(bytes: &[u8], limits: XmlLimits) -> Result<Self> {
        let source = std::str::from_utf8(bytes).map_err(|_| invalid("XML must be UTF-8"))?;
        if !source.chars().all(xml_character) {
            return Err(invalid("XML-invalid character"));
        }
        let mut reader = NsReader::from_str(source);
        let mut nodes: Vec<Node> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        let mut declaration_seen = false;
        loop {
            let start = reader.buffer_position() as usize;
            let (namespace, event) = reader
                .read_resolved_event()
                .map_err(|_| invalid("malformed XML"))?;
            let ns = match namespace {
                ResolveResult::Bound(ns) => ns.as_ref().to_owned(),
                ResolveResult::Unbound => String::new(),
                ResolveResult::Unknown(_) => return Err(invalid("unbound XML namespace")),
            };
            let end = reader.buffer_position() as usize;
            match event {
                Event::Start(tag) | Event::Empty(tag) => {
                    if nodes.len() >= limits.max_nodes || stack.len() >= limits.max_depth {
                        return Err(invalid("XML node or depth limit"));
                    }
                    let node =
                        make_node(bytes, &reader, &tag, ns, start..end, stack.last().copied())?;
                    let empty = node.empty;
                    let index = nodes.len();
                    if let Some(&parent) = stack.last() {
                        nodes[parent].children.push(index);
                    }
                    nodes.push(node);
                    if !empty {
                        stack.push(nodes.len() - 1);
                    }
                }
                Event::End(_) => {
                    let index = stack.pop().ok_or_else(|| invalid("unmatched XML close"))?;
                    nodes[index].content.end = start;
                    nodes[index].span.end = end;
                }
                Event::Text(text) => {
                    let decoded = text.xml_content(quick_xml::XmlVersion::Implicit1_0);
                    // quick-xml emits references as separate GeneralRef events.
                    append_text(&mut nodes, &stack, &decoded, true)?;
                }
                Event::GeneralRef(reference) => {
                    let value = match reference
                        .resolve_char_ref()
                        .map_err(|_| invalid("XML character reference"))?
                    {
                        Some(character) => character.to_string(),
                        None => quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                            .ok_or_else(|| invalid("unknown XML entity"))?
                            .to_owned(),
                    };
                    append_text(&mut nodes, &stack, &value, false)?;
                }
                Event::CData(data) => {
                    let text = data.xml_content(quick_xml::XmlVersion::Implicit1_0);
                    append_text(&mut nodes, &stack, &text, false)?;
                }
                Event::Decl(declaration) => {
                    if declaration_seen
                        || !nodes.is_empty()
                        || !matches!(
                            declaration.xml_version(),
                            Ok(quick_xml::XmlVersion::Explicit1_0)
                        )
                    {
                        return Err(invalid("invalid XML declaration"));
                    }
                    declaration_seen = true;
                }
                Event::DocType(_) => return Err(invalid("DTD is forbidden")),
                Event::Eof => break,
                _ => {}
            }
        }
        if !stack.is_empty() || nodes.iter().filter(|node| node.parent.is_none()).count() != 1 {
            return Err(invalid("XML needs one complete root"));
        }
        Ok(Self { nodes })
    }

    pub fn children(&self, parent: usize) -> impl Iterator<Item = (usize, &Node)> {
        self.nodes[parent]
            .children
            .iter()
            .map(move |&index| (index, &self.nodes[index]))
    }
    /// The one child with this expanded name; a duplicate is an error.
    pub fn child(&self, parent: usize, ns: &str, name: &str) -> Result<Option<(usize, &Node)>> {
        let mut nodes = self.children(parent).filter(|(_, node)| node.is(ns, name));
        let first = nodes.next();
        if nodes.next().is_some() {
            return Err(invalid("duplicate singleton element"));
        }
        Ok(first)
    }
    /// Require the root element's expanded name.
    pub fn root(&self, ns: &str, name: &str) -> Result<()> {
        if !self.nodes[0].is(ns, name) {
            return Err(invalid("unexpected XML root"));
        }
        Ok(())
    }
}

fn make_node(
    bytes: &[u8],
    reader: &NsReader<&[u8]>,
    tag: &BytesStart<'_>,
    namespace: String,
    span: Range<usize>,
    parent: Option<usize>,
) -> Result<Node> {
    let empty = bytes.get(span.end.saturating_sub(2)) == Some(&b'/');
    let qualified = tag.name().as_ref().to_owned();
    let name = tag.local_name().as_ref().to_owned();
    let mut attrs = BTreeMap::new();
    let mut attrs_ns = BTreeMap::new();
    for attr in tag.attributes() {
        let attr = attr.map_err(|_| invalid("malformed or duplicate attribute"))?;
        let key = attr.key.as_ref().to_owned();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|_| invalid("attribute value"))?
            .into_owned();
        if !value.chars().all(xml_character) {
            return Err(invalid("XML-invalid attribute character"));
        }
        let (namespace, local) = reader.resolver().resolve_attribute(attr.key);
        let namespace = match namespace {
            ResolveResult::Bound(ns) => ns.as_ref().to_owned(),
            ResolveResult::Unbound => String::new(),
            ResolveResult::Unknown(_) => return Err(invalid("unbound attribute namespace")),
        };
        let local = local.as_ref().to_owned();
        if attrs_ns.insert((namespace, local), value.clone()).is_some() {
            return Err(invalid("duplicate expanded attribute"));
        }
        attrs.insert(key, value);
    }
    let attr_spans = attribute_spans(bytes, span.start + 1 + qualified.len(), span.end)?;
    Ok(Node {
        namespace,
        name,
        qualified,
        attrs,
        attrs_ns,
        attr_spans,
        open_end: span.end,
        content: span.end..span.end,
        span,
        parent,
        children: Vec::new(),
        text: String::new(),
        empty,
    })
}
fn xml_character(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | ' '..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}
fn append_text(
    nodes: &mut [Node],
    stack: &[usize],
    text: &str,
    allow_outside_whitespace: bool,
) -> Result<()> {
    if !text.chars().all(xml_character) {
        return Err(invalid("XML-invalid text character"));
    }
    if let Some(&index) = stack.last() {
        nodes[index].text.push_str(text);
    } else if !allow_outside_whitespace || !text.trim().is_empty() {
        return Err(invalid("text outside XML root"));
    }
    Ok(())
}

fn attribute_spans(
    bytes: &[u8],
    mut cursor: usize,
    end: usize,
) -> Result<BTreeMap<String, Range<usize>>> {
    let mut spans = BTreeMap::new();
    while cursor < end {
        while cursor < end && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= end || matches!(bytes[cursor], b'/' | b'>') {
            break;
        }
        let start = cursor;
        while cursor < end && !bytes[cursor].is_ascii_whitespace() && bytes[cursor] != b'=' {
            cursor += 1;
        }
        let key = std::str::from_utf8(&bytes[start..cursor])
            .map_err(|_| invalid("attribute encoding"))?
            .to_owned();
        while cursor < end && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            return Err(invalid("attribute equals"));
        }
        cursor += 1;
        while cursor < end && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let quote = *bytes
            .get(cursor)
            .ok_or_else(|| invalid("attribute quote"))?;
        if !matches!(quote, b'\'' | b'"') {
            return Err(invalid("attribute quote"));
        }
        cursor += 1;
        while cursor < end && bytes[cursor] != quote {
            cursor += 1;
        }
        if cursor >= end {
            return Err(invalid("unterminated attribute"));
        }
        cursor += 1;
        spans.insert(key, start..cursor);
    }
    Ok(spans)
}

fn invalid(reason: &'static str) -> XmlError {
    XmlError(reason)
}

/// Escape text for an element body; a carriage return is kept as `&#13;`.
#[must_use]
pub fn escape_text(text: &str) -> String {
    quick_xml::escape::escape(text).replace('\r', "&#13;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: XmlLimits = XmlLimits {
        max_depth: 16,
        max_nodes: 64,
    };

    #[test]
    fn names_resolve_by_namespace_not_prefix_and_spans_address_source_bytes() {
        let xml = br#"<x:Relationships xmlns:x="http://schemas.openxmlformats.org/package/2006/relationships"><x:Relationship Id="a" Target="t&amp;u.xml" TargetMode="External"/><Relationship Target="ignored"/></x:Relationships>"#;
        let tree = XmlTree::parse(xml, LIMITS).expect("well-formed rels");
        tree.root(PACKAGE_RELATIONSHIPS, "Relationships")
            .expect("root");
        let targets: Vec<_> = tree
            .nodes
            .iter()
            .filter(|node| node.is(PACKAGE_RELATIONSHIPS, "Relationship"))
            .filter_map(|node| node.attr("Target"))
            .collect();
        assert_eq!(targets, ["t&u.xml"]);
        let span = tree.nodes[1].attr_spans["Target"].clone();
        assert_eq!(&xml[span], br#"Target="t&amp;u.xml""#);
        assert_eq!(tree.nodes[1].child_name("Other"), "x:Other");
    }

    #[test]
    fn dtd_unbound_prefix_second_root_and_limits_are_refused() {
        for bad in [
            &b"<!DOCTYPE a [<!ENTITY e \"x\">]><a>&e;</a>"[..],
            b"<p:a/>",
            b"<a/><b/>",
            b"<a>text</a>tail",
            b"<a b=\"1\" b=\"2\"/>",
        ] {
            assert!(XmlTree::parse(bad, LIMITS).is_err(), "{bad:?}");
        }
        let deep = "<a>".repeat(17) + &"</a>".repeat(17);
        assert_eq!(
            XmlTree::parse(deep.as_bytes(), LIMITS).map(|_| ()),
            Err(XmlError("XML node or depth limit"))
        );
    }

    #[test]
    fn escaped_text_keeps_carriage_returns() {
        assert_eq!(escape_text("a<b\r"), "a&lt;b&#13;");
    }
}
