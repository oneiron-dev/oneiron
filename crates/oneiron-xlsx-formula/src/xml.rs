//! Namespace-aware XML offsets for narrow cache edits; never a reserializer.
use std::collections::BTreeMap;
use std::ops::Range;

use quick_xml::{
    NsReader,
    events::{BytesStart, Event},
    name::ResolveResult,
};

use crate::{FormulaError, Result};

pub(crate) const MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
pub(crate) const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
pub(crate) const DOC_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

#[derive(Debug)]
pub(crate) struct Node {
    pub namespace: String,
    pub name: String,
    pub qualified: String,
    pub attrs: BTreeMap<String, String>,
    pub attrs_ns: BTreeMap<(String, String), String>,
    pub attr_spans: BTreeMap<String, Range<usize>>,
    pub span: Range<usize>,
    pub open_end: usize,
    pub content: Range<usize>,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub text: String,
    pub empty: bool,
}
impl Node {
    pub(super) fn is(&self, ns: &str, name: &str) -> bool {
        self.namespace == ns && self.name == name
    }
    pub(super) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(String::as_str)
    }
    pub(super) fn attr_ns(&self, ns: &str, name: &str) -> Option<&str> {
        self.attrs_ns
            .get(&(ns.to_owned(), name.to_owned()))
            .map(String::as_str)
    }
    pub(super) fn child_name(&self, name: &str) -> String {
        self.qualified
            .rsplit_once(':')
            .map_or_else(|| name.into(), |(p, _)| format!("{p}:{name}"))
    }
}

pub(crate) struct Xml {
    pub nodes: Vec<Node>,
}
impl Xml {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
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
                ResolveResult::Bound(ns) => std::str::from_utf8(ns.as_ref())
                    .map_err(|_| invalid("namespace encoding"))?
                    .to_owned(),
                ResolveResult::Unbound => String::new(),
                ResolveResult::Unknown(_) => return Err(invalid("unbound XML namespace")),
            };
            let end = reader.buffer_position() as usize;
            match event {
                Event::Start(tag) | Event::Empty(tag) => {
                    if nodes.len() >= 250_000 || stack.len() >= 128 {
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
                    let decoded = text
                        .xml_content(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|_| invalid("XML text encoding"))?;
                    // quick-xml 0.41 emits references as separate GeneralRef events.
                    append_text(&mut nodes, &stack, &decoded, true)?;
                }
                Event::GeneralRef(reference) => {
                    let name = reference
                        .decode()
                        .map_err(|_| invalid("XML reference encoding"))?;
                    let encoded = format!("&{name};");
                    let value = quick_xml::escape::unescape(&encoded)
                        .map_err(|_| invalid("unknown XML entity"))?;
                    append_text(&mut nodes, &stack, &value, false)?;
                }
                Event::CData(data) => {
                    let text = data
                        .xml_content(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|_| invalid("CDATA encoding"))?;
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

    pub(super) fn children(&self, parent: usize) -> impl Iterator<Item = (usize, &Node)> {
        self.nodes[parent]
            .children
            .iter()
            .map(move |&index| (index, &self.nodes[index]))
    }
    pub(super) fn child(
        &self,
        parent: usize,
        ns: &str,
        name: &str,
    ) -> Result<Option<(usize, &Node)>> {
        let mut nodes = self.children(parent).filter(|(_, node)| node.is(ns, name));
        let first = nodes.next();
        if nodes.next().is_some() {
            return Err(invalid("duplicate singleton element"));
        }
        Ok(first)
    }
    pub(super) fn root(&self, ns: &str, name: &str) -> Result<()> {
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
    let qualified = std::str::from_utf8(tag.name().as_ref())
        .map_err(|_| invalid("tag encoding"))?
        .to_owned();
    let name = std::str::from_utf8(tag.local_name().as_ref())
        .map_err(|_| invalid("tag encoding"))?
        .to_owned();
    let mut attrs = BTreeMap::new();
    let mut attrs_ns = BTreeMap::new();
    for attr in tag.attributes() {
        let attr = attr.map_err(|_| invalid("malformed or duplicate attribute"))?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(|_| invalid("attribute encoding"))?
            .to_owned();
        let value = attr
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|_| invalid("attribute value"))?
            .into_owned();
        if !value.chars().all(xml_character) {
            return Err(invalid("XML-invalid attribute character"));
        }
        let (namespace, local) = reader.resolver().resolve_attribute(attr.key);
        let namespace = match namespace {
            ResolveResult::Bound(ns) => std::str::from_utf8(ns.as_ref())
                .map_err(|_| invalid("attribute namespace"))?
                .to_owned(),
            ResolveResult::Unbound => String::new(),
            ResolveResult::Unknown(_) => return Err(invalid("unbound attribute namespace")),
        };
        let local = std::str::from_utf8(local.as_ref())
            .map_err(|_| invalid("attribute name"))?
            .to_owned();
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

pub(crate) fn invalid(reason: &'static str) -> FormulaError {
    FormulaError::InvalidWorkbook(reason)
}
pub(crate) fn unsupported(reason: &'static str) -> FormulaError {
    FormulaError::UnsupportedWorkbook(reason)
}
pub(crate) fn escaped(text: &str) -> String {
    quick_xml::escape::escape(text).replace('\r', "&#13;")
}
