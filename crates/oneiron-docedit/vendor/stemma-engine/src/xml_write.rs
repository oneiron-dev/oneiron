//! Streaming XML writer for OOXML document parts.
//!
//! Provides `XmlWriter`, a thin wrapper around a growing byte buffer that supports:
//! - Writing the XML declaration and OOXML root element with all known namespaces
//! - Writing raw start/end tags for structural elements like `<w:body>`
//! - Streaming individual `xmltree::Element` nodes (paragraphs, tables, bookmarks)
//!
//! This enables element-by-element streaming: each block is serialized and written
//! immediately, then dropped — avoiding the need to hold the entire body tree in
//! memory or perform a double pass (build tree -> walk tree for bytes).

use std::io::{self, Write};

use xmltree::{Element, EmitterConfig};

use crate::admission::{HeldBuffer, Hold};
use crate::word_xml::{CORE_NAMESPACE_URIS, KNOWN_OOXML_NAMESPACES};

/// A streaming XML writer that writes OOXML content to a byte buffer.
///
/// Elements are serialized using xmltree's `write_with_config` (no XML declaration),
/// which may redundantly re-declare namespaces on individual elements. This is valid
/// XML and accepted by Word — the root element's namespace declarations are
/// authoritative and the redundant ones are harmless.
///
/// The buffer takes each growth from its hold before it allocates (FIX 10657):
/// a writer [`Self::held`] under an operation's hold reserves the part it
/// streams as it is written, and a refused growth fails that write with the
/// refusal ([`crate::admission::Refusal::from_io`]).
pub(crate) struct XmlWriter {
    buf: HeldBuffer,
}

impl XmlWriter {
    /// Creates a new writer with an empty buffer that reserves nothing.
    pub fn new() -> Self {
        Self::held(Hold::default())
    }

    /// Creates a new writer with an empty buffer growing under `hold`.
    pub fn held(hold: Hold) -> Self {
        Self {
            buf: HeldBuffer::new(hold),
        }
    }

    /// Writes a raw `<tag>` opening tag (no attributes, no namespace declarations).
    ///
    /// Used for structural elements like `<w:body>` that appear inside the root
    /// and don't need their own namespace declarations.
    pub fn start_tag(&mut self, tag: &str) -> io::Result<()> {
        self.buf.write_all(b"<")?;
        self.buf.write_all(tag.as_bytes())?;
        self.buf.write_all(b">")
    }

    /// Writes a raw `</tag>` closing tag.
    pub fn end_tag(&mut self, tag: &str) -> io::Result<()> {
        self.buf.write_all(b"</")?;
        self.buf.write_all(tag.as_bytes())?;
        self.buf.write_all(b">")
    }

    /// Writes an `xmltree::Element` as a complete XML fragment (no declaration).
    ///
    /// Uses xmltree's built-in serializer with `write_document_declaration: false`.
    /// The element may redundantly declare namespace prefixes that are already on the
    /// root — this is valid XML.
    pub fn write_element(&mut self, element: &Element) -> io::Result<()> {
        let config = EmitterConfig::new().write_document_declaration(false);
        element
            .write_with_config(&mut self.buf, config)
            .map_err(emitter_error)
    }

    /// Writes a raw `xmltree::XMLNode`. Elements are written via `write_element`;
    /// text, comments, CDATA, and PIs are written as raw bytes.
    pub fn write_xml_node(&mut self, node: &xmltree::XMLNode) -> io::Result<()> {
        match node {
            xmltree::XMLNode::Element(el) => self.write_element(el),
            xmltree::XMLNode::Text(text) => xml_escape_into(&mut self.buf, text),
            xmltree::XMLNode::Comment(text) => {
                self.buf.write_all(b"<!--")?;
                self.buf.write_all(text.as_bytes())?;
                self.buf.write_all(b"-->")
            }
            xmltree::XMLNode::CData(text) => {
                self.buf.write_all(b"<![CDATA[")?;
                self.buf.write_all(text.as_bytes())?;
                self.buf.write_all(b"]]>")
            }
            xmltree::XMLNode::ProcessingInstruction(name, data) => {
                self.buf.write_all(b"<?")?;
                self.buf.write_all(name.as_bytes())?;
                if let Some(d) = data {
                    self.buf.write_all(b" ")?;
                    self.buf.write_all(d.as_bytes())?;
                }
                self.buf.write_all(b"?>")
            }
        }
    }

    /// Writes the document-level `<w:background>` element (ISO 29500-1 §17.2.1).
    ///
    /// Emits the four `w:*` attributes in document order, then any preserved
    /// drawing children verbatim. The children were serialized by `write_element`
    /// at import (xmltree re-declares the namespaces they use on the child node),
    /// so they are self-contained fragments and are written byte-for-byte.
    pub fn write_background(&mut self, bg: &crate::domain::DocumentBackground) -> io::Result<()> {
        self.buf.write_all(b"<w:background")?;
        for (attr, value) in [
            ("w:color", &bg.color),
            ("w:themeColor", &bg.theme_color),
            ("w:themeTint", &bg.theme_tint),
            ("w:themeShade", &bg.theme_shade),
        ] {
            if let Some(v) = value {
                self.buf.write_all(b" ")?;
                self.buf.write_all(attr.as_bytes())?;
                self.buf.write_all(b"=\"")?;
                xml_escape_into(&mut self.buf, v)?;
                self.buf.write_all(b"\"")?;
            }
        }
        if bg.drawing_xml.is_empty() {
            self.buf.write_all(b"/>")?;
        } else {
            self.buf.write_all(b">")?;
            for fragment in &bg.drawing_xml {
                self.buf.write_all(fragment.as_bytes())?;
            }
            self.buf.write_all(b"</w:background>")?;
        }
        Ok(())
    }

    /// Consumes the writer and returns the accumulated byte buffer. A refused
    /// write already returned its refusal to the caller, which stopped there;
    /// a refused writer returns no bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.buf.into_inner().unwrap_or_default()
    }
}

/// An emitter's error as I/O: its own I/O error as it is, so a refused
/// growth keeps its refusal.
fn emitter_error(error: xmltree::Error) -> io::Error {
    match error {
        xmltree::Error::Io(error) => error,
        error => io::Error::other(error.to_string()),
    }
}

/// Writes the XML declaration and OOXML root element opening tag with all known
/// namespace declarations.
///
/// The namespace set includes:
/// 1. All entries from `KNOWN_OOXML_NAMESPACES` (the finite set of OOXML prefixes)
/// 2. Any additional namespaces from `base_root` (preserving vendor-specific ones)
/// 3. An `mc:Ignorable` attribute listing all extension namespace prefixes
///
/// This replaces the post-hoc `ensure_all_used_namespaces` pass: instead of walking
/// the tree after serialization to discover which prefixes are used, we pre-declare
/// all known prefixes up front.
pub(crate) fn write_ooxml_root_start(
    w: &mut XmlWriter,
    root_tag: &str,
    base_root: &Element,
) -> io::Result<()> {
    // XML declaration
    w.buf
        .write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")?;

    // Collect all namespace declarations: known + base_root's extras.
    // Use an ordered collection to produce deterministic output.
    let ns_map: Vec<(&str, &str)> = KNOWN_OOXML_NAMESPACES.to_vec();
    let known_prefixes: std::collections::HashSet<&str> =
        KNOWN_OOXML_NAMESPACES.iter().map(|(p, _)| *p).collect();

    // Merge in any additional namespaces from the base document's root element
    // (vendor extensions like pt14:, aml:, …). Attributes carrying these
    // prefixes survive on preserved elements, so dropping the declaration here
    // emits non-well-formed XML (unbound prefix) — exactly the defect the
    // I-XML-001 gate refuses. BTreeMap iteration keeps the output deterministic.
    let mut vendor_ns: Vec<(&str, &str)> = Vec::new();
    if let Some(ref ns) = base_root.namespaces {
        for (prefix, uri) in ns.into_iter() {
            if !prefix.is_empty()
                && prefix != "xml"
                && prefix != "xmlns"
                && !known_prefixes.contains(prefix)
            {
                vendor_ns.push((prefix, uri));
            }
        }
    }

    // Build mc:Ignorable value: all extension namespace prefixes (not in
    // CORE_NAMESPACE_URIS), including the vendor extras — a consumer that does
    // not understand a vendor namespace must be told it is safe to ignore.
    let mut ignorable_prefixes: Vec<&str> = Vec::new();
    for &(prefix, uri) in ns_map.iter().chain(vendor_ns.iter()) {
        if !CORE_NAMESPACE_URIS.contains(&uri) && !prefix.is_empty() && prefix != "mc" {
            ignorable_prefixes.push(prefix);
        }
    }

    // Write the root element opening tag.
    w.buf.write_all(b"<")?;
    w.buf.write_all(root_tag.as_bytes())?;

    // Write namespace declarations (known set, then preserved vendor extras).
    for &(prefix, uri) in ns_map.iter().chain(vendor_ns.iter()) {
        w.buf.write_all(b" xmlns:")?;
        w.buf.write_all(prefix.as_bytes())?;
        w.buf.write_all(b"=\"")?;
        xml_escape_attr_into(&mut w.buf, uri)?;
        w.buf.write_all(b"\"")?;
    }

    // Write mc:Ignorable attribute.
    if !ignorable_prefixes.is_empty() {
        w.buf.write_all(b" mc:Ignorable=\"")?;
        for (i, prefix) in ignorable_prefixes.iter().enumerate() {
            if i > 0 {
                w.buf.write_all(b" ")?;
            }
            w.buf.write_all(prefix.as_bytes())?;
        }
        w.buf.write_all(b"\"")?;
    }

    // Carry the root element's `xml:space` (ECMA-376 permits it on any element,
    // XML §2.10). Some generators declare `xml:space="preserve"` on the story
    // root and then write space-only runs as bare `<w:t> </w:t>`, relying on the
    // inherited value. Our streaming rebuild re-emits the root here and would
    // otherwise drop the attribute, so those bare runs — carried byte-verbatim
    // inside opaque interiors (textbox `w:txbxContent`, other raw_xml) where we
    // never stamp per-run preserve — would collapse to zero-width and silently
    // corrupt their text. Our own emitted markup carries no incidental
    // inter-element whitespace (the streaming writer and xmltree serializer both
    // run without indentation), so inheriting root preservation is a no-op for
    // it; only genuine text content is affected, exactly as the source intended.
    if let Some(space) = crate::xml_attrs::attr_get(base_root, "xml:space") {
        w.buf.write_all(b" xml:space=\"")?;
        xml_escape_attr_into(&mut w.buf, space)?;
        w.buf.write_all(b"\"")?;
    }

    w.buf.write_all(b">")
}

/// Escape XML special characters in a double-quoted attribute value.
fn xml_escape_attr_into(buf: &mut impl Write, text: &str) -> io::Result<()> {
    write_escaped(buf, text, |byte| match byte {
        b'&' => Some("&amp;"),
        b'<' => Some("&lt;"),
        b'"' => Some("&quot;"),
        _ => None,
    })
}

/// Escape XML special characters in text content.
fn xml_escape_into(buf: &mut impl Write, text: &str) -> io::Result<()> {
    write_escaped(buf, text, |byte| match byte {
        b'&' => Some("&amp;"),
        b'<' => Some("&lt;"),
        b'>' => Some("&gt;"),
        _ => None,
    })
}

/// Write `text` with each byte `escape` names replaced by its entity, the
/// runs between them written whole.
fn write_escaped(
    buf: &mut impl Write,
    text: &str,
    escape: impl Fn(u8) -> Option<&'static str>,
) -> io::Result<()> {
    let bytes = text.as_bytes();
    let mut run = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if let Some(entity) = escape(byte) {
            buf.write_all(&bytes[run..index])?;
            buf.write_all(entity.as_bytes())?;
            run = index + 1;
        }
    }
    buf.write_all(&bytes[run..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmltree::Namespace;

    fn minimal_root() -> Element {
        let mut root = Element::new("document");
        root.prefix = Some("w".to_string());
        let mut ns_map = std::collections::BTreeMap::new();
        ns_map.insert(
            "w".to_string(),
            "http://schemas.openxmlformats.org/wordprocessingml/2006/main".to_string(),
        );
        root.namespaces = Some(Namespace(ns_map));
        root
    }

    #[test]
    fn write_ooxml_root_start_produces_valid_xml_declaration() {
        let mut w = XmlWriter::new();
        let root = minimal_root();
        write_ooxml_root_start(&mut w, "w:document", &root).unwrap();
        w.end_tag("w:document").unwrap();
        let xml = String::from_utf8(w.into_inner()).unwrap();
        assert!(
            xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"),
            "should start with XML declaration"
        );
        assert!(xml.contains("<w:document "), "should have root element");
        assert!(
            xml.contains(
                "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\""
            ),
            "should declare w namespace"
        );
        assert!(xml.ends_with("</w:document>"), "should close root element");
    }

    #[test]
    fn write_ooxml_root_start_preserves_vendor_namespaces() {
        // A base document carrying a vendor namespace (e.g. Open-Xml-PowerTools
        // pt14:) keeps its attributes on preserved elements, so the root MUST
        // re-declare the prefix and list it in mc:Ignorable — otherwise the
        // output is non-well-formed (unbound prefix, I-XML-001).
        let mut w = XmlWriter::new();
        let mut root = minimal_root();
        if let Some(Namespace(ref mut ns_map)) = root.namespaces {
            ns_map.insert(
                "pt14".to_string(),
                "http://powertools.codeplex.com/2011".to_string(),
            );
        }
        write_ooxml_root_start(&mut w, "w:document", &root).unwrap();
        w.end_tag("w:document").unwrap();
        let xml = String::from_utf8(w.into_inner()).unwrap();
        assert!(
            xml.contains("xmlns:pt14=\"http://powertools.codeplex.com/2011\""),
            "vendor namespace declaration must be preserved on the root: {xml}"
        );
        let ignorable = xml
            .split("mc:Ignorable=\"")
            .nth(1)
            .and_then(|rest| rest.split('\"').next())
            .expect("mc:Ignorable present");
        assert!(
            ignorable.split_whitespace().any(|p| p == "pt14"),
            "vendor prefix must be listed in mc:Ignorable: {ignorable}"
        );
    }

    #[test]
    fn write_ooxml_root_start_includes_mc_ignorable() {
        let mut w = XmlWriter::new();
        let root = minimal_root();
        write_ooxml_root_start(&mut w, "w:document", &root).unwrap();
        w.end_tag("w:document").unwrap();
        let xml = String::from_utf8(w.into_inner()).unwrap();
        assert!(
            xml.contains("mc:Ignorable=\""),
            "should have mc:Ignorable attribute"
        );
        // w14 is a known extension namespace — should be in mc:Ignorable
        assert!(
            xml.contains("w14"),
            "mc:Ignorable should list extension prefixes like w14"
        );
    }

    #[test]
    fn write_element_produces_valid_fragment() {
        let mut w = XmlWriter::new();
        let root = minimal_root();
        write_ooxml_root_start(&mut w, "w:document", &root).unwrap();
        w.start_tag("w:body").unwrap();

        // Build a simple paragraph element
        let mut p = Element::new("p");
        p.prefix = Some("w".to_string());
        p.namespace =
            Some("http://schemas.openxmlformats.org/wordprocessingml/2006/main".to_string());

        w.write_element(&p).unwrap();
        w.end_tag("w:body").unwrap();
        w.end_tag("w:document").unwrap();

        let xml = String::from_utf8(w.into_inner()).unwrap();
        assert!(xml.contains("<w:body>"), "should have body start");
        assert!(xml.contains("</w:body>"), "should have body end");
        // The paragraph element should appear somewhere in the output
        assert!(xml.contains("w:p"), "should contain paragraph element");
    }
}
