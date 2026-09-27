//! Validate a touched XML part with a complete XML 1.0 parser, then patch
//! exactly one lexical text span. Unknown nodes keep their original bytes.
use super::{Error, Result};
use quick_xml::{Reader, events::Event};

pub(super) fn replace_leaf_text(
    xml: &[u8],
    path: &[&str],
    expected: &str,
    value: &str,
) -> Result<Vec<u8>> {
    if value.chars().any(|c| !is_xml_char(c)) {
        return Err(Error::Edit("invalid XML character"));
    }
    if path.is_empty() || path.iter().any(|segment| segment.is_empty()) {
        return Err(Error::Edit("an absolute, nonempty QName path is required"));
    }
    // No-op archive parts remain opaque. Only an edit pays for this complete
    // parse. DTD/entity expansion is disabled; parsing has no external fetch.
    validate(xml)?;
    let matches = leaf_spans(xml, path, expected)?;
    if matches.len() != 1 {
        return Err(Error::Edit("target is absent, ambiguous, or not leaf text"));
    }
    if value == expected {
        return Ok(xml.to_vec());
    }
    let (start, end) = matches[0];
    let escaped = quick_xml::escape::escape(value);
    let mut out = Vec::with_capacity(xml.len() + escaped.len());
    out.extend_from_slice(&xml[..start]);
    out.extend_from_slice(escaped.as_bytes());
    out.extend_from_slice(&xml[end..]);
    Ok(out)
}

/// Return whether an OPC relationship or content type declares a digital
/// signature, after the complete metadata XML has been validated. The caller
/// treats any parse failure as read-only but still permits byte-exact no-op.
pub(super) fn signature_metadata(xml: &[u8]) -> Result<bool> {
    let document = validate(xml)?;
    Ok(document
        .descendants()
        .filter(roxmltree::Node::is_element)
        .any(|node| {
            node.attributes().any(|attr| {
                matches!(attr.name(), "Type" | "ContentType")
                    && attr
                        .value()
                        .to_ascii_lowercase()
                        .contains("digital-signature")
            })
        }))
}

fn validate(xml: &[u8]) -> Result<roxmltree::Document<'_>> {
    let text = std::str::from_utf8(xml).map_err(|_| Error::Edit("non-UTF8 XML"))?;
    let document = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 1_000_000,
            ..roxmltree::ParsingOptions::default()
        },
    )
    .map_err(|_| Error::Edit("malformed or unsupported XML"))?;
    // roxmltree accepts a few malformed lexical forms while building a tree.
    // Check those XML 1.0 grammar rules against the original tokens too.
    lexical_preflight(xml)?;
    Ok(document)
}

/// A lexical selection over already-validated XML. A semantic tree rewrite
/// would serialize unknown extensions; here only one text range is replaced.
fn leaf_spans(xml: &[u8], path: &[&str], expected: &str) -> Result<Vec<(usize, usize)>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<String> = Vec::new();
    let mut matches = Vec::new();
    let mut nested = false;
    let mut target_text: Option<(usize, usize, String)> = None;
    loop {
        let start = reader.buffer_position() as usize;
        let event = reader
            .read_event()
            .map_err(|_| Error::Edit("malformed XML"))?;
        let end = reader.buffer_position() as usize;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                // Both ordinary and self-closing children make the target
                // non-leaf. Never splice over an unaddressed child.
                if matches_path(&stack, path) {
                    nested = true;
                }
                stack.push(tag.name().as_ref().to_owned());
                if matches_path(&stack, path) {
                    target_text = None;
                    nested = empty;
                }
                if empty {
                    stack.pop();
                }
            }
            Event::Text(text) => {
                if matches_path(&stack, path) {
                    let literal = normalize_eols(text.as_ref());
                    append_text(&mut target_text, start, end, &literal);
                }
            }
            Event::GeneralRef(reference) => {
                if matches_path(&stack, path) {
                    let resolved = match reference
                        .resolve_char_ref()
                        .map_err(|_| Error::Edit("invalid XML character reference"))?
                    {
                        Some(character) => character,
                        None => match reference.as_ref() {
                            "amp" => '&',
                            "lt" => '<',
                            "gt" => '>',
                            "quot" => '"',
                            "apos" => '\'',
                            _ => return Err(Error::Edit("unknown XML entity")),
                        },
                    };
                    append_text(&mut target_text, start, end, &resolved.to_string());
                }
            }
            Event::CData(_) | Event::Comment(_) | Event::PI(_) | Event::Decl(_) => {
                if matches_path(&stack, path) {
                    nested = true;
                }
            }
            Event::End(_) => {
                if matches_path(&stack, path)
                    && !nested
                    && let Some((start, end, decoded)) = &target_text
                    && decoded == expected
                {
                    matches.push((*start, *end));
                }
                stack.pop().ok_or(Error::Edit("unbalanced XML"))?;
            }
            Event::DocType(_) => return Err(Error::Edit("DTD is not supported")),
            Event::Eof => break,
        }
    }
    Ok(matches)
}

fn matches_path(stack: &[String], path: &[&str]) -> bool {
    stack.len() == path.len()
        && stack
            .iter()
            .zip(path)
            .all(|(actual, wanted)| actual == wanted)
}
fn append_text(
    target: &mut Option<(usize, usize, String)>,
    start: usize,
    end: usize,
    decoded: &str,
) {
    if let Some((_, last, content)) = target {
        *last = end;
        content.push_str(decoded);
    } else {
        *target = Some((start, end, decoded.to_owned()));
    }
}
fn normalize_eols(raw: &str) -> String {
    raw.replace("\r\n", "\n").replace('\r', "\n")
}
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// Grammar checks not enforced by roxmltree's tree builder or quick-xml's
/// tokenizer. Work on original tokens; never reserialize the document.
fn lexical_preflight(xml: &[u8]) -> Result<()> {
    let mut reader = Reader::from_reader(xml);
    loop {
        match reader
            .read_event()
            .map_err(|_| Error::Edit("malformed XML"))?
        {
            Event::Start(tag) | Event::Empty(tag) => {
                require_xml_name(tag.name().as_ref(), false)?;
                let raw = tag.as_ref();
                let name_len = tag.name().as_ref().len();
                check_attribute_spacing(&raw[name_len..])?;
                for attribute in tag.attributes() {
                    let attr = attribute.map_err(|_| Error::Edit("invalid XML attribute"))?;
                    require_xml_name(attr.key.as_ref(), false)?;
                }
            }
            Event::Text(text) if text.as_ref().contains("]]>") => {
                return Err(Error::Edit("CDATA terminator in XML text"));
            }
            Event::PI(pi) => {
                let target = pi.target();
                if target.eq_ignore_ascii_case("xml") {
                    return Err(Error::Edit("reserved XML PI target"));
                }
                require_xml_name(target, true)?;
            }
            Event::Decl(decl) => validate_declaration(&decl)?,
            Event::DocType(_) => return Err(Error::Edit("DTD is not supported")),
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(())
}

fn validate_declaration(decl: &quick_xml::events::BytesDecl<'_>) -> Result<()> {
    let raw = decl.as_ref();
    let attrs = raw
        .strip_prefix("xml")
        .ok_or(Error::Edit("invalid XML declaration"))?;
    let attributes = check_attribute_spacing(attrs)?;
    let mut order = Vec::new();
    for (key, value) in attributes {
        match key {
            "version" if order.is_empty() && value == "1.0" => {}
            "encoding" if order == ["version"] && value.eq_ignore_ascii_case("utf-8") => {}
            "standalone"
                if (order == ["version"] || order == ["version", "encoding"])
                    && matches!(value, "yes" | "no") => {}
            _ => return Err(Error::Edit("invalid XML declaration")),
        }
        order.push(key);
    }
    if order.first() != Some(&"version") {
        return Err(Error::Edit("missing XML version"));
    }
    Ok(())
}

/// XML requires an S before each attribute, including between quoted values.
/// The event attribute iterator alone accepts `a="x"b="y"`.
fn check_attribute_spacing(raw: &str) -> Result<Vec<(&str, &str)>> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    let mut attributes = Vec::new();
    while i < bytes.len() {
        if !is_s(bytes[i]) {
            return Err(Error::Edit("missing XML attribute separator"));
        }
        while i < bytes.len() && is_s(bytes[i]) {
            i += 1;
        }
        if i == bytes.len() {
            return Ok(attributes);
        }
        let start = i;
        while i < bytes.len() && !is_s(bytes[i]) && bytes[i] != b'=' {
            i += 1;
        }
        if i == start {
            return Err(Error::Edit("invalid XML attribute name"));
        }
        let name = &raw[start..i];
        while i < bytes.len() && is_s(bytes[i]) {
            i += 1;
        }
        if bytes.get(i) != Some(&b'=') {
            return Err(Error::Edit("invalid XML attribute assignment"));
        }
        i += 1;
        while i < bytes.len() && is_s(bytes[i]) {
            i += 1;
        }
        let quote = *bytes.get(i).ok_or(Error::Edit("unquoted XML attribute"))?;
        if !matches!(quote, b'\'' | b'"') {
            return Err(Error::Edit("unquoted XML attribute"));
        }
        i += 1;
        let value_start = i;
        while i < bytes.len() && bytes[i] != quote {
            if bytes[i] == b'<' {
                return Err(Error::Edit("invalid XML attribute character"));
            }
            i += 1;
        }
        if i == bytes.len() {
            return Err(Error::Edit("unclosed XML attribute"));
        }
        attributes.push((name, &raw[value_start..i]));
        i += 1;
    }
    Ok(attributes)
}
fn is_s(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// XML Name for PI targets; QName for elements and attributes (no empty
/// prefix, no second colon). Namespace binding is checked by roxmltree.
fn require_xml_name(name: &str, allow_colon: bool) -> Result<()> {
    if !allow_colon && name.contains(':') {
        let (prefix, local) = name
            .split_once(':')
            .ok_or(Error::Edit("invalid XML QName"))?;
        if prefix.is_empty() || local.is_empty() || local.contains(':') {
            return Err(Error::Edit("invalid XML QName"));
        }
        require_xml_name(prefix, true)?;
        return require_xml_name(local, true);
    }
    let mut chars = name.chars();
    if !chars.next().is_some_and(|c| is_name_start(c, allow_colon))
        || !chars.all(|c| is_name_start(c, allow_colon)
            || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')) {
        return Err(Error::Edit("invalid XML name"));
    }
    Ok(())
}
fn is_name_start(c: char, colon: bool) -> bool {
    (colon && c == ':')
        || matches!(c, 'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
}
