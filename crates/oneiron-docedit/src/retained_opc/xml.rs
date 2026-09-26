//! Byte-span XML patcher. Validate a whole touched part before selecting one
//! leaf; keep every unaddressed tag, namespace declaration and extension raw.
use super::{Error, Result};
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use std::collections::{HashMap, HashSet};

pub(super) fn replace_leaf_text(
    xml: &[u8],
    path: &[&str],
    expected: &str,
    value: &str,
) -> Result<Vec<u8>> {
    if !value.chars().all(is_xml_char) {
        return Err(Error::Edit("invalid XML character"));
    }
    if path.is_empty() || path.iter().any(|segment| segment.is_empty()) {
        return Err(Error::Edit("an absolute, nonempty QName path is required"));
    }
    let matches = inspect(xml, Some((path, expected)))?.1;
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

/// Validate metadata even when no edit is requested. The bool reports an OPC
/// digital-signature relationship or content type. A malformed result makes
/// mutation read-only; it does not prevent byte-exact no-op export.
pub(super) fn signature_metadata(xml: &[u8]) -> Result<bool> {
    Ok(inspect(xml, None)?.0)
}

/// Validate UTF-8 XML 1.0 well-formedness and select a lexical leaf span.
/// There is no DTD/entity expansion or external resource fetch.
fn inspect(xml: &[u8], select: Option<(&[&str], &str)>) -> Result<(bool, Vec<(usize, usize)>)> {
    std::str::from_utf8(xml).map_err(|_| Error::Edit("non-UTF8 XML"))?;
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<String> = Vec::new();
    let mut scopes: Vec<HashMap<String, String>> = Vec::new();
    let mut matches = Vec::new();
    let mut nested = false;
    let mut target_text: Option<(usize, usize, String)> = None;
    let mut seen_root = false;
    let mut seen_decl = false;
    let mut prolog_content_before_decl = false;
    let mut signature = false;
    loop {
        let start = reader.buffer_position() as usize;
        let event = reader
            .read_event()
            .map_err(|_| Error::Edit("malformed XML"))?;
        let end = reader.buffer_position() as usize;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                if stack.is_empty() {
                    if seen_root {
                        return Err(Error::Edit("multiple XML roots"));
                    }
                    seen_root = true;
                }
                // Both start and empty children make the selected node non-leaf.
                if selected(&stack, select) {
                    nested = true;
                }
                let scope = validate_tag(&tag, &scopes, &mut signature)?;
                stack.push(tag.name().as_ref().to_owned());
                scopes.push(scope);
                if selected(&stack, select) {
                    target_text = None;
                    nested = empty;
                }
                if empty {
                    stack.pop();
                    scopes.pop();
                }
                if stack.len() > 1024 {
                    return Err(Error::Edit("XML nesting limit"));
                }
            }
            Event::Text(text) => {
                let raw = text.as_ref();
                if !raw.chars().all(is_xml_char) {
                    return Err(Error::Edit("invalid XML text character"));
                }
                let normalized = normalize_eols(raw);
                let decoded = quick_xml::escape::unescape(&normalized)
                    .map_err(|_| Error::Edit("invalid XML entity"))?;
                if stack.is_empty() && !seen_root {
                    prolog_content_before_decl = true;
                }
                if stack.is_empty() && !decoded.chars().all(is_xml_space) {
                    return Err(Error::Edit("text outside XML root"));
                }
                if selected(&stack, select) {
                    append_text(&mut target_text, start, end, &decoded);
                }
            }
            Event::GeneralRef(reference) => {
                if stack.is_empty() {
                    return Err(Error::Edit("entity outside XML root"));
                }
                let resolved = resolve_reference(&reference)?;
                if selected(&stack, select) {
                    append_text(&mut target_text, start, end, &resolved.to_string());
                }
            }
            Event::CData(text) => {
                if stack.is_empty() || !text.as_ref().chars().all(is_xml_char) {
                    return Err(Error::Edit("invalid CDATA"));
                }
                if selected(&stack, select) {
                    nested = true;
                }
            }
            Event::Comment(text) => {
                if !seen_root {
                    prolog_content_before_decl = true;
                }
                let comment = text.as_ref();
                if !comment.chars().all(is_xml_char)
                    || comment.contains("--")
                    || comment.ends_with('-')
                {
                    return Err(Error::Edit("invalid XML comment"));
                }
                if selected(&stack, select) {
                    nested = true;
                }
            }
            Event::PI(text) => {
                if !seen_root {
                    prolog_content_before_decl = true;
                }
                if text.target().eq_ignore_ascii_case("xml")
                    || !text.as_ref().chars().all(is_xml_char)
                {
                    return Err(Error::Edit("invalid XML instruction"));
                }
                if selected(&stack, select) {
                    nested = true;
                }
            }
            Event::Decl(decl) => {
                if seen_root || seen_decl || prolog_content_before_decl || !stack.is_empty() {
                    return Err(Error::Edit("misplaced XML declaration"));
                }
                seen_decl = true;
                if decl
                    .version()
                    .map_err(|_| Error::Edit("invalid XML declaration"))?
                    != "1.0"
                {
                    return Err(Error::Edit("unsupported XML version"));
                }
                if let Some(encoding) = decl.encoding() {
                    let encoding = encoding.map_err(|_| Error::Edit("invalid XML declaration"))?;
                    if !encoding.eq_ignore_ascii_case("utf-8") {
                        return Err(Error::Edit("unsupported XML encoding"));
                    }
                }
            }
            Event::End(_) => {
                if selected(&stack, select)
                    && !nested
                    && let Some((start, end, decoded)) = &target_text
                    && select.is_some_and(|(_, expected)| decoded == expected)
                {
                    matches.push((*start, *end));
                }
                stack.pop().ok_or(Error::Edit("unbalanced XML"))?;
                scopes.pop();
            }
            Event::DocType(_) => return Err(Error::Edit("DTD is not supported")),
            Event::Eof => break,
        }
    }
    if !seen_root || !stack.is_empty() {
        return Err(Error::Edit("incomplete XML document"));
    }
    Ok((signature, matches))
}

fn selected(stack: &[String], select: Option<(&[&str], &str)>) -> bool {
    select.is_some_and(|(path, _)| {
        stack.len() == path.len()
            && stack
                .iter()
                .zip(path)
                .all(|(actual, wanted)| actual == wanted)
    })
}

fn validate_tag(
    tag: &BytesStart<'_>,
    scopes: &[HashMap<String, String>],
    signature: &mut bool,
) -> Result<HashMap<String, String>> {
    let mut new_scope = HashMap::new();
    let mut attributes = Vec::new();
    for attribute in tag.attributes() {
        let attr = attribute.map_err(|_| Error::Edit("malformed or duplicate XML attribute"))?;
        let key = attr.key.as_ref();
        let _ = qname(key)?;
        if attr.value.contains('<') || !attr.value.chars().all(is_xml_char) {
            return Err(Error::Edit("invalid XML attribute character"));
        }
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Explicit1_0)
            .map_err(|_| Error::Edit("invalid XML attribute entity"))?;
        if !value.chars().all(is_xml_char) {
            return Err(Error::Edit("invalid XML attribute entity"));
        }
        if (key == "Type" || key == "ContentType")
            && value.to_ascii_lowercase().contains("digital-signature")
        {
            *signature = true;
        }
        if key == "xmlns" || key.starts_with("xmlns:") {
            let prefix = key.strip_prefix("xmlns:").unwrap_or("");
            if prefix == "xmlns"
                || (prefix == "xml") != (value == "http://www.w3.org/XML/1998/namespace")
                || (!prefix.is_empty() && value.is_empty())
                || value == "http://www.w3.org/2000/xmlns/"
            {
                return Err(Error::Edit("invalid namespace declaration"));
            }
            new_scope.insert(prefix.to_owned(), value.to_string());
        }
        attributes.push(key.to_owned());
    }
    let tag_name = tag.name();
    let (prefix, _) = qname(tag_name.as_ref())?;
    resolve_prefix(prefix, &new_scope, scopes)?;
    let mut seen = HashSet::new();
    for key in attributes {
        if key == "xmlns" || key.starts_with("xmlns:") {
            continue;
        }
        let (prefix, local) = qname(&key)?;
        let ns = if prefix.is_empty() {
            "".to_owned()
        } else {
            resolve_prefix(prefix, &new_scope, scopes)?.to_owned()
        };
        if !seen.insert((ns, local.to_owned())) {
            return Err(Error::Edit("duplicate expanded XML attribute"));
        }
    }
    Ok(new_scope)
}

fn resolve_prefix<'a>(
    prefix: &str,
    new_scope: &'a HashMap<String, String>,
    scopes: &'a [HashMap<String, String>],
) -> Result<&'a str> {
    if prefix == "xml" {
        return Ok("http://www.w3.org/XML/1998/namespace");
    }
    if prefix == "xmlns" {
        return Err(Error::Edit("reserved XML namespace prefix"));
    }
    if prefix.is_empty() {
        return Ok("");
    }
    new_scope
        .get(prefix)
        .or_else(|| scopes.iter().rev().find_map(|scope| scope.get(prefix)))
        .map(String::as_str)
        .filter(|uri| !uri.is_empty())
        .ok_or(Error::Edit("unbound XML namespace prefix"))
}

fn qname(name: &str) -> Result<(&str, &str)> {
    let (prefix, local) = name.split_once(':').unwrap_or(("", name));
    if (!prefix.is_empty() && !valid_name(prefix)) || !valid_name(local) {
        return Err(Error::Edit("invalid XML QName"));
    }
    Ok((prefix, local))
}
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(is_name_start)
        && chars.all(|c| is_name_start(c) || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}'))
}
fn is_name_start(c: char) -> bool {
    matches!(c, 'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
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
fn is_xml_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}
fn resolve_reference(reference: &quick_xml::events::BytesRef<'_>) -> Result<char> {
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
    if !is_xml_char(resolved) {
        return Err(Error::Edit("invalid XML character reference"));
    }
    Ok(resolved)
}
