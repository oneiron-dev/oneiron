//! Inspect Word settings without rewriting them; enforced protection is a hard edit refusal.
use crate::opc::OpcPackage;
use crate::{Error, Result};
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const WORD: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const STRICT_WORD: &str = "http://purl.oclc.org/ooxml/wordprocessingml/main";
const RELS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const SETTINGS_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings";
const STRICT_SETTINGS_REL: &str =
    "http://purl.oclc.org/ooxml/officeDocument/relationships/settings";

/// Protection metadata, not a password-verification or unlock capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxProtection {
    pub enforced: bool,
    pub edit: Option<String>,
}

/// Settings relevant to the narrow writer. Unknown settings stay untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxSettings {
    pub part: Option<String>,
    pub document_protection: Option<DocxProtection>,
    pub track_revisions: bool,
    pub write_protection: bool,
}

impl DocxSettings {
    /// Refuses every enforced mode, including comments and trackedChanges.
    /// This organ does not authenticate passwords or implement protection exceptions.
    pub fn require_editable(&self) -> Result<()> {
        if self
            .document_protection
            .as_ref()
            .is_some_and(|p| p.enforced)
        {
            return Err(Error::EditFailed("docx document protection is enforced"));
        }
        if self.write_protection {
            return Err(Error::EditFailed(
                "docx write protection requires an external authorization path",
            ));
        }
        Ok(())
    }
}

/// Resolve the settings relationship (including nonstandard part names), then
/// inspect protection and tracked mode. Malformed or ambiguous settings fail closed.
pub fn inspect_docx_settings(package: &OpcPackage) -> Result<DocxSettings> {
    let mut part = None;
    if let Some(bytes) = package.part("word/_rels/document.xml.rels") {
        let root = parse(bytes)?;
        if root.ns != RELS || root.name != "Relationships" {
            return invalid("invalid Word settings relationship root");
        }
        for child in &root.children {
            if child.ns != RELS || child.name != "Relationship" {
                continue;
            }
            let kind = child.attr("", "Type");
            if kind != Some(SETTINGS_REL) && kind != Some(STRICT_SETTINGS_REL) {
                continue;
            }
            if part.is_some()
                || child
                    .attr("", "TargetMode")
                    .is_some_and(|m| m != "Internal")
            {
                return invalid("ambiguous or external Word settings relationship");
            }
            let target = child
                .attr("", "Target")
                .ok_or(Error::InvalidPackage("missing settings target"))?;
            part = Some(resolve_target(target)?);
        }
    }
    if package.contains("word/settings.xml") {
        if part
            .as_deref()
            .is_some_and(|name| name != "word/settings.xml")
        {
            return invalid("conflicting Word settings parts");
        }
        part = Some("word/settings.xml".to_owned());
    }
    let Some(name) = part else {
        return Ok(DocxSettings::default());
    };
    let bytes = package
        .part(&name)
        .ok_or(Error::InvalidPackage("missing Word settings part"))?;
    let root = parse(bytes)?;
    if !is_word(&root.ns) || root.name != "settings" || root.non_whitespace {
        return invalid("invalid Word settings root");
    }
    let mut settings = DocxSettings {
        part: Some(name),
        ..DocxSettings::default()
    };
    let mut tracking_seen = false;
    for child in &root.children {
        match child.name.as_str() {
            "documentProtection" => {
                if settings.document_protection.is_some() || !is_word(&child.ns) {
                    return invalid("duplicate or invalid document protection element");
                }
                check_leaf(child)?;
                let enforced = word_bool(child, "enforcement", false)?;
                let edit = child.word_attr("edit")?;
                if edit.is_some_and(|mode| {
                    !matches!(
                        mode,
                        "none" | "readOnly" | "comments" | "trackedChanges" | "forms"
                    )
                }) {
                    return invalid("invalid document protection edit mode");
                }
                word_bool(child, "formatting", false)?;
                settings.document_protection = Some(DocxProtection {
                    enforced,
                    edit: edit.map(str::to_owned),
                });
            }
            "trackRevisions" => {
                if tracking_seen || !is_word(&child.ns) {
                    return invalid("duplicate or invalid tracked mode element");
                }
                check_leaf(child)?;
                settings.track_revisions = word_bool(child, "val", true)?;
                tracking_seen = true;
            }
            "writeProtection" => {
                if settings.write_protection || !is_word(&child.ns) {
                    return invalid("duplicate or invalid write protection element");
                }
                check_leaf(child)?;
                settings.write_protection = true;
            }
            _ => {
                if has_policy_descendant(child) {
                    return invalid(
                        "Word protection or tracking setting is not a direct settings child",
                    );
                }
            }
        }
    }
    Ok(settings)
}

fn is_word(ns: &str) -> bool {
    matches!(ns, WORD | STRICT_WORD)
}
fn check_leaf(node: &Node) -> Result<()> {
    if node.non_whitespace || !node.children.is_empty() {
        return invalid("Word protection or tracking setting is not empty");
    }
    Ok(())
}
fn has_policy_descendant(node: &Node) -> bool {
    node.children.iter().any(|child| {
        matches!(
            child.name.as_str(),
            "documentProtection" | "writeProtection" | "trackRevisions"
        ) || has_policy_descendant(child)
    })
}
fn word_bool(node: &Node, name: &str, default: bool) -> Result<bool> {
    match node.word_attr(name)? {
        None => Ok(default),
        Some("1" | "true" | "on") => Ok(true),
        Some("0" | "false" | "off") => Ok(false),
        Some(_) => invalid("invalid Word settings boolean"),
    }
}
fn resolve_target(target: &str) -> Result<String> {
    if target.is_empty() || target.contains(['\\', ':', '%', '?', '#']) {
        return invalid("unsupported Word settings target");
    }
    let mut path = if target.starts_with('/') {
        Vec::new()
    } else {
        vec!["word"]
    };
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                path.pop()
                    .ok_or(Error::InvalidPackage("settings target escapes package"))?;
            }
            value => path.push(value),
        }
    }
    if path.is_empty() {
        return invalid("empty Word settings target");
    }
    Ok(path.join("/"))
}

struct Node {
    ns: String,
    name: String,
    attrs: BTreeMap<(String, String), String>,
    children: Vec<Node>,
    non_whitespace: bool,
}
impl Node {
    fn attr(&self, ns: &str, name: &str) -> Option<&str> {
        self.attrs
            .get(&(ns.to_owned(), name.to_owned()))
            .map(String::as_str)
    }
    fn word_attr(&self, name: &str) -> Result<Option<&str>> {
        let mut result = None;
        for ((ns, local), value) in &self.attrs {
            if local == name {
                if ns != &self.ns || result.is_some() {
                    return invalid("invalid Word settings attribute namespace");
                }
                result = Some(value.as_str());
            }
        }
        Ok(result)
    }
}
fn namespace(resolved: ResolveResult<'_>) -> Result<String> {
    match resolved {
        ResolveResult::Unbound => Ok(String::new()),
        ResolveResult::Bound(ns) => std::str::from_utf8(ns.as_ref())
            .map(str::to_owned)
            .map_err(|_| Error::InvalidPackage("non UTF-8 settings namespace")),
        ResolveResult::Unknown(_) => invalid("unbound settings XML prefix"),
    }
}
fn parse(bytes: &[u8]) -> Result<Node> {
    // Read only. This tree is never serialized back into the retained package.
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidPackage("settings XML is not UTF-8"))?;
    if bytes.iter().any(|b| matches!(b, 0..=8 | 11 | 12 | 14..=31)) {
        return invalid("settings XML has forbidden control characters");
    }
    let mut reader = NsReader::from_reader(bytes);
    reader.config_mut().check_comments = true;
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut declaration_seen = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|_| Error::InvalidPackage("malformed Word settings XML"))?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                if stack.len() >= 128 {
                    return invalid("Word settings XML nesting limit");
                }
                let node = read_node(&reader, &element)?;
                if empty {
                    append(node, &mut stack, &mut root)?;
                } else {
                    stack.push(node);
                }
            }
            Event::End(_) => {
                let node = stack
                    .pop()
                    .ok_or(Error::InvalidPackage("unexpected settings close tag"))?;
                append(node, &mut stack, &mut root)?;
            }
            Event::Text(text) => {
                let text = text
                    .decode()
                    .map_err(|_| Error::InvalidPackage("invalid settings text"))?;
                text_content(&text, &mut stack)?;
            }
            Event::CData(text) => {
                let text = text
                    .decode()
                    .map_err(|_| Error::InvalidPackage("invalid settings CDATA"))?;
                text_content(&text, &mut stack)?;
            }
            Event::GeneralRef(reference) => {
                let value = reference
                    .decode()
                    .map_err(|_| Error::InvalidPackage("invalid settings entity"))?;
                let escaped = format!("&{value};");
                let decoded = quick_xml::escape::unescape(&escaped)
                    .map_err(|_| Error::InvalidPackage("invalid settings entity"))?;
                text_content(&decoded, &mut stack)?;
            }
            Event::Decl(declaration) => {
                if declaration_seen
                    || root.is_some()
                    || !stack.is_empty()
                    || !matches!(
                        declaration.xml_version(),
                        Ok(quick_xml::XmlVersion::Explicit1_0)
                    )
                {
                    return invalid("invalid settings XML declaration");
                }
                declaration_seen = true;
            }
            Event::DocType(_) => return invalid("settings DOCTYPE is not permitted"),
            Event::Eof => break,
            _ => {}
        }
    }
    if !stack.is_empty() {
        return invalid("truncated Word settings XML");
    }
    root.ok_or(Error::InvalidPackage("missing Word settings XML root"))
}
fn read_node(
    reader: &NsReader<&[u8]>,
    element: &quick_xml::events::BytesStart<'_>,
) -> Result<Node> {
    let (resolved, local) = reader.resolver().resolve_element(element.name());
    let ns = namespace(resolved)?;
    let name = std::str::from_utf8(local.as_ref())
        .map_err(|_| Error::InvalidPackage("non UTF-8 settings name"))?
        .to_owned();
    let mut attrs = BTreeMap::new();
    for attr in element.attributes() {
        let attr = attr.map_err(|_| Error::InvalidPackage("malformed Word settings attribute"))?;
        if attr.value.contains(&b'<') {
            return invalid("invalid less-than in settings attribute");
        }
        let value = attr
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|_| Error::InvalidPackage("invalid Word settings attribute value"))?
            .into_owned();
        if value.chars().any(|c| !valid_xml_char(c)) {
            return invalid("invalid settings attribute character");
        }
        if attr.key.as_ref() == b"xmlns" || attr.key.as_ref().starts_with(b"xmlns:") {
            continue;
        }
        let (resolved, local) = reader.resolver().resolve_attribute(attr.key);
        let key = (
            namespace(resolved)?,
            std::str::from_utf8(local.as_ref())
                .map_err(|_| Error::InvalidPackage("invalid settings attribute name"))?
                .to_owned(),
        );
        if attrs.insert(key, value).is_some() {
            return invalid("duplicate Word settings attribute");
        }
    }
    Ok(Node {
        ns,
        name,
        attrs,
        children: Vec::new(),
        non_whitespace: false,
    })
}
fn append(node: Node, stack: &mut [Node], root: &mut Option<Node>) -> Result<()> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else if root.replace(node).is_some() {
        return invalid("multiple Word settings XML roots");
    }
    Ok(())
}
fn valid_xml_char(c: char) -> bool {
    matches!(c, '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}
fn text_content(text: &str, stack: &mut [Node]) -> Result<()> {
    if text.chars().any(|c| !valid_xml_char(c)) {
        return invalid("invalid settings text character");
    }
    if !text.trim().is_empty() {
        if let Some(node) = stack.last_mut() {
            node.non_whitespace = true;
        } else {
            return invalid("text outside Word settings XML root");
        }
    }
    Ok(())
}
fn invalid<T>(reason: &'static str) -> Result<T> {
    Err(Error::InvalidPackage(reason))
}

#[cfg(test)]
mod tests;
