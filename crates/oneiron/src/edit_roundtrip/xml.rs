//! Namespace-aware OPC and worksheet XML reads for the edit gate.

use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

const SHEET_NS: &[u8] = b"http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const REL_ATTR_NS: &[u8] = b"http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const PACKAGE_REL_NS: &[u8] = b"http://schemas.openxmlformats.org/package/2006/relationships";
const CONTENT_NS: &[u8] = b"http://schemas.openxmlformats.org/package/2006/content-types";

pub(super) struct Element {
    name: String,
    namespace: Option<String>,
    attrs: Vec<(String, Option<String>, String)>,
}

impl Element {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, ns, _)| key == name && ns.is_none())
            .map(|(_, _, value)| value.as_str())
    }
    fn relationship_id(&self) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, ns, _)| {
                key == "id" && ns.as_deref().is_some_and(|ns| ns.as_bytes() == REL_ATTR_NS)
            })
            .map(|(_, _, value)| value.as_str())
    }
    fn is(&self, name: &str, namespace: &[u8]) -> bool {
        self.name == name
            && self
                .namespace
                .as_deref()
                .is_none_or(|ns| ns.as_bytes() == namespace)
    }
}

fn namespace(result: ResolveResult<'_>) -> std::result::Result<Option<String>, &'static str> {
    match result {
        ResolveResult::Bound(ns) => Ok(Some(ns.as_ref().to_owned())),
        ResolveResult::Unbound => Ok(None),
        ResolveResult::Unknown(_) => Err("unbound XML prefix"),
    }
}

fn element(
    reader: &NsReader<&[u8]>,
    tag: &BytesStart<'_>,
) -> std::result::Result<Element, &'static str> {
    let (ns, local) = reader.resolver().resolve_element(tag.name());
    let name = local.as_ref().to_owned();
    let element_namespace = namespace(ns)?;
    let mut attrs = Vec::new();
    for attr in tag.attributes() {
        let attr = attr.map_err(|_| "invalid XML attribute")?;
        let (ns, local) = reader.resolver().resolve_attribute(attr.key);
        let key = local.as_ref().to_owned();
        let ns = if attr.key.as_ref() == "xmlns" || attr.key.as_ref().starts_with("xmlns:") {
            None
        } else {
            namespace(ns)?
        };
        let value = attr
            .normalized_value(quick_xml::XmlVersion::default())
            .map_err(|_| "invalid XML attribute value")?
            .into_owned();
        attrs.push((key, ns, value));
    }
    Ok(Element {
        name,
        namespace: element_namespace,
        attrs,
    })
}

pub(super) fn elements(xml: &[u8]) -> std::result::Result<Vec<Element>, &'static str> {
    let xml = std::str::from_utf8(xml).map_err(|_| "XML is not UTF-8")?;
    let mut reader = NsReader::from_str(xml);
    let mut out = Vec::new();
    loop {
        match reader.read_event().map_err(|_| "malformed XML")? {
            Event::Start(tag) | Event::Empty(tag) => out.push(element(&reader, &tag)?),
            Event::DocType(_) => return Err("XML DTD is not supported"),
            Event::Eof => return Ok(out),
            _ => {}
        }
    }
}

pub(super) fn external_refs(xml: &[u8]) -> std::result::Result<Vec<String>, &'static str> {
    elements(xml)?
        .into_iter()
        .filter(|e| e.is("externalReference", SHEET_NS))
        .map(|e| {
            e.relationship_id()
                .map(str::to_owned)
                .ok_or("externalReference has no relationship id")
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ExternalRelationship {
    pub id: String,
    pub target: String,
    pub kind: String,
    pub mode: Option<String>,
}

pub(super) fn external_relationships(
    xml: &[u8],
) -> std::result::Result<Vec<ExternalRelationship>, &'static str> {
    elements(xml)?
        .into_iter()
        .filter(|e| {
            e.is("Relationship", PACKAGE_REL_NS)
                && e.attribute("Type")
                    .is_some_and(|t| t.ends_with("/externalLink"))
        })
        .map(|e| {
            Ok(ExternalRelationship {
                id: e
                    .attribute("Id")
                    .ok_or("externalLink has no id")?
                    .to_owned(),
                target: e
                    .attribute("Target")
                    .ok_or("externalLink has no target")?
                    .to_owned(),
                kind: e
                    .attribute("Type")
                    .ok_or("externalLink has no type")?
                    .to_owned(),
                mode: e.attribute("TargetMode").map(str::to_owned),
            })
        })
        .collect()
}

pub(super) fn content_type(
    xml: &[u8],
    part: &str,
) -> std::result::Result<Option<String>, &'static str> {
    let elements = elements(xml)?;
    let override_name = format!("/{part}");
    if let Some(item) = elements.iter().find(|e| {
        e.is("Override", CONTENT_NS) && e.attribute("PartName") == Some(override_name.as_str())
    }) {
        return Ok(item.attribute("ContentType").map(str::to_owned));
    }
    let ext = part.rsplit_once('.').map_or("", |(_, ext)| ext);
    Ok(elements
        .iter()
        .find(|e| e.is("Default", CONTENT_NS) && e.attribute("Extension") == Some(ext))
        .and_then(|e| e.attribute("ContentType"))
        .map(str::to_owned))
}

/// Read decoded formula text, including namespace-qualified `<f>` and XML
/// entities. The validator refuses parse errors rather than trusting a scan.
pub(super) fn formulas(xml: &str) -> std::result::Result<Vec<String>, &'static str> {
    let mut reader = NsReader::from_str(xml);
    let mut out = Vec::new();
    let mut formula: Option<String> = None;
    loop {
        match reader.read_event().map_err(|_| "malformed worksheet XML")? {
            Event::Start(tag) => {
                let elem = element(&reader, &tag)?;
                if elem.is("f", SHEET_NS) {
                    formula = Some(String::new());
                }
            }
            Event::Text(text) => {
                if let Some(f) = formula.as_mut() {
                    f.push_str(&unescape(text.as_ref()).map_err(|_| "invalid formula XML entity")?);
                }
            }
            Event::CData(text) => {
                if let Some(f) = formula.as_mut() {
                    f.push_str(text.as_ref());
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(f) = formula.as_mut() {
                    if let Some(ch) = reference
                        .resolve_char_ref()
                        .map_err(|_| "invalid formula XML entity")?
                    {
                        f.push(ch);
                    } else if let Some(value) =
                        quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                    {
                        f.push_str(value);
                    } else {
                        return Err("unsupported formula XML entity");
                    }
                }
            }
            Event::End(tag) => {
                if tag.local_name().as_ref() == "f"
                    && let Some(f) = formula.take()
                    && !f.is_empty()
                {
                    out.push(f);
                }
            }
            Event::DocType(_) => return Err("worksheet DTD is not supported"),
            Event::Eof => return Ok(out),
            _ => {}
        }
    }
}
