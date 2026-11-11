//! Namespace-aware WebDAV multistatus decoding for the pack's CalDAV wire
//! (fix list row 16307): no DTD and no external entities. Each element keeps
//! which of the two namespaces read here it is in (none for any other), its
//! local name, text and attributes. A document holds at most a million
//! elements.

use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

pub(super) const DAV: &str = "DAV:";
pub(super) const CAL: &str = "urn:ietf:params:xml:ns:caldav";

/// The most elements one document holds.
const MAX_NODES: usize = 1_000_000;

/// The namespaces this parser tells apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Dav,
    Cal,
}

/// Which namespace `uri` is, if one read here. Each element keeps this, not
/// its URI: a long URI bound once and used by many elements costs nothing
/// per element.
fn namespace(uri: &str) -> Option<Namespace> {
    match uri {
        DAV => Some(Namespace::Dav),
        CAL => Some(Namespace::Cal),
        _ => None,
    }
}

/// One element of a multistatus document.
#[derive(Default)]
pub(super) struct Node {
    ns: Option<Namespace>,
    name: String,
    pub(super) text: String,
    /// Its attributes by local name, their values as written.
    attributes: Vec<(String, String)>,
    children: Vec<Node>,
}

/// A provider controls how deep its multistatus nests, so a tree is torn
/// down one node at a time, never one stack frame per level: the default drop
/// would recurse through `children`, and a deep enough document, well inside
/// the byte limit, would overflow the stack. A parse that fails mid-document
/// drops its open stack through the same path.
impl Drop for Node {
    fn drop(&mut self) {
        let mut pending = std::mem::take(&mut self.children);
        while let Some(mut node) = pending.pop() {
            pending.append(&mut node.children);
        }
    }
}

impl Node {
    pub(super) fn child(&self, ns: &str, name: &str) -> Option<&Self> {
        let ns = namespace(ns)?;
        self.children
            .iter()
            .find(|node| node.ns == Some(ns) && node.name == name)
    }

    pub(super) fn children<'a>(
        &'a self,
        ns: &str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a Self> {
        let ns = namespace(ns);
        self.children
            .iter()
            .filter(move |node| ns.is_some() && node.ns == ns && node.name == name)
    }

    /// The property `ns:name` of a `response`, from a `propstat` whose
    /// status is 200.
    pub(super) fn property(&self, ns: &str, name: &str) -> Option<&Self> {
        self.children(DAV, "propstat")
            .filter(|propstat| {
                propstat
                    .child(DAV, "status")
                    .is_some_and(|status| status_code(&status.text) == Some(200))
            })
            .find_map(|propstat| propstat.child(DAV, "prop")?.child(ns, name))
    }

    /// The value of the attribute named `name`.
    pub(super) fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The code of a DAV status line (`HTTP/1.1 404 Not Found`).
pub(super) fn status_code(line: &str) -> Option<u16> {
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Parses a `multistatus` document.
///
/// # Errors
///
/// Text that is not UTF-8, malformed XML, a DTD, an element with no
/// namespace, or a root other than `DAV:multistatus`.
pub(super) fn parse(bytes: &[u8]) -> Result<Node, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "DAV XML is not UTF-8")?;
    let mut reader = NsReader::from_str(text);
    let mut stack = vec![Node::default()];
    let mut nodes = 0_usize;
    loop {
        let event = reader.read_event().map_err(|_| "malformed DAV XML")?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                nodes += 1;
                if nodes > MAX_NODES {
                    return Err("DAV XML holds too many elements");
                }
                let (ns, local) = reader.resolver().resolve_element(tag.name());
                let ns = match ns {
                    ResolveResult::Bound(ns) => namespace(ns.as_ref()),
                    _ => return Err("DAV XML element has no namespace"),
                };
                let attributes = tag
                    .attributes()
                    .filter_map(std::result::Result::ok)
                    .map(|attribute| {
                        (
                            attribute.key.local_name().as_ref().to_owned(),
                            attribute.value.into_owned(),
                        )
                    })
                    .collect();
                let node = Node {
                    ns,
                    name: local.as_ref().to_owned(),
                    text: String::new(),
                    attributes,
                    children: Vec::new(),
                };
                if empty {
                    stack
                        .last_mut()
                        .ok_or("DAV XML nesting")?
                        .children
                        .push(node);
                } else {
                    stack.push(node);
                }
            }
            Event::Text(text) => {
                stack.last_mut().ok_or("DAV XML nesting")?.text.push_str(
                    &quick_xml::escape::unescape(text.as_ref()).map_err(|_| "DAV XML entity")?,
                );
            }
            Event::CData(text) => stack
                .last_mut()
                .ok_or("DAV XML nesting")?
                .text
                .push_str(text.as_ref()),
            Event::GeneralRef(reference) => {
                let value = reference
                    .resolve_char_ref()
                    .map_err(|_| "DAV XML entity")?
                    .map(String::from)
                    .or_else(|| {
                        quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                            .map(str::to_owned)
                    })
                    .ok_or("DAV XML entity")?;
                stack
                    .last_mut()
                    .ok_or("DAV XML nesting")?
                    .text
                    .push_str(&value);
            }
            Event::End(_) => {
                if stack.len() <= 1 {
                    return Err("DAV XML nesting");
                }
                let node = stack.pop().ok_or("DAV XML nesting")?;
                stack
                    .last_mut()
                    .ok_or("DAV XML nesting")?
                    .children
                    .push(node);
            }
            Event::DocType(_) => return Err("DAV XML DTD is not supported"),
            Event::Eof => {
                if stack.len() != 1 {
                    return Err("DAV XML nesting");
                }
                let mut root = stack.pop().ok_or("DAV XML nesting")?;
                if root.children.len() != 1 {
                    return Err("DAV XML root");
                }
                let document = root.children.pop().ok_or("DAV XML root")?;
                if document.ns != Some(Namespace::Dav) || document.name != "multistatus" {
                    return Err("DAV response is not multistatus");
                }
                return Ok(document);
            }
            _ => {}
        }
    }
}

/// `text` escaped for an XML element's content.
pub(super) fn escape(text: &str) -> String {
    quick_xml::escape::escape(text).into_owned()
}
