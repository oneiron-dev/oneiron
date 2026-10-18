//! Namespace-aware DAV multistatus decoding. No DTD or external entities.
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

pub(super) const DAV: &str = "DAV:";
pub(super) const CAL: &str = "urn:ietf:params:xml:ns:caldav";

#[derive(Default)]
pub(super) struct Node {
    ns: String,
    name: String,
    pub text: String,
    children: Vec<Node>,
}

impl Node {
    pub(super) fn child(&self, ns: &str, name: &str) -> Option<&Self> {
        self.children.iter().find(|n| n.ns == ns && n.name == name)
    }
    pub(super) fn children<'a>(&'a self, ns: &'a str, name: &'a str) -> impl Iterator<Item = &'a Self> {
        self.children.iter().filter(move |n| n.ns == ns && n.name == name)
    }
    pub(super) fn property(&self, ns: &str, name: &str) -> Option<&Self> {
        self.children(DAV, "propstat").filter(|p| {
            p.child(DAV, "status").is_some_and(|s| s.text.split_whitespace().nth(1) == Some("200"))
        }).find_map(|p| p.child(DAV, "prop")?.child(ns, name))
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Node, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "DAV XML is not UTF-8")?;
    let mut reader = NsReader::from_str(text);
    let mut stack = vec![Node::default()];
    loop {
        let event = reader.read_event().map_err(|_| "malformed DAV XML")?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                let (ns, local) = reader.resolver().resolve_element(tag.name());
                let ns = match ns {
                    ResolveResult::Bound(ns) => ns.as_ref().to_owned(),
                    _ => return Err("DAV XML element has no namespace"),
                };
                let node = Node { ns, name: local.as_ref().to_owned(), ..Default::default() };
                if empty {
                    stack.last_mut().ok_or("DAV XML nesting")?.children.push(node);
                } else {
                    stack.push(node);
                }
            }
            Event::Text(text) => {
                stack.last_mut().ok_or("DAV XML nesting")?.text.push_str(
                    &quick_xml::escape::unescape(text.as_ref()).map_err(|_| "DAV XML entity")?,
                );
            }
            Event::CData(text) => stack.last_mut().ok_or("DAV XML nesting")?.text.push_str(text.as_ref()),
            Event::GeneralRef(reference) => {
                let value = reference.resolve_char_ref().map_err(|_| "DAV XML entity")?
                    .map(|ch| ch.to_string()).or_else(|| {
                        quick_xml::escape::resolve_predefined_entity(reference.as_ref()).map(str::to_owned)
                    }).ok_or("DAV XML entity")?;
                stack.last_mut().ok_or("DAV XML nesting")?.text.push_str(&value);
            }
            Event::End(_) => {
                if stack.len() <= 1 { return Err("DAV XML nesting"); }
                let node = stack.pop().ok_or("DAV XML nesting")?;
                stack.last_mut().ok_or("DAV XML nesting")?.children.push(node);
            }
            Event::DocType(_) => return Err("DAV XML DTD is not supported"),
            Event::Eof => {
                if stack.len() != 1 { return Err("DAV XML nesting"); }
                let mut root = stack.pop().ok_or("DAV XML nesting")?;
                if root.children.len() != 1 { return Err("DAV XML root"); }
                let document = root.children.pop().ok_or("DAV XML root")?;
                if document.ns != DAV || document.name != "multistatus" { return Err("DAV response is not multistatus"); }
                return Ok(document);
            }
            _ => {}
        }
    }
}

pub(super) fn escape(text: &str) -> String {
    quick_xml::escape::escape(text).into_owned()
}
