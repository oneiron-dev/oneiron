//! The calendar host's DAV parser and strict successful-property selection.
pub(super) use oneiron::mail_pack::dav_xml::{CAL, DAV, Node, escape, parse_unbounded as parse};

pub(super) fn property<'a>(node: &'a Node, ns: &str, name: &str) -> Option<&'a Node> {
    node.children(DAV, "propstat")
        .filter(|p| {
            p.child(DAV, "status")
                .is_some_and(|s| s.text.split_whitespace().nth(1) == Some("200"))
        })
        .find_map(|p| p.child(DAV, "prop")?.child(ns, name))
}
