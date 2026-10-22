//! PPTX comment XML spans, queries and surgery.
//! Entry: `Xml`.
//! parse owns parsing; this module owns the node types and query methods.
//!
//! Namespace-aware XML spans for surgical edits. Unknown markup stays byte-identical.
//! DTDs/entities and malformed XML fail closed; no resource is fetched. Depth
//! and counts are observations: the parse reserves memory as it grows.

mod parse;

use super::model::{Codec, PatchResult, PptxError};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

#[derive(Debug, Clone)]
pub(super) struct Attr {
    pub ns: String,
    pub name: String,
    pub value: String,
    pub span: Range<usize>,
}
#[derive(Debug, Clone)]
pub(super) struct Node {
    pub ns: String,
    pub name: String,
    pub qname: String,
    pub attrs: Vec<Attr>,
    pub parent: Option<usize>,
    pub start: usize,
    pub open_end: usize,
    pub close_start: usize,
    pub end: usize,
    pub empty: bool,
    children: Vec<usize>,
    namespaces: std::rc::Rc<BTreeMap<String, String>>,
}
impl Node {
    pub(super) fn is(&self, ns: &str, name: &str) -> bool {
        self.ns == ns && self.name == name
    }
    pub(super) fn attr(&self, name: &str) -> Option<&str> {
        self.attr_ns("", name)
    }
    pub(super) fn attr_ns(&self, ns: &str, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.ns == ns && a.name == name)
            .map(|a| a.value.as_str())
    }
    pub(super) fn required(&self, name: &str) -> PatchResult<&str> {
        self.attr(name).ok_or(PptxError::InvalidXml)
    }
}
#[derive(Debug)]
pub(super) struct Xml<'a> {
    pub text: &'a str,
    pub nodes: Vec<Node>,
}
impl Xml<'_> {
    pub(super) fn root(&self, ns: &str, name: &str) -> PatchResult<usize> {
        if self.nodes[0].is(ns, name) {
            Ok(0)
        } else {
            Err(PptxError::InvalidXml)
        }
    }
    pub(super) fn children(&self, parent: usize, ns: &str, name: &str) -> Vec<usize> {
        self.nodes[parent]
            .children
            .iter()
            .copied()
            .filter(|i| self.nodes[*i].is(ns, name))
            .collect()
    }
    pub(super) fn child(&self, parent: usize, ns: &str, name: &str) -> PatchResult<Option<usize>> {
        let children = self.children(parent, ns, name);
        match children.as_slice() {
            [] => Ok(None),
            [id] => Ok(Some(*id)),
            _ => Err(PptxError::AmbiguousAnchor),
        }
    }
    pub(super) fn descendants(&self, parent: usize, ns: &str, name: &str) -> Vec<usize> {
        let p = &self.nodes[parent];
        self.nodes
            .iter()
            .enumerate()
            .skip(parent + 1)
            .take_while(|(_, n)| n.start < p.end)
            .filter_map(|(i, n)| n.is(ns, name).then_some(i))
            .collect()
    }
    pub(super) fn append(&self, parent: usize, fragment: &str) -> String {
        let n = &self.nodes[parent];
        if n.empty {
            replace(
                self.text,
                n.open_end - 2..n.open_end,
                &format!(">{fragment}</{}>", n.qname),
            )
        } else {
            replace(self.text, n.close_start..n.close_start, fragment)
        }
    }
    pub(super) fn fingerprint(&self, node: usize) -> [u8; 32] {
        self.fingerprint_with(node, &|_, _| false)
    }

    /// Slide content excludes only the two Office extensions written by the
    /// review route: the slide creationId and its modern-comment relation.
    /// Unknown extensions, backgrounds, and other slide content still drift.
    pub(super) fn slide_content_fingerprint(&self, root: usize) -> [u8; 32] {
        self.fingerprint_with(root, &|xml, node| xml.is_review_metadata(node))
    }

    fn is_review_metadata(&self, node: usize) -> bool {
        use super::model::{COMMENT_EXT, P, SLIDE_ID_EXT};
        let n = &self.nodes[node];
        if n.is(P, "ext") {
            let Some(list) = n.parent else {
                return false;
            };
            let Some(owner) = self.nodes[list].parent else {
                return false;
            };
            if !self.nodes[list].is(P, "extLst") {
                return false;
            }
            return (self.nodes[owner].is(P, "sld") && n.attr("uri") == Some(COMMENT_EXT))
                || (self.nodes[owner].is(P, "cSld") && n.attr("uri") == Some(SLIDE_ID_EXT));
        }
        let Some(owner) = n.parent else {
            return false;
        };
        // The writer may create extLst solely for review metadata. An empty
        // wrapper must not change the normalized content fingerprint.
        if !n.is(P, "extLst")
            || !n.attrs.is_empty()
            || !(self.nodes[owner].is(P, "sld") || self.nodes[owner].is(P, "cSld"))
        {
            return false;
        }
        let mut at = n.open_end;
        for &child in &n.children {
            let item = &self.nodes[child];
            if !self.text[at..item.start].trim().is_empty() || !self.is_review_metadata(child) {
                return false;
            }
            at = item.end;
        }
        n.empty || self.text[at..n.close_start].trim().is_empty()
    }

    /// The walk keeps its open elements on a heap stack, not the call
    /// stack, so a part nests as deep as its memory allows (FIX 8596).
    fn fingerprint_with(&self, node: usize, skip: &impl Fn(&Xml<'_>, usize) -> bool) -> [u8; 32] {
        fn field(hash: &mut blake3::Hasher, text: &str) {
            hash.update(&(text.len() as u64).to_le_bytes());
            hash.update(text.as_bytes());
        }
        fn header(xml: &Xml<'_>, node: usize, hash: &mut blake3::Hasher) {
            let n = &xml.nodes[node];
            field(hash, &n.ns);
            field(hash, &n.name);
            let mut attrs: Vec<_> = n.attrs.iter().collect();
            attrs.sort_by_key(|a| (&a.ns, &a.name));
            for a in attrs {
                field(hash, &a.ns);
                field(hash, &a.name);
                field(hash, &a.value);
            }
            hash.update(&[0]);
        }
        let mut hash = blake3::Hasher::new();
        // Each open element: its node, its next child, and where the text
        // before that child starts.
        let mut open: Vec<(usize, usize, usize)> = Vec::new();
        if !skip(self, node) {
            header(self, node, &mut hash);
            open.push((node, 0, self.nodes[node].open_end));
        }
        while let Some(&(id, next, at)) = open.last() {
            let n = &self.nodes[id];
            if let Some(&child) = n.children.get(next) {
                let c = &self.nodes[child];
                let text = &self.text[at..c.start];
                if !text.trim().is_empty() {
                    field(&mut hash, text);
                }
                if let Some(top) = open.last_mut() {
                    *top = (id, next + 1, c.end);
                }
                if !skip(self, child) {
                    header(self, child, &mut hash);
                    open.push((child, 0, c.open_end));
                }
            } else {
                if !n.empty {
                    let text = &self.text[at..n.close_start];
                    if !text.trim().is_empty() {
                        field(&mut hash, text);
                    }
                }
                hash.update(&[1]);
                open.pop();
            }
        }
        *hash.finalize().as_bytes()
    }

    pub(super) fn set_attr(&self, node: usize, name: &str, value: &str) -> PatchResult<String> {
        let n = &self.nodes[node];
        let value = escape(value)?;
        if let Some(a) = n.attrs.iter().find(|a| a.ns.is_empty() && a.name == name) {
            Ok(replace(self.text, a.span.clone(), &value))
        } else {
            let at = n.open_end - if n.empty { 2 } else { 1 };
            Ok(replace(self.text, at..at, &format!(" {name}=\"{value}\"")))
        }
    }
}
pub(super) fn replace(text: &str, range: Range<usize>, value: &str) -> String {
    let mut out = String::with_capacity(text.len() + value.len());
    out.push_str(&text[..range.start]);
    out.push_str(value);
    out.push_str(&text[range.end..]);
    out
}
fn valid_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{d7ff}').contains(&c)
        || ('\u{e000}'..='\u{fffd}').contains(&c)
        || c >= '\u{10000}'
}
pub(super) fn escape(text: &str) -> PatchResult<String> {
    if text.chars().any(|c| !valid_char(c)) {
        return Err(PptxError::InvalidPatch);
    }
    Ok(text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('\r', "&#13;")
        .replace('\n', "&#10;")
        .replace('\t', "&#9;"))
}
