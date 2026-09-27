//! Namespace-aware XML spans for surgical edits. Unknown markup stays byte-identical.
//! DTDs/entities, excessive depth and malformed XML fail closed; no resource is fetched.

use super::package::{PatchResult, PptxError};
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
impl<'a> Xml<'a> {
    pub(super) fn parse(text: &'a str) -> PatchResult<Self> {
        if text.len() > 32 * 1024 * 1024 || text.chars().any(|c| !valid_char(c)) {
            return Err(PptxError::InvalidXml);
        }
        let bytes = text.as_bytes();
        let mut nodes: Vec<Node> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        let mut pos = usize::from(text.starts_with('\u{feff}')) * 3;
        let mut roots = 0;
        while pos < bytes.len() {
            if bytes[pos] != b'<' {
                let end = text[pos..].find('<').map_or(bytes.len(), |n| pos + n);
                let value = unescape(&text[pos..end])?;
                if (stack.is_empty() && !value.trim().is_empty()) || text[pos..end].contains("]]>")
                {
                    return Err(PptxError::InvalidXml);
                }
                pos = end;
                continue;
            }
            if text[pos..].starts_with("<!--") {
                let end = text[pos + 4..].find("-->").ok_or(PptxError::InvalidXml)? + pos + 4;
                if text[pos + 4..end].contains("--") {
                    return Err(PptxError::InvalidXml);
                }
                pos = end + 3;
                continue;
            }
            if text[pos..].starts_with("<![CDATA[") {
                if stack.is_empty() {
                    return Err(PptxError::InvalidXml);
                }
                pos = text[pos + 9..].find("]]>").ok_or(PptxError::InvalidXml)? + pos + 12;
                continue;
            }
            if text[pos..].starts_with("<?") {
                let end = text[pos + 2..].find("?>").ok_or(PptxError::InvalidXml)? + pos + 2;
                let mut target_end = pos + 2;
                let target = read_name(text, &mut target_end)?;
                if target.eq_ignore_ascii_case("xml") {
                    if target != "xml" || pos != usize::from(text.starts_with('\u{feff}')) * 3 {
                        return Err(PptxError::InvalidXml);
                    }
                    let declaration = format!("<declaration{}/>", &text[target_end..end]);
                    let parsed = Xml::parse(&declaration)?;
                    let n = &parsed.nodes[0];
                    if n.attr("version") != Some("1.0")
                        || n.attrs.first().is_none_or(|a| a.name != "version")
                        || n.attr("encoding")
                            .is_some_and(|s| !s.eq_ignore_ascii_case("utf-8"))
                        || n.attr("standalone")
                            .is_some_and(|s| s != "yes" && s != "no")
                        || n.attrs.iter().any(|a| {
                            !a.ns.is_empty()
                                || !matches!(a.name.as_str(), "version" | "encoding" | "standalone")
                        })
                    {
                        return Err(PptxError::InvalidXml);
                    }
                }
                pos = end + 2;
                continue;
            }
            if text[pos..].starts_with("<!") {
                return Err(PptxError::InvalidXml);
            }
            let start = pos;
            pos += 1;
            if bytes.get(pos) == Some(&b'/') {
                pos += 1;
                let qname = read_name(text, &mut pos)?;
                skip_ws(bytes, &mut pos);
                if bytes.get(pos) != Some(&b'>') {
                    return Err(PptxError::InvalidXml);
                }
                let index = stack.pop().ok_or(PptxError::InvalidXml)?;
                if nodes[index].qname != qname {
                    return Err(PptxError::InvalidXml);
                }
                nodes[index].close_start = start;
                nodes[index].end = pos + 1;
                pos += 1;
                continue;
            }
            let qname = read_name(text, &mut pos)?.to_owned();
            let mut raw = Vec::new();
            loop {
                let previous = pos;
                skip_ws(bytes, &mut pos);
                if matches!(bytes.get(pos), Some(b'>' | b'/')) {
                    break;
                }
                if pos == previous {
                    return Err(PptxError::InvalidXml);
                }
                let name = read_name(text, &mut pos)?.to_owned();
                skip_ws(bytes, &mut pos);
                if bytes.get(pos) != Some(&b'=') {
                    return Err(PptxError::InvalidXml);
                }
                pos += 1;
                skip_ws(bytes, &mut pos);
                let quote = *bytes.get(pos).ok_or(PptxError::InvalidXml)?;
                if quote != b'\'' && quote != b'"' {
                    return Err(PptxError::InvalidXml);
                }
                pos += 1;
                let begin = pos;
                while bytes.get(pos).is_some_and(|b| *b != quote) {
                    if bytes[pos] == b'<' {
                        return Err(PptxError::InvalidXml);
                    }
                    pos += 1;
                }
                if pos == bytes.len() {
                    return Err(PptxError::InvalidXml);
                }
                raw.push((name, unescape(&text[begin..pos])?, begin..pos));
                pos += 1;
                if raw.len() > 4096 {
                    return Err(PptxError::InvalidXml);
                }
            }
            let empty = bytes.get(pos) == Some(&b'/');
            if empty {
                pos += 1;
            }
            if bytes.get(pos) != Some(&b'>') {
                return Err(PptxError::InvalidXml);
            }
            pos += 1;
            let parent = stack.last().copied();
            let mut namespaces = parent.map_or_else(
                || {
                    std::rc::Rc::new(BTreeMap::from([(
                        "xml".into(),
                        "http://www.w3.org/XML/1998/namespace".into(),
                    )]))
                },
                |i| nodes[i].namespaces.clone(),
            );
            let mut raw_names = BTreeSet::new();
            for (name, value, _) in &raw {
                if !raw_names.insert(name) {
                    return Err(PptxError::InvalidXml);
                }
                if name == "xmlns" {
                    std::rc::Rc::make_mut(&mut namespaces).insert(String::new(), value.clone());
                } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                    if prefix == "xmlns"
                        || (prefix == "xml" && value != "http://www.w3.org/XML/1998/namespace")
                        || value.is_empty()
                    {
                        return Err(PptxError::InvalidXml);
                    }
                    std::rc::Rc::make_mut(&mut namespaces).insert(prefix.into(), value.clone());
                }
            }
            if namespaces.len() > 256 {
                return Err(PptxError::InvalidXml);
            }
            let (ns, name) = expanded(&qname, &namespaces, false)?;
            let mut attrs = Vec::new();
            let mut expanded_names = BTreeSet::new();
            for (qname, value, span) in raw {
                if qname == "xmlns" || qname.starts_with("xmlns:") {
                    continue;
                }
                let (ns, name) = expanded(&qname, &namespaces, true)?;
                if !expanded_names.insert((ns.clone(), name.clone())) {
                    return Err(PptxError::InvalidXml);
                }
                attrs.push(Attr {
                    ns,
                    name,
                    value,
                    span,
                });
            }
            if parent.is_none() {
                roots += 1;
                if roots != 1 {
                    return Err(PptxError::InvalidXml);
                }
            }
            let index = nodes.len();
            nodes.push(Node {
                ns,
                name,
                qname,
                attrs,
                parent,
                start,
                open_end: pos,
                close_start: pos,
                end: pos,
                empty,
                children: Vec::new(),
                namespaces,
            });
            if let Some(parent) = parent {
                nodes[parent].children.push(index);
            }
            if !empty {
                stack.push(index);
            }
            if stack.len() > 256 || nodes.len() > 500_000 {
                return Err(PptxError::InvalidXml);
            }
        }
        if !stack.is_empty() || roots != 1 {
            return Err(PptxError::InvalidXml);
        }
        Ok(Self { text, nodes })
    }
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
        use super::package::{COMMENT_EXT, P, SLIDE_ID_EXT};
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

    fn fingerprint_with(&self, node: usize, skip: &impl Fn(&Xml<'_>, usize) -> bool) -> [u8; 32] {
        fn field(hash: &mut blake3::Hasher, text: &str) {
            hash.update(&(text.len() as u64).to_le_bytes());
            hash.update(text.as_bytes());
        }
        fn visit(
            xml: &Xml<'_>,
            node: usize,
            hash: &mut blake3::Hasher,
            skip: &impl Fn(&Xml<'_>, usize) -> bool,
        ) {
            if skip(xml, node) {
                return;
            }
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
            let mut at = n.open_end;
            for &i in &n.children {
                let child = &xml.nodes[i];
                let text = &xml.text[at..child.start];
                if !text.trim().is_empty() {
                    field(hash, text);
                }
                visit(xml, i, hash, skip);
                at = child.end;
            }
            if !n.empty {
                let text = &xml.text[at..n.close_start];
                if !text.trim().is_empty() {
                    field(hash, text);
                }
            }
            hash.update(&[1]);
        }
        let mut hash = blake3::Hasher::new();
        visit(self, node, &mut hash, skip);
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
fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while bytes
        .get(*pos)
        .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
    {
        *pos += 1;
    }
}
fn read_name<'a>(text: &'a str, pos: &mut usize) -> PatchResult<&'a str> {
    let start = *pos;
    let bytes = text.as_bytes();
    if !bytes
        .get(start)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return Err(PptxError::InvalidXml);
    }
    while bytes
        .get(*pos)
        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        *pos += 1;
    }
    let name = &text[start..*pos];
    if name.matches(':').count() > 1 || name.ends_with(':') {
        return Err(PptxError::InvalidXml);
    }
    Ok(name)
}
fn expanded(
    qname: &str,
    map: &BTreeMap<String, String>,
    attr: bool,
) -> PatchResult<(String, String)> {
    if let Some((prefix, name)) = qname.split_once(':') {
        Ok((
            map.get(prefix).ok_or(PptxError::InvalidXml)?.clone(),
            name.into(),
        ))
    } else {
        Ok((
            if attr {
                String::new()
            } else {
                map.get("").cloned().unwrap_or_default()
            },
            qname.into(),
        ))
    }
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
fn unescape(text: &str) -> PatchResult<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        let end = rest.find(';').ok_or(PptxError::InvalidXml)?;
        let entity = &rest[..end];
        let c = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let num = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(dec) = entity.strip_prefix('#') {
                    dec.parse().ok()
                } else {
                    None
                };
                num.and_then(char::from_u32)
                    .filter(|c| valid_char(*c))
                    .ok_or(PptxError::InvalidXml)?
            }
        };
        out.push(c);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}
