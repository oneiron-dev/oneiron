//! Namespace-aware parsing for PPTX comment XML.
//! Entry: `Xml::parse_with_limits`.
//! Xml and Node remain defined in the parent module.

use super::*;

impl<'a> Xml<'a> {
    pub(in crate::pptx_comments) fn parse_with_limits(
        text: &'a str,
        limits: &PptxCommentLimits,
    ) -> PatchResult<Self> {
        if text.len() > limits.max_xml_bytes || text.chars().any(|c| !valid_char(c)) {
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
                    let parsed = Xml::parse_with_limits(&declaration, limits)?;
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
                if raw.len() > limits.max_xml_attributes {
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
            if namespaces.len() > limits.max_xml_namespaces {
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
            // Count empty elements as a depth level too: an empty child is
            // still nested even though it never enters the open-element stack.
            if stack.len() >= limits.max_xml_depth || nodes.len() >= limits.max_xml_nodes {
                return Err(PptxError::InvalidXml);
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
        }
        if !stack.is_empty() || roots != 1 {
            return Err(PptxError::InvalidXml);
        }
        Ok(Self { text, nodes })
    }
}

pub(super) fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while bytes
        .get(*pos)
        .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
    {
        *pos += 1;
    }
}

pub(super) fn read_name<'a>(text: &'a str, pos: &mut usize) -> PatchResult<&'a str> {
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

pub(super) fn expanded(
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

pub(super) fn unescape(text: &str) -> PatchResult<String> {
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
