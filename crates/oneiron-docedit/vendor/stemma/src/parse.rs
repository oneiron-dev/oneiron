// Copyright (c) 2026 Stemma. Licensed under Apache-2.0.
// Oneiron fork: selected stateless engine components; see ../PROVENANCE.md.
use std::io::Cursor;
use quick_xml::{Reader, events::Event};

pub(crate) fn parse(bytes: &[u8]) -> Result<xmltree::Element, String> {
    ensure_xml_depth_within_limit(bytes, 128)?;
    xmltree::Element::parse(bytes).map_err(|error| error.to_string())
}

fn ensure_xml_depth_within_limit(bytes: &[u8], limit: usize) -> Result<(), String> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    let mut buf = Vec::new();
    let mut depth = 0usize;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(_)) => {
                depth += 1;
                if depth > limit {
                    return Err(format!("XML nesting exceeds {limit}: {depth}"));
                }
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Empty(_)) => {
                let empty_depth = depth + 1;
                if empty_depth > limit {
                    return Err(format!("XML nesting exceeds {limit}: {empty_depth}"));
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(error.to_string()),
            Ok(Event::DocType(_)) => return Err("DOCTYPE is not permitted".to_owned()),
            _ => {}
        }
        buf.clear();
    }

    Ok(())
}

/// Locate direct body paragraphs without normalizing any XML bytes.
pub fn body_paragraph_ranges(bytes: &[u8]) -> Result<Vec<std::ops::Range<usize>>, String> {
    ensure_xml_depth_within_limit(bytes, 128)?;
    let mut reader = Reader::from_reader(bytes);
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut ranges = Vec::new();
    let mut paragraph_start = None;
    loop {
        let start = reader.buffer_position() as usize;
        match reader.read_event().map_err(|error| error.to_string())? {
            Event::Start(element) => {
                if stack.last().map(Vec::as_slice) == Some(b"w:body") && element.name().as_ref() == b"w:p" {
                    paragraph_start = Some(start);
                }
                stack.push(element.name().as_ref().to_vec());
            }
            Event::Empty(element) => {
                if stack.last().map(Vec::as_slice) == Some(b"w:body") && element.name().as_ref() == b"w:p" {
                    ranges.push(start..reader.buffer_position() as usize);
                }
            }
            Event::End(element) => {
                if stack.pop().as_deref() != Some(element.name().as_ref()) { return Err("mismatched XML close".to_owned()); }
                if stack.last().map(Vec::as_slice) == Some(b"w:body") && element.name().as_ref() == b"w:p" {
                    ranges.push(paragraph_start.take().ok_or("missing paragraph start")?..reader.buffer_position() as usize);
                }
            }
            Event::Eof => break,
            Event::DocType(_) => return Err("DOCTYPE is not permitted".to_owned()),
            _ => {}
        }
    }
    if !stack.is_empty() { return Err("truncated XML".to_owned()); }
    Ok(ranges)
}

/// Detect unresolved paragraph-mark revisions before ordinal addressing.
pub fn has_paragraph_mark_revision(bytes: &[u8]) -> Result<bool, String> {
    let root = parse(bytes)?;
    fn visit(element: &xmltree::Element) -> bool {
        let is_ppr = element.name == "pPr";
        element.children.iter().any(|node| {
            let xmltree::XMLNode::Element(child) = node else { return false; };
            if is_ppr && child.name == "rPr" && child.children.iter().any(|node| {
                matches!(node, xmltree::XMLNode::Element(mark) if matches!(mark.name.as_str(), "ins" | "del" | "moveFrom" | "moveTo"))
            }) { return true; }
            visit(child)
        })
    }
    Ok(visit(&root))
}

/// Whether the narrow retained writer can address only direct paragraph runs.
/// Unknown siblings remain legal if they do not hide any Word text-bearing run.
pub fn plain_paragraph_shape(bytes: &[u8], ordinal: u32) -> Result<bool, String> {
    use xmltree::{Element, XMLNode};
    fn element_children(element: &Element) -> impl Iterator<Item = &Element> {
        element.children.iter().filter_map(|node| match node { XMLNode::Element(child) => Some(child), _ => None })
    }
    fn has_word_content(element: &Element) -> bool {
        (element.namespace.as_deref() == Some("http://schemas.openxmlformats.org/wordprocessingml/2006/main")
            && matches!(element.name.as_str(), "r" | "p" | "t" | "delText"))
            || element_children(element).any(has_word_content)
    }
    let root = parse(bytes)?;
    let body = element_children(&root).find(|child| child.name == "body").ok_or("missing body")?;
    let paragraph = element_children(body).filter(|child| child.name == "p")
        .nth(ordinal.checked_sub(1).ok_or("zero paragraph")? as usize).ok_or("missing paragraph")?;
    Ok(element_children(paragraph).all(|child| {
        if child.prefix.as_deref() == Some("w") && matches!(child.name.as_str(), "r" | "pPr") { true }
        else { !has_word_content(child) }
    }))
}
