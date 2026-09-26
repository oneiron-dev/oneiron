//! Lexical XML patcher: retain all unaddressed nodes, namespace declarations,
//! processing instructions and extensions at their original byte offsets.
use super::{Error, Result};
use quick_xml::{Reader, events::Event};

pub(super) fn replace_leaf_text(
    xml: &[u8],
    path: &[&str],
    expected: &str,
    value: &str,
) -> Result<Vec<u8>> {
    if value.chars().any(|c| !is_xml_char(c)) {
        return Err(Error::Edit("invalid XML character"));
    }
    if path.is_empty() || path.iter().any(|segment| segment.is_empty()) {
        return Err(Error::Edit("an absolute, nonempty QName path is required"));
    }
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<String> = Vec::new();
    let mut matches = Vec::new();
    let mut nested = false;
    let mut target_text: Option<(usize, usize, String)> = None;
    loop {
        let start = reader.buffer_position() as usize;
        let event = reader
            .read_event()
            .map_err(|_| Error::Edit("malformed XML"))?;
        let end = reader.buffer_position() as usize;
        match event {
            Event::Start(tag) => {
                if matches_path(&stack, path) {
                    nested = true;
                }
                stack.push(tag.name().as_ref().to_owned());
                if matches_path(&stack, path) {
                    target_text = None;
                    nested = false;
                }
            }
            Event::Empty(tag) => {
                stack.push(tag.name().as_ref().to_owned());
                if matches_path(&stack, path) {
                    nested = true;
                }
                stack.pop();
            }
            Event::Text(text) => {
                if matches_path(&stack, path) {
                    let decoded = quick_xml::escape::unescape(text.as_ref())
                        .map_err(|_| Error::Edit("invalid XML entity"))?;
                    append_text(&mut target_text, start, end, &decoded);
                }
            }
            Event::GeneralRef(reference) => {
                if matches_path(&stack, path) {
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
                    append_text(&mut target_text, start, end, &resolved.to_string());
                }
            }
            Event::Comment(_) | Event::PI(_) | Event::Decl(_) => {
                if matches_path(&stack, path) {
                    nested = true;
                }
            }
            Event::CData(_) => {
                if matches_path(&stack, path) {
                    nested = true;
                }
            }
            Event::End(_) => {
                if matches_path(&stack, path)
                    && !nested
                    && let Some((start, end, decoded)) = &target_text
                    && decoded == expected
                {
                    matches.push((*start, *end));
                }
                stack.pop().ok_or(Error::Edit("unbalanced XML"))?;
            }
            Event::DocType(_) => return Err(Error::Edit("DTD is not supported")),
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(Error::Edit("unclosed XML element"));
    }
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

fn matches_path(stack: &[String], path: &[&str]) -> bool {
    stack.len() == path.len()
        && stack
            .iter()
            .zip(path)
            .all(|(actual, wanted)| actual.as_str() == *wanted)
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

fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}
