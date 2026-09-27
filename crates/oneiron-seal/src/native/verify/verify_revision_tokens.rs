//! Bounded PDF lexical framing for revision object definitions and stream payloads.

use lopdf::{Document, Object, ObjectId};
use std::collections::BTreeSet;

/// Keep object-header recognition out of length-delimited stream payloads.
/// The effective xref gives the stream's raw header offset; lopdf retains
/// its encoded content length even when a decoded view is also available.
pub(super) fn stream_payloads(doc: &Document, bytes: &[u8], limit: usize) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for (id, obj) in doc.objects.iter().take(limit.min(10_000)) {
        let Object::Stream(stream) = obj else {
            continue;
        };
        let Some(lopdf::xref::XrefEntry::Normal { offset, .. }) = doc.reference_table.get(id.0)
        else {
            continue;
        };
        let at = *offset as usize;
        let Some(header) = bytes.get(at..bytes.len().min(at.saturating_add(4096))) else {
            continue;
        };
        let Some((_, payload)) = stream_delimiter(header) else {
            continue;
        };
        let begin = at + payload;
        let Some(end) = begin.checked_add(stream.content.len()) else {
            continue;
        };
        if bytes.get(begin..end) == Some(stream.content.as_slice()) {
            spans.push((begin, end));
        }
    }
    spans
}

pub(super) struct HeaderScan {
    pub(super) ids: BTreeSet<ObjectId>,
    pub(super) duplicate: bool,
}

fn pdf_space(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}

fn header_token(line: &[u8]) -> Option<ObjectId> {
    let mut at = 0;
    while line.get(at).is_some_and(|b| pdf_space(*b)) {
        at += 1;
    }
    let first = at;
    while line.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    let num = std::str::from_utf8(line.get(first..at)?)
        .ok()?
        .parse::<u32>()
        .ok()?;
    if !line.get(at).is_some_and(|b| pdf_space(*b)) {
        return None;
    }
    while line.get(at).is_some_and(|b| pdf_space(*b)) {
        at += 1;
    }
    let first = at;
    while line.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    let generation = std::str::from_utf8(line.get(first..at)?)
        .ok()?
        .parse::<u16>()
        .ok()?;
    if !line.get(at).is_some_and(|b| pdf_space(*b)) {
        return None;
    }
    while line.get(at).is_some_and(|b| pdf_space(*b)) {
        at += 1;
    }
    if !line.get(at..)?.starts_with(b"obj") {
        return None;
    }
    at += 3;
    if line.get(at).is_some_and(|b| {
        !pdf_space(*b) && !matches!(*b, b'<' | b'>' | b'(' | b')' | b'[' | b']' | b'/' | b'%')
    }) {
        return None;
    }
    Some((num, generation))
}

/// Lex only outside PDF literals, hex strings, comments, and the parser's
/// length-delimited stream spans. Bounded by the input and object budgets.
pub(super) fn scan_headers(
    segment: &[u8],
    base: usize,
    max_objects: usize,
    spans: &[(usize, usize)],
) -> Option<HeaderScan> {
    let mut scan = HeaderScan {
        ids: BTreeSet::new(),
        duplicate: false,
    };
    let mut offset = base;
    let mut literal = 0usize;
    let mut hex = false;
    let mut escaped = false;
    for line in segment.split_inclusive(|b| *b == b'\n') {
        let current = offset;
        offset += line.len();
        if spans
            .iter()
            .any(|&(start, end)| current >= start && current < end)
        {
            continue;
        }
        if literal == 0
            && !hex
            && let Some(id) = header_token(line)
        {
            if !scan.ids.insert(id) {
                scan.duplicate = true;
            }
            if scan.ids.len() > max_objects.min(10_000) {
                return None;
            }
        }
        let mut i = 0;
        while i < line.len() {
            let b = line[i];
            if literal > 0 {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'(' {
                    literal += 1;
                } else if b == b')' {
                    literal -= 1;
                }
            } else if hex {
                if b == b'>' {
                    hex = false;
                }
            } else if b == b'%' {
                break;
            } else if b == b'(' {
                literal = 1;
            } else if b == b'<' && line.get(i + 1) != Some(&b'<') {
                hex = true;
            } else if b == b'<' {
                i += 1;
            } // dictionary opener, not a hex string
            i += 1;
        }
    }
    Some(scan)
}

/// Find the stream token after its containing dictionary, not a matching
/// substring inside a PDF string/comment or the stream payload itself.
/// Returns (keyword offset, first payload byte) for LF and CRLF framing.
pub(super) fn stream_delimiter(header: &[u8]) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    let mut literal = 0usize;
    let mut hex = false;
    let mut escaped = false;
    let mut comment = false;
    let mut saw_dictionary = false;
    let mut i = 0;
    while i < header.len() {
        let b = header[i];
        if comment {
            if b == b'\n' || b == b'\r' {
                comment = false;
            }
        } else if literal > 0 {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'(' {
                literal += 1;
            } else if b == b')' {
                literal -= 1;
            }
        } else if hex {
            if b == b'>' {
                hex = false;
            }
        } else if b == b'%' {
            comment = true;
        } else if header.get(i..i + 2) == Some(b"<<") {
            depth += 1;
            saw_dictionary = true;
            i += 1;
        } else if header.get(i..i + 2) == Some(b">>") {
            depth = depth.checked_sub(1)?;
            i += 1;
        } else if b == b'(' {
            literal = 1;
        } else if b == b'<' {
            hex = true;
        } else if saw_dictionary && depth == 0 && i > 0 && pdf_space(header[i - 1]) {
            if header.get(i..i + 8) == Some(b"stream\r\n") {
                return Some((i, i + 8));
            }
            if header.get(i..i + 7) == Some(b"stream\n") {
                return Some((i, i + 7));
            }
        }
        i += 1;
    }
    None
}

/// Scan a raw segment without stream metadata (also used for xref headers).
pub(super) fn revision_headers(segment: &[u8], max_objects: usize) -> Option<BTreeSet<ObjectId>> {
    let scan = scan_headers(segment, 0, max_objects, &[])?;
    (!scan.duplicate).then_some(scan.ids)
}
