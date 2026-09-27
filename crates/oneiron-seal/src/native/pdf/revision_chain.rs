//! Shared, bounded PDF revision discovery from the actual xref /Prev chain.
//! Marker-looking bytes in streams never create extra revisions.
use crate::api::SealResourceLimits;
use lopdf::{Document, LoadOptions, Object};

const MAX_REVISIONS: usize = 32;
const MAX_PREFIX_WORK: usize = 2 * 1024 * 1024 * 1024;
fn eol(b: u8) -> bool {
    matches!(b, b'\r' | b'\n')
}
fn ws(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}

/// Proven revision identity within one validated xref/`/Prev` chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RevisionBoundary {
    pub index: usize,
    pub eof_end: usize,
}

/// Bind a signed range once to a structural revision, never to raw marker
/// text that merely resembles an EOF inside a stream or string.
pub(crate) fn bind_range(
    bytes: &[u8],
    ends: Option<&[usize]>,
    covers_to: u64,
) -> Option<RevisionBoundary> {
    ends?.iter().enumerate().find_map(|(index, eof_end)| {
        owns_eof(bytes, *eof_end, covers_to).then_some(RevisionBoundary {
            index,
            eof_end: *eof_end,
        })
    })
}

/// A signature may cover the EOF marker itself or as many as four EOL bytes
/// immediately after it. This is the same boundary law used by classification
/// and the coverage ladder. The following revision's glue is not signed.
pub(crate) fn owns_eof(bytes: &[u8], eof_end: usize, covers_to: u64) -> bool {
    let Ok(end) = usize::try_from(covers_to) else {
        return false;
    };
    end >= eof_end
        && end - eof_end <= 4
        && bytes
            .get(eof_end..end)
            .is_some_and(|s| s.iter().all(|b| eol(*b)))
}

/// A signed range may leave at most four final EOL bytes unsigned.
pub(crate) fn file_tail_covered(bytes: &[u8], covers_to: u64) -> bool {
    let Ok(end) = usize::try_from(covers_to) else {
        return false;
    };
    bytes
        .get(end..)
        .is_some_and(|s| s.len() <= 4 && s.iter().all(|b| eol(*b)))
}

pub(crate) fn load_snapshot(bytes: &[u8], limits: &SealResourceLimits) -> Option<Document> {
    let doc = Document::load_mem_with_options(
        bytes,
        LoadOptions {
            strict: true,
            max_decompressed_size: Some(limits.max_input_bytes),
            ..LoadOptions::default()
        },
    )
    .ok()?;
    (doc.objects.len() <= limits.max_pdf_objects).then_some(doc)
}

/// Parse only `startxref <decimal> %%EOF` at an actual xref section's end.
/// The full prefix loader must also point to that same xref, so a decoy in a
/// content stream cannot become a revision even when it names an old xref.
fn find_end(
    bytes: &[u8],
    xref: usize,
    stop: usize,
    limits: &SealResourceLimits,
    final_section: bool,
) -> Option<(usize, usize, Document)> {
    if xref >= stop || stop > bytes.len() {
        return None;
    }
    let mut at = xref;
    while at + 9 <= stop {
        let found = bytes[at..stop].windows(9).position(|w| w == b"startxref")? + at;
        at = found + 9;
        if found > 0 && !eol(bytes[found - 1]) {
            continue;
        }
        let mut pos = at;
        while pos < stop && ws(bytes[pos]) {
            pos += 1;
        }
        let first = pos;
        while pos < stop && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let Ok(num) = std::str::from_utf8(&bytes[first..pos])
            .unwrap_or("")
            .parse::<usize>()
        else {
            continue;
        };
        if num != xref {
            continue;
        }
        while pos < stop && ws(bytes[pos]) {
            pos += 1;
        }
        if bytes.get(pos..pos.checked_add(5)?) != Some(b"%%EOF".as_slice()) {
            continue;
        }
        let end = pos + 5;
        if final_section {
            let tail = &bytes[end..stop];
            if tail.len() > 4 || !tail.iter().all(|b| eol(*b)) {
                continue;
            }
        }
        let Some(doc) = load_snapshot(&bytes[..end], limits) else {
            continue;
        };
        if doc.xref_start == xref {
            return Some((end, found, doc));
        }
    }
    None
}

/// Scan the classic xref's trailer dictionary, not an arbitrary `/Prev`
/// substring in an /ID string, nested array or stream. The strict lopdf load
/// separately checks the table and every referenced object.
fn table_prev(bytes: &[u8], xref: usize, marker: usize) -> Option<Option<usize>> {
    let section = bytes.get(xref..marker)?;
    if !section.starts_with(b"xref") {
        return None;
    }
    let trailer = section.windows(7).position(|w| w == b"trailer")? + xref + 7;
    let mut pos = trailer;
    while pos < marker && ws(bytes[pos]) {
        pos += 1;
    }
    if bytes.get(pos..pos + 2)? != b"<<" {
        return None;
    }
    pos += 2;
    let mut dict_depth = 1usize;
    let mut array_depth = 0usize;
    let mut prev = None;
    while pos < marker && dict_depth > 0 {
        match bytes[pos] {
            b'%' => {
                while pos < marker && !eol(bytes[pos]) {
                    pos += 1;
                }
            }
            b'(' => {
                // Skip escaped and nested literal strings.
                pos += 1;
                let mut depth = 1usize;
                while pos < marker && depth > 0 {
                    match bytes[pos] {
                        b'\\' => pos = pos.saturating_add(2),
                        b'(' => {
                            depth += 1;
                            pos += 1;
                        }
                        b')' => {
                            depth -= 1;
                            pos += 1;
                        }
                        _ => pos += 1,
                    }
                }
                if depth != 0 {
                    return None;
                }
            }
            b'<' if bytes.get(pos + 1) == Some(&b'<') => {
                dict_depth += 1;
                pos += 2;
            }
            b'<' => {
                pos += 1;
                while pos < marker && bytes[pos] != b'>' {
                    pos += 1;
                }
                if pos == marker {
                    return None;
                }
                pos += 1;
            }
            b'>' if bytes.get(pos + 1) == Some(&b'>') => {
                dict_depth -= 1;
                pos += 2;
            }
            b'[' => {
                array_depth += 1;
                pos += 1;
            }
            b']' => {
                array_depth = array_depth.checked_sub(1)?;
                pos += 1;
            }
            b'/' => {
                pos += 1;
                let begin = pos;
                while pos < marker && !ws(bytes[pos]) && !b"/[]<>()%".contains(&bytes[pos]) {
                    pos += 1;
                }
                if dict_depth == 1 && array_depth == 0 && bytes.get(begin..pos) == Some(b"Prev") {
                    if prev.is_some() {
                        return None;
                    }
                    while pos < marker && ws(bytes[pos]) {
                        pos += 1;
                    }
                    let begin = pos;
                    while pos < marker && bytes[pos].is_ascii_digit() {
                        pos += 1;
                    }
                    prev = Some(
                        std::str::from_utf8(bytes.get(begin..pos)?)
                            .ok()?
                            .parse()
                            .ok()?,
                    );
                }
            }
            _ => pos += 1,
        }
    }
    (dict_depth == 0 && array_depth == 0).then_some(prev)
}

fn section_prev(doc: &Document, bytes: &[u8], xref: usize, marker: usize) -> Option<Option<usize>> {
    if bytes.get(xref..xref + 4) == Some(b"xref".as_slice()) {
        return table_prev(bytes, xref, marker);
    }
    // For an xref stream the /Prev is in that stream object's parsed dict.
    let stream = doc
        .reference_table
        .entries
        .iter()
        .find_map(|(num, entry)| match entry {
            lopdf::xref::XrefEntry::Normal { offset, generation } if *offset as usize == xref => {
                doc.objects
                    .get(&(*num, *generation))
                    .and_then(|o| o.as_stream().ok())
            }
            _ => None,
        })?;
    if !matches!(stream.dict.get(b"Type"), Ok(Object::Name(n)) if n == b"XRef") {
        return None;
    }
    match stream.dict.get(b"Prev") {
        Ok(Object::Integer(n)) => Some(Some(usize::try_from(*n).ok()?)),
        Err(_) => Some(None),
        _ => None,
    }
}

/// Return exact EOF ends in revision order, or no proof. A malicious or
/// unsupported xref chain never becomes an empty/clean change list.
pub(crate) fn revision_ends(
    bytes: &[u8],
    doc: &Document,
    limits: &SealResourceLimits,
) -> Option<Vec<usize>> {
    let mut ends = Vec::new();
    let mut xref = doc.xref_start;
    let mut stop = bytes.len();
    let mut final_section = true;
    let mut work = 0usize;
    loop {
        if ends.len() >= MAX_REVISIONS {
            return None;
        }
        let (end, marker, parsed) = find_end(bytes, xref, stop, limits, final_section)?;
        work = work.checked_add(end)?;
        if work > MAX_PREFIX_WORK {
            return None;
        }
        ends.push(end);
        let Some(prev) = section_prev(&parsed, bytes, xref, marker)? else {
            break;
        };
        if prev >= xref || end <= prev {
            return None;
        }
        stop = xref;
        xref = prev;
        final_section = false;
    }
    ends.reverse();
    Some(ends)
}
