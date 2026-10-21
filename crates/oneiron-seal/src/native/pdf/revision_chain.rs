//! Shared PDF revision discovery from the actual xref /Prev chain.
//! Marker-looking bytes in streams never create extra revisions. A chain of
//! any length is followed whole; its length, the prefix bytes it parsed and
//! each classic section's tokens go to the invocation's counts (Rule 5).
//! The CR/LF run after a revision's `%%EOF` belongs to that revision however
//! long it is: only CR and LF bytes, never the next revision's content.
//! Every snapshot's decodes reserve their memory first (FIX 7654); a refusal
//! ends the walk as itself (`Err`), never as a revision that did not parse.
use super::decode::{self, LoadError};
use crate::api::{Counter, SealResourceLimits};
use crate::memory::SealMemoryRefusal;
use lopdf::{Document, Object};

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

/// A signature may cover the EOF marker itself or any run of EOL bytes
/// immediately after it, which holds no content (Rule 5: no count of them
/// refuses). This is the same boundary law used by classification and the
/// coverage ladder. The following revision's glue is not signed.
pub(crate) fn owns_eof(bytes: &[u8], eof_end: usize, covers_to: u64) -> bool {
    let Ok(end) = usize::try_from(covers_to) else {
        return false;
    };
    end >= eof_end
        && bytes
            .get(eof_end..end)
            .is_some_and(|s| s.iter().all(|b| eol(*b)))
}

/// A signed range may leave the file's final run of EOL bytes unsigned,
/// however long, and nothing else.
pub(crate) fn file_tail_covered(bytes: &[u8], covers_to: u64) -> bool {
    let Ok(end) = usize::try_from(covers_to) else {
        return false;
    };
    bytes.get(end..).is_some_and(|s| s.iter().all(|b| eol(*b)))
}

/// A strict snapshot, each stream decoded whole, refused only past the ISO
/// object bound: `None` when the bytes are no such snapshot, `Err` when the
/// memory its decodes needed was not reserved.
pub(crate) fn load_snapshot(
    bytes: &[u8],
    limits: &SealResourceLimits,
) -> Result<Option<Document>, SealMemoryRefusal> {
    let doc = match decode::load_strict(bytes, limits) {
        Ok(doc) => doc,
        Err(LoadError::Memory(refusal)) => return Err(refusal),
        Err(LoadError::Malformed) => return Ok(None),
    };
    limits.observed.note(Counter::PdfObjects, doc.objects.len());
    Ok((doc.objects.len() <= limits.max_pdf_objects).then_some(doc))
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
) -> Result<Option<(usize, usize, Document)>, SealMemoryRefusal> {
    if xref >= stop || stop > bytes.len() {
        return Ok(None);
    }
    let mut at = xref;
    while at + 9 <= stop {
        let Some(found) = bytes[at..stop].windows(9).position(|w| w == b"startxref") else {
            return Ok(None);
        };
        let found = found + at;
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
        let Some(eof) = pos.checked_add(5) else {
            return Ok(None);
        };
        if bytes.get(pos..eof) != Some(b"%%EOF".as_slice()) {
            continue;
        }
        let end = pos + 5;
        if final_section && !bytes[end..stop].iter().all(|b| eol(*b)) {
            continue;
        }
        let Some(doc) = load_snapshot(&bytes[..end], limits)? else {
            continue;
        };
        if doc.xref_start == xref {
            return Ok(Some((end, found, doc)));
        }
    }
    Ok(None)
}

/// Bind a classic xref's decoded trailer name to the shared PDF lexer.
fn table_prev(
    bytes: &[u8],
    xref: usize,
    marker: usize,
    limits: &SealResourceLimits,
) -> Option<Option<usize>> {
    let (prev, work) = super::lex::table_prev_work(bytes.get(xref..marker)?).ok()?;
    limits.observed.note(Counter::StructuralWork, work);
    Some(prev)
}

fn section_prev(
    doc: &Document,
    bytes: &[u8],
    xref: usize,
    marker: usize,
    limits: &SealResourceLimits,
) -> Option<Option<usize>> {
    if bytes.get(xref..xref + 4) == Some(b"xref".as_slice()) {
        return table_prev(bytes, xref, marker, limits);
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

/// Return exact EOF ends in revision order, or no proof (`Ok(None)`). A
/// malicious or unsupported xref chain never becomes an empty/clean change
/// list, and memory a snapshot was refused never becomes no proof.
pub(crate) fn revision_ends(
    bytes: &[u8],
    doc: &Document,
    limits: &SealResourceLimits,
) -> Result<Option<Vec<usize>>, SealMemoryRefusal> {
    let mut ends = Vec::new();
    let mut xref = doc.xref_start;
    let mut stop = bytes.len();
    let mut final_section = true;
    let mut work = 0usize;
    loop {
        let Some((end, marker, parsed)) = find_end(bytes, xref, stop, limits, final_section)?
        else {
            return Ok(None);
        };
        work = work.saturating_add(end);
        ends.push(end);
        limits.observed.note(Counter::Revisions, ends.len());
        limits.observed.note(Counter::PrefixBytes, work);
        let Some(prev) = section_prev(&parsed, bytes, xref, marker, limits) else {
            return Ok(None);
        };
        let Some(prev) = prev else {
            break;
        };
        if prev >= xref || end <= prev {
            return Ok(None);
        }
        stop = xref;
        xref = prev;
        final_section = false;
    }
    ends.reverse();
    Ok(Some(ends))
}
