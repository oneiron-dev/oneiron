//! Core half of `graph_fs::coreutils_text`: its store-layer items live in `oneiron_store::graph_fs::coreutils_text` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::graph_fs::coreutils_text::*;

use super::paging::{CommandOutputBuilder, SealedPosition};
use crate::batch::secret_scan::ContainerReader;
use crate::error::Result;
use oneiron_store::batch::secret_scan::container::{ReadProgress, withheld};

/// Prints the lines of `bytes` from `from`, with a prefix from `prefix`
/// (`None` skips it) and a newline, until `max_lines` are printed or the page
/// is full. A line longer than a whole page prints across pages, cut on a character
/// boundary. Returns how many lines it finished, and where the next page
/// resumes when the page filled first.
pub(super) fn page_lines(
    bytes: &[u8],
    from: LinePosition,
    out: &mut CommandOutputBuilder,
    max_lines: usize,
    reader: &ContainerReader,
    scan_bytes: usize,
    mut prefix: impl FnMut(&str) -> Option<String>,
) -> Result<(usize, Option<LinePosition>)> {
    let mut finished = 0;
    let mut at = from;
    while at.line < bytes.len() && finished < max_lines {
        let rest = &bytes[at.line..];
        // Lines end at `\n` or `\r\n`, as `str::lines` splits them.
        let (line, next) = match line_end(rest, reader, scan_bytes)? {
            Some(end) => (
                rest[..end].strip_suffix(b"\r").unwrap_or(&rest[..end]),
                at.line + end + 1,
            ),
            None => (rest, bytes.len()),
        };
        let mut text = String::new();
        lossy_for_each(line, reader, scan_bytes, |chunk| text.push_str(chunk))?;
        if let Some(prefix) = prefix(&text) {
            if let Some(printed) = out.push_line_parts(&[&prefix, &text, "\n"], at.printed) {
                at.printed = printed;
                return Ok((finished, Some(at)));
            }
            finished += 1;
        }
        at = LinePosition {
            line: next,
            printed: 0,
        };
    }
    Ok((finished, None))
}

fn checkpoint(reader: &ContainerReader) -> Result<()> {
    reader
        .pacing
        .checkpoint(ReadProgress::Member)
        .map_err(withheld)
}

fn line_end(bytes: &[u8], reader: &ContainerReader, scan_bytes: usize) -> Result<Option<usize>> {
    let mut offset = 0;
    for chunk in bytes.chunks(scan_bytes.max(1)) {
        checkpoint(reader)?;
        if let Some(end) = chunk.iter().position(|byte| *byte == b'\n') {
            return Ok(Some(offset + end));
        }
        offset += chunk.len();
    }
    Ok(None)
}

/// Emits whole-input lossy UTF-8 without splitting a sequence at a scan boundary.
fn lossy_for_each(
    bytes: &[u8],
    reader: &ContainerReader,
    scan_bytes: usize,
    mut emit: impl FnMut(&str),
) -> Result<()> {
    let quantum = scan_bytes.max(char::MAX.len_utf8());
    let mut offset = 0;
    while offset < bytes.len() {
        checkpoint(reader)?;
        let end = offset.saturating_add(quantum).min(bytes.len());
        while offset < end {
            match std::str::from_utf8(&bytes[offset..end]) {
                Ok(text) => {
                    emit(text);
                    offset = end;
                }
                Err(error) => {
                    let valid_end = offset + error.valid_up_to();
                    emit(
                        std::str::from_utf8(&bytes[offset..valid_end])
                            .expect("UTF-8 error prefix is valid"),
                    );
                    offset = valid_end;
                    match error.error_len() {
                        Some(len) => {
                            emit("\u{fffd}");
                            offset += len;
                        }
                        None if end == bytes.len() => {
                            emit("\u{fffd}");
                            offset = end;
                        }
                        // Keep the incomplete sequence in the source for the next quantum.
                        None => break,
                    }
                }
            }
        }
    }
    Ok(())
}

/// Counts the same lossy text as `str::lines` and `str::split_whitespace`,
/// yielding between byte quanta even within one long line or word.
pub(super) fn text_counts(
    bytes: &[u8],
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<(usize, usize)> {
    checkpoint(reader)?;
    let (mut lines, mut words) = (0, 0);
    let mut in_word = false;
    lossy_for_each(bytes, reader, scan_bytes, |text| {
        for ch in text.chars() {
            if ch == '\n' {
                lines += 1;
            }
            if ch.is_whitespace() {
                in_word = false;
            } else if !in_word {
                words += 1;
                in_word = true;
            }
        }
    })?;
    // A nonempty last line needs no newline; CR stripping never changes the count.
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        lines += 1;
    }
    Ok((lines, words))
}
