//! Core half of `graph_fs::coreutils_text`: its store-layer items live in `oneiron_store::graph_fs::coreutils_text` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::graph_fs::coreutils_text::*;

use super::paging::{CommandOutputBuilder, SealedPosition};
use crate::batch::secret_scan::ContainerReader;
use crate::error::Result;
use oneiron_store::batch::secret_scan::container::{ReadProgress, withheld};

/// Prints the lines of `bytes` from `from`, each as `render` makes it (`None`
/// skips it), until `max_lines` are printed or the page is full. A line
/// longer than a whole page prints across pages, cut on a character
/// boundary. Returns how many lines it finished, and where the next page
/// resumes when the page filled first.
pub(super) fn page_lines(
    bytes: &[u8],
    from: LinePosition,
    out: &mut CommandOutputBuilder,
    max_lines: usize,
    reader: &ContainerReader,
    scan_bytes: usize,
    mut render: impl FnMut(&str) -> Option<String>,
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
        if let Some(rendered) = render(&String::from_utf8_lossy(line)) {
            if let Some(printed) = out.push_line(&rendered, at.printed) {
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

/// Counts the same lossy text as `str::lines` and `str::split_whitespace`,
/// yielding between byte quanta even within one long line or word.
pub(super) fn text_counts(
    bytes: &[u8],
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<(usize, usize)> {
    checkpoint(reader)?;
    let text = String::from_utf8_lossy(bytes);
    let (mut lines, mut words, mut scanned) = (0, 0, 0);
    let mut in_word = false;
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
        scanned += ch.len_utf8();
        if scanned >= scan_bytes {
            checkpoint(reader)?;
            scanned = 0;
        }
    }
    // A nonempty last line needs no newline; CR stripping never changes the count.
    if !text.is_empty() && !text.ends_with('\n') {
        lines += 1;
    }
    Ok((lines, words))
}
