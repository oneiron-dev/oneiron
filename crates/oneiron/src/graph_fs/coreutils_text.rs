//! Core half of `graph_fs::coreutils_text`: its store-layer items live in `oneiron_store::graph_fs::coreutils_text` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::graph_fs::coreutils_text::*;

use super::paging::{CommandOutputBuilder, SealedPosition};
use crate::batch::secret_scan::ContainerReader;
use crate::error::Result;
use oneiron_store::batch::secret_scan::container::{ReadProgress, withheld};

/// Prints HEAD lines without materializing a whole lossy line.
pub(super) fn page_head_lines(
    bytes: &[u8],
    from: LinePosition,
    out: &mut CommandOutputBuilder,
    max_lines: usize,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<(usize, Option<LinePosition>)> {
    let mut finished = 0;
    let mut at = from;
    while at.line < bytes.len() && finished < max_lines {
        let (line, next) = next_line(bytes, at.line, reader, scan_bytes)?;
        let cut = push_lossy_line(line, &[], at.printed, out, reader, scan_bytes)?;
        if let Some(printed) = cut {
            at.printed = printed;
            return Ok((finished, Some(at)));
        }
        finished += 1;
        at = LinePosition {
            line: next,
            printed: 0,
        };
    }
    Ok((finished, None))
}

/// GREP searches overlapping lossy windows bounded by the needle and scan quantum.
pub(super) fn page_grep_lines(
    bytes: &[u8],
    from: LinePosition,
    out: &mut CommandOutputBuilder,
    max_lines: usize,
    reader: &ContainerReader,
    scan_bytes: usize,
    pattern: &str,
    path: &str,
) -> Result<(usize, Option<LinePosition>)> {
    let mut finished = 0;
    let mut at = from;
    while at.line < bytes.len() && finished < max_lines {
        let (line, next) = next_line(bytes, at.line, reader, scan_bytes)?;
        if contains_lossy_literal(line, pattern, reader, scan_bytes)? {
            if let Some(printed) =
                push_lossy_line(line, &[path, ":"], at.printed, out, reader, scan_bytes)?
            {
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

fn contains_lossy_literal(
    line: &[u8],
    pattern: &str,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<bool> {
    if pattern.is_empty() {
        checkpoint(reader)?;
        return Ok(true);
    }
    let quantum = scan_bytes.max(char::MAX.len_utf8());
    if pattern.len() > quantum {
        return contains_long_lossy_literal(line, pattern, reader, scan_bytes);
    }
    let mut window = String::new();
    let mut pending = 0;
    let mut matched = false;
    lossy_for_each(line, reader, scan_bytes, |chunk| {
        if matched {
            return Ok(());
        }
        window.push_str(chunk);
        pending += chunk.len();
        if pending >= quantum {
            matched = window.contains(pattern);
            if !matched {
                let mut keep_from = window.len().saturating_sub(pattern.len() - 1);
                while !window.is_char_boundary(keep_from) {
                    keep_from -= 1;
                }
                drop(window.drain(..keep_from));
                pending = 0;
            }
        }
        Ok(())
    })?;
    checkpoint(reader)?;
    Ok(matched || window.contains(pattern))
}

fn contains_long_lossy_literal(
    line: &[u8],
    pattern: &str,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<bool> {
    let quantum = scan_bytes.max(char::MAX.len_utf8());
    let contains = |window: &[u8]| {
        checkpoint(reader)?;
        super::coreutils_search::contains_long_literal(window, pattern, quantum, || {
            checkpoint(reader)
        })
    };
    let mut window = Vec::new();
    let mut pending = 0;
    let mut matched = false;
    lossy_for_each(line, reader, scan_bytes, |chunk| {
        if matched {
            return Ok(());
        }
        window.extend_from_slice(chunk.as_bytes());
        pending += chunk.len();
        if pending >= pattern.len() {
            matched = contains(&window)?;
            if !matched {
                // Byte matching permits a retained window to begin inside a UTF-8 scalar.
                let keep_from = window.len().saturating_sub(pattern.len() - 1);
                let retained = window.len() - keep_from;
                let mut copied = 0;
                while copied < retained {
                    checkpoint(reader)?;
                    let end = copied.saturating_add(quantum).min(retained);
                    window.copy_within(keep_from + copied..keep_from + end, copied);
                    copied = end;
                }
                window.truncate(retained);
                pending = 0;
            }
        }
        Ok(())
    })?;
    checkpoint(reader)?;
    if matched { Ok(true) } else { contains(&window) }
}

fn push_lossy_line(
    line: &[u8],
    prefix: &[&str],
    printed: usize,
    out: &mut CommandOutputBuilder,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<Option<usize>> {
    let mut len = 0;
    let mut boundary = printed == 0;
    for part in prefix {
        if let Some(offset) = printed.checked_sub(len)
            && offset <= part.len()
        {
            boundary |= part.is_char_boundary(offset);
        }
        len += part.len();
    }
    lossy_for_each(line, reader, scan_bytes, |chunk| {
        if let Some(offset) = printed.checked_sub(len)
            && offset <= chunk.len()
        {
            boundary |= chunk.is_char_boundary(offset);
        }
        len += chunk.len();
        Ok(())
    })?;
    boundary |= printed == len || printed == len + 1;
    len += 1;
    let printed = if boundary { printed } else { 0 };
    out.push_line_streamed(len, printed, |output, mut remaining| {
        let (mut offset, mut copied) = (0, 0);
        let mut truncated = false;
        {
            let mut copy_chunk = |chunk: &str| {
                let end = offset + chunk.len();
                if !truncated && end > printed && remaining > 0 {
                    let start = printed.saturating_sub(offset);
                    let mut take = remaining.min(chunk.len() - start);
                    while !chunk.is_char_boundary(start + take) {
                        take -= 1;
                    }
                    output.extend_from_slice(&chunk.as_bytes()[start..start + take]);
                    copied += take;
                    remaining -= take;
                    truncated = start + take < chunk.len();
                }
                offset = end;
                Ok(())
            };
            for part in prefix {
                copy_chunk(part)?;
            }
            lossy_for_each(line, reader, scan_bytes, &mut copy_chunk)?;
        }
        if !truncated && remaining > 0 && printed <= offset {
            output.push(b'\n');
            copied += 1;
        }
        Ok(copied)
    })
}

fn next_line<'bytes>(
    bytes: &'bytes [u8],
    at: usize,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<(&'bytes [u8], usize)> {
    let rest = &bytes[at..];
    // Lines end at `\n` or `\r\n`, as `str::lines` splits them.
    Ok(match line_end(rest, reader, scan_bytes)? {
        Some(end) => (
            rest[..end].strip_suffix(b"\r").unwrap_or(&rest[..end]),
            at + end + 1,
        ),
        None => (rest, bytes.len()),
    })
}

/// Copies complete UTF-8 text with the caller's reader, without rendering a page.
pub(super) fn copy_text_parts(
    parts: &[&str],
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<String> {
    let quantum = scan_bytes.max(char::MAX.len_utf8());
    let mut path = String::new();
    for part in parts {
        let mut rest = *part;
        while !rest.is_empty() {
            checkpoint(reader)?;
            let mut end = quantum.min(rest.len());
            while !rest.is_char_boundary(end) {
                end -= 1;
            }
            path.push_str(&rest[..end]);
            rest = &rest[end..];
        }
    }
    Ok(path)
}

pub(super) fn join_graph_path_with_reader(
    parent: &str,
    name: &str,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<String> {
    if parent == "/" {
        copy_text_parts(&["/", name], reader, scan_bytes)
    } else {
        copy_text_parts(&[parent, "/", name], reader, scan_bytes)
    }
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
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let quantum = scan_bytes.max(char::MAX.len_utf8());
    let mut offset = 0;
    while offset < bytes.len() {
        checkpoint(reader)?;
        let end = offset.saturating_add(quantum).min(bytes.len());
        while offset < end {
            match std::str::from_utf8(&bytes[offset..end]) {
                Ok(text) => {
                    emit(text)?;
                    offset = end;
                }
                Err(error) => {
                    let valid_end = offset + error.valid_up_to();
                    emit(
                        std::str::from_utf8(&bytes[offset..valid_end])
                            .expect("UTF-8 error prefix is valid"),
                    )?;
                    offset = valid_end;
                    match error.error_len() {
                        Some(len) => {
                            emit("\u{fffd}")?;
                            offset += len;
                        }
                        None if end == bytes.len() => {
                            emit("\u{fffd}")?;
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
        Ok(())
    })?;
    // A nonempty last line needs no newline; CR stripping never changes the count.
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        lines += 1;
    }
    Ok((lines, words))
}
