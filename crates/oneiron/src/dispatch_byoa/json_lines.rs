//! One JSON object per line, read whole from a stream's start in order (FIX 9240).
//!
//! Both the provider-usage read and the spent-seat read walk a runner CLI's
//! output this way, so the walk lives here once: leading ASCII blanks are
//! consumed without being held, a line opening with `{` is read whole and
//! handed over as bytes, a line led by any other ASCII byte is passed over
//! without being held, and a line led by a non-ASCII byte is read whole,
//! lossy-decoded and Unicode-trimmed, and handed over as text only when the
//! trimmed line opens with `{`. A buffer is a traversal unit only: no line
//! is skipped for its length.

use std::io::{BufRead, BufReader, Read};

/// One candidate line the walk hands over.
pub(super) enum JsonLine<'a> {
    /// A line that opened with `{`: its raw bytes, read whole however many
    /// buffer reads it spans.
    Bytes(&'a [u8]),
    /// A line led by a non-ASCII byte, lossy-decoded and Unicode-trimmed,
    /// opening with `{`.
    Text(&'a str),
}

/// Hands `visit` each candidate line `reader` holds, read whole from its
/// start in order. A read error maps through `map_err` and ends the walk;
/// what a handed line parses as is the visitor's own read.
///
/// # Errors
///
/// Returns `map_err`'s error when the stream cannot be read.
pub(super) fn each_json_line<R, E>(
    reader: R,
    mut map_err: impl FnMut(std::io::Error) -> E,
    mut visit: impl for<'line> FnMut(JsonLine<'line>),
) -> Result<(), E>
where
    R: Read,
{
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        let buffered = reader.fill_buf().map_err(&mut map_err)?;
        let Some(&first) = buffered.first() else {
            return Ok(());
        };
        if first.is_ascii_whitespace() {
            let blanks = buffered
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
            reader.consume(blanks);
        } else if first == b'{' {
            line.clear();
            reader.read_until(b'\n', &mut line).map_err(&mut map_err)?;
            visit(JsonLine::Bytes(&line));
        } else if first.is_ascii() {
            skip_line(&mut reader, &mut map_err)?;
        } else {
            line.clear();
            reader.read_until(b'\n', &mut line).map_err(&mut map_err)?;
            let decoded = String::from_utf8_lossy(&line);
            let trimmed = decoded.trim();
            if trimmed.starts_with('{') {
                visit(JsonLine::Text(trimmed));
            }
        }
    }
}

/// Passes over the rest of one line without holding it.
fn skip_line<E>(
    reader: &mut impl BufRead,
    map_err: &mut impl FnMut(std::io::Error) -> E,
) -> Result<(), E> {
    loop {
        let buffered = reader.fill_buf().map_err(&mut *map_err)?;
        if buffered.is_empty() {
            return Ok(());
        }
        let (take, ends) = buffered
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or((buffered.len(), false), |at| (at + 1, true));
        reader.consume(take);
        if ends {
            return Ok(());
        }
    }
}
