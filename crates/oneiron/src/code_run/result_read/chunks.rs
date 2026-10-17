//! `chunks`: a result cut into range refs, a page at a time. A chunk is a
//! range of its parent named `<handle>#<start>-<end>` in the parent's own
//! bytes, so a chunk of a range is a range of the same parent. No byte is
//! copied and nothing is published: a chunk is read as its parent is.

use super::{
    LinePos, ReadBounds, Reply, ResultBody, Scan, Seek, decode, floor_boundary, invalid_input,
    refusal, scan_limit, seek_line, whole_index,
};
use crate::Result;
use crate::code_run::CodeRunOutputKind;
use serde::Deserialize;
use serde_json::{Value, json};

/// Chunks one page holds at most.
const PAGE_CHUNKS: usize = 256;

/// Bytes a line-aligned chunk looks on past its size for a newline.
const ALIGN_BYTES: u64 = 64 * 1024;

/// The most bytes one token-sized `chunks` call tokenizes: tokenizing 8 MiB
/// stays inside one 5 s step. It is a page bound, never a result bound: the
/// reply's cursor goes on from where it stopped.
pub(crate) const CHUNK_TOKEN_PAGE_BYTES: u64 = 8 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunksInput {
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    lines: Option<u64>,
    /// Chunks of about this many tokens each, counted with the executor's
    /// tokenizer, grown line by line.
    #[serde(default)]
    tokens: Option<u64>,
    /// With `tokens`: the most bytes one chunk holds.
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    overlap: Option<u64>,
    #[serde(default)]
    align: Option<Align>,
    #[serde(default)]
    cursor: Option<ChunkCursor>,
}

/// Where a byte chunk ends: at the first newline past its size, or at the
/// size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Align {
    Line,
    None,
}

/// Where the next page starts, and the newlines before it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkCursor {
    offset: u64,
    #[serde(default)]
    line: u64,
}

/// One chunk of the window `[start, end)` as a page lists it, in the
/// parent's bytes.
fn entry(parent: &str, base: u64, start: u64, end: u64, cut: bool) -> Value {
    let (start, end) = (base + start, base + end);
    let mut chunk = json!({"ref": format!("{parent}#{start}-{end}"), "start": start, "end": end});
    if cut {
        chunk["cut"] = json!(true);
    }
    chunk
}

/// `chunks`: see the module. `parent` is the handle of the body the window
/// is of.
pub(super) fn chunks(
    body: &dyn ResultBody,
    reference: &str,
    parent: &str,
    input: Value,
    bounds: &ReadBounds<'_>,
) -> Result<Reply> {
    let input: ChunksInput = match decode(input) {
        Ok(input) => input,
        Err(refused) => return Ok(Reply::Denied(refused)),
    };
    let text = body.kind() == CodeRunOutputKind::Text;
    let overlap = input.overlap.unwrap_or(0);
    let align = input
        .align
        .unwrap_or(if text { Align::Line } else { Align::None });
    let len = body.len();
    let from = input.cursor.map_or(LinePos::START, |cursor| LinePos {
        offset: cursor.offset.min(len),
        lfs: cursor.line,
    });
    let mut scan = Scan::new(bounds.scan_bytes());
    let mut page = Vec::new();
    if let Some(tokens) = input.tokens {
        if input.bytes.is_some() || input.lines.is_some() || input.overlap.is_some() || tokens == 0
        {
            return Ok(Reply::Denied(invalid_input(
                "chunks takes tokens: n (with max_bytes) alone, with n above zero",
            )));
        }
        if !text {
            return Ok(Reply::Denied(refusal("tokens_on_binary")));
        }
        let max_bytes = input.max_bytes.unwrap_or(u64::MAX).max(1);
        // The page bound reads no more than the scan bound would.
        let scan_bound = bounds.scan_bytes();
        let mut scan = Scan::new(scan_bound.min(CHUNK_TOKEN_PAGE_BYTES));
        let (next, spent) = by_tokens(
            body,
            parent,
            tokens,
            max_bytes,
            from.offset,
            &mut scan,
            &mut page,
        )?;
        let mut reply = json!({"ref": reference, "chunks": page, "done": next.is_none()});
        if let Some(next) = next {
            reply["next"] = next;
        }
        if spent && scan_bound <= CHUNK_TOKEN_PAGE_BYTES {
            reply["limit"] = scan_limit();
        }
        return Ok(Reply::Output(reply));
    }
    if input.max_bytes.is_some() {
        return Ok(Reply::Denied(invalid_input("max_bytes goes with tokens")));
    }
    let (next, limited) = match (input.bytes, input.lines) {
        (Some(size), None) if size > 0 && overlap < size => by_bytes(
            body,
            parent,
            size,
            overlap,
            align,
            text,
            from.offset,
            &mut scan,
            &mut page,
        )?,
        (None, Some(count)) if count > 0 && overlap < count => {
            if !text {
                return Ok(Reply::Denied(refusal("lines_on_binary")));
            }
            by_lines(body, parent, count, overlap, from, &mut scan, &mut page)?
        }
        _ => {
            return Ok(Reply::Denied(invalid_input(
                "chunks takes bytes: n or lines: n, with n above zero and any overlap below n",
            )));
        }
    };
    let mut reply = json!({"ref": reference, "chunks": page, "done": next.is_none()});
    if let Some(next) = next {
        reply["next"] = next;
    }
    if limited {
        reply["limit"] = scan_limit();
    }
    Ok(Reply::Output(reply))
}

/// Chunks of `size` bytes from `start`, each ending at a newline when
/// aligned (looked for at most 64 KiB on, then cut at a character
/// boundary and marked `cut`). The cursor of the next page, and whether
/// the scan bound ended this one.
#[allow(clippy::too_many_arguments)]
fn by_bytes(
    body: &dyn ResultBody,
    parent: &str,
    size: u64,
    overlap: u64,
    align: Align,
    text: bool,
    start: u64,
    scan: &mut Scan,
    page: &mut Vec<Value>,
) -> Result<(Option<Value>, bool)> {
    let len = body.len();
    let base = body.base();
    let mut s = start;
    loop {
        if s >= len {
            return Ok((None, false));
        }
        if page.len() == PAGE_CHUNKS {
            return Ok((Some(json!({"offset": s})), false));
        }
        let target = s.saturating_add(size);
        let (mut e, cut) = if target >= len {
            (len, false)
        } else if align == Align::Line {
            // A few bytes before the size are read too, to cut at a
            // character boundary when no newline comes.
            let lead = target.saturating_sub(4).max(s);
            let ahead = usize::try_from(target - 1 - lead).unwrap_or(0);
            let want = usize::try_from(ALIGN_BYTES).unwrap_or(usize::MAX) + ahead;
            let piece = scan.read(body, lead, want)?;
            let reached = lead + piece.len() as u64;
            match piece
                .get(ahead..)
                .and_then(|rest| rest.iter().position(|byte| *byte == b'\n'))
            {
                Some(newline) => (lead + (ahead + newline) as u64 + 1, false),
                None if reached >= len => (len, false),
                None if piece.len() < want => return Ok((Some(json!({"offset": s})), true)),
                None => {
                    let at = usize::try_from(target - lead).unwrap_or(0);
                    let at = if text { floor_boundary(&piece, at) } else { at };
                    (lead + at as u64, true)
                }
            }
        } else {
            (target, false)
        };
        if e <= s {
            e = target.min(len);
        }
        page.push(entry(parent, base, s, e, cut));
        // The next chunk starts `overlap` bytes before this one ends: at
        // the line start before that when aligned.
        let mut next = e;
        if overlap > 0 && e < len {
            next = e.saturating_sub(overlap).max(s + 1);
            if align == Align::Line {
                let lead = next.saturating_sub(ALIGN_BYTES).max(s + 1);
                let behind = usize::try_from(next - lead).unwrap_or(0);
                let piece = scan.read(body, lead, behind)?;
                if let Some(newline) = piece.iter().rposition(|byte| *byte == b'\n') {
                    next = lead + newline as u64 + 1;
                }
            }
        }
        s = next.max(s + 1);
    }
}

/// Chunks of about `tokens` tokens from `start`, each grown line by line
/// until the next line would take it past `tokens` or past `max_bytes`: a
/// line longer than either is cut at a character boundary into a chunk of
/// its own, marked `cut`. Lines are counted with the executor's tokenizer.
/// The cursor of the next page, and whether the scan bound ended this one.
fn by_tokens(
    body: &dyn ResultBody,
    parent: &str,
    tokens: u64,
    max_bytes: u64,
    start: u64,
    scan: &mut Scan,
    page: &mut Vec<Value>,
) -> Result<(Option<Value>, bool)> {
    let len = body.len();
    let base = body.base();
    // The longest piece of one line: a token is at least a byte.
    let piece_cap = usize::try_from(ALIGN_BYTES.min(max_bytes).min(tokens).max(1)).unwrap_or(1);
    let (mut buf, mut buf_at) = (Vec::new(), start);
    let (mut chunk_start, mut at, mut count, mut cut) = (start, start, 0_u64, false);
    loop {
        if at >= len {
            if at > chunk_start {
                page.push(entry(parent, base, chunk_start, at, cut));
            }
            return Ok((None, false));
        }
        let off = usize::try_from(at - buf_at).unwrap_or(usize::MAX);
        let rest = buf.get(off..).unwrap_or_default();
        let newline = rest.iter().take(piece_cap).position(|byte| *byte == b'\n');
        let held_to = buf_at + buf.len() as u64;
        if newline.is_none() && rest.len() < piece_cap && held_to < len {
            let more = scan.read(body, held_to, ALIGN_BYTES as usize)?;
            if more.is_empty() {
                // The bound is spent: the page ends at the last whole line.
                if at > chunk_start {
                    page.push(entry(parent, base, chunk_start, at, cut));
                    return Ok((Some(json!({"offset": at})), true));
                }
                if page.is_empty() && !rest.is_empty() {
                    let end = at + floor_boundary(rest, rest.len()).max(1) as u64;
                    page.push(entry(parent, base, at, end, true));
                    return Ok((Some(json!({"offset": end})), true));
                }
                return Ok((Some(json!({"offset": chunk_start})), true));
            }
            buf.drain(..off.min(buf.len()));
            buf_at = at;
            buf.extend_from_slice(&more);
            continue;
        }
        let (line_len, piece) = match newline {
            Some(newline) => (newline + 1, false),
            None if rest.len() >= piece_cap => (floor_boundary(rest, piece_cap).max(1), true),
            None => (rest.len(), false),
        };
        let line = &rest[..line_len];
        let line_tokens =
            crate::tokenizer::count_context_pack_tokens(&String::from_utf8_lossy(line)) as u64;
        let held = at - chunk_start;
        if at > chunk_start
            && (count.saturating_add(line_tokens) > tokens
                || held.saturating_add(line_len as u64) > max_bytes)
        {
            page.push(entry(parent, base, chunk_start, at, cut));
            (chunk_start, count, cut) = (at, 0, false);
            if page.len() == PAGE_CHUNKS {
                return Ok((Some(json!({"offset": at})), false));
            }
            continue;
        }
        count = count.saturating_add(line_tokens);
        at += line_len as u64;
        cut |= piece;
        if count >= tokens || at - chunk_start >= max_bytes || piece {
            page.push(entry(parent, base, chunk_start, at, cut));
            (chunk_start, count, cut) = (at, 0, false);
            if page.len() == PAGE_CHUNKS && at < len {
                return Ok((Some(json!({"offset": at})), false));
            }
        }
    }
}

/// Chunks of `count` lines from `from`, found by the line index when the
/// window is the whole body, else by a bounded scan. A first chunk the scan
/// bound ends is cut there and marked `cut`. The cursor of the next page,
/// and whether the scan bound ended this one.
fn by_lines(
    body: &dyn ResultBody,
    parent: &str,
    count: u64,
    overlap: u64,
    from: LinePos,
    scan: &mut Scan,
    page: &mut Vec<Value>,
) -> Result<(Option<Value>, bool)> {
    let len = body.len();
    let base = body.base();
    let index = whole_index(body);
    let index = index.as_deref();
    let mut at = from;
    loop {
        if at.offset >= len {
            return Ok((None, false));
        }
        if page.len() == PAGE_CHUNKS {
            return Ok((Some(json!({"offset": at.offset, "line": at.lfs})), false));
        }
        let start = at;
        let (end, whole, cut) = match seek_line(body, index, start, start.lfs + count, scan)? {
            Seek::At(end) => (
                LinePos {
                    offset: end,
                    lfs: start.lfs + count,
                },
                true,
                false,
            ),
            Seek::End(end) => (end, false, false),
            Seek::Limit(reached) if page.is_empty() && reached.offset > start.offset => {
                (reached, false, true)
            }
            Seek::Limit(_) => {
                return Ok((
                    Some(json!({"offset": start.offset, "line": start.lfs})),
                    true,
                ));
            }
        };
        // The last line the chunk touches: the one before its end, when it
        // ends on a newline.
        let on_newline = whole
            || body
                .read(end.offset.saturating_sub(1), 1)?
                .first()
                .is_some_and(|byte| *byte == b'\n');
        let last = if on_newline {
            end.lfs.saturating_sub(1)
        } else {
            end.lfs
        };
        let mut chunk = entry(parent, base, start.offset, end.offset, cut);
        chunk["lines"] = json!([start.lfs, last]);
        page.push(chunk);
        at = end;
        if whole && overlap > 0 && end.offset < len {
            let back = end.lfs - overlap;
            if let Seek::At(offset) = seek_line(body, index, start, back, scan)?
                && offset > start.offset
            {
                at = LinePos { offset, lfs: back };
            }
        }
        if cut {
            return Ok((Some(json!({"offset": at.offset, "line": at.lfs})), true));
        }
    }
}
