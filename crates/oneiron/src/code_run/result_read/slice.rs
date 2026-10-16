//! `slice`: one range of a result's body, by bytes or by lines, at most one
//! reply of it, with where to go on from. Text is cut at character
//! boundaries and shown as a string, anything else as base64; the stored
//! bytes, CRLFs and invalid UTF-8 are never changed, only the view of them.

use super::{
    LinePos, ReadBounds, Reply, ResultBody, Scan, Seek, count_lf, decode, encoded_len,
    floor_boundary, invalid_input, lfs_before, refusal, scan_limit, seek_line, view, whole_index,
};
use crate::Result;
use crate::code_run::CodeRunOutputKind;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SliceInput {
    #[serde(default)]
    bytes: Option<Vec<u64>>,
    #[serde(default)]
    lines: Option<Vec<u64>>,
    /// Where an earlier line lookup reached the scan bound.
    #[serde(default)]
    cursor: Option<LineCursor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LineCursor {
    offset: u64,
    line: u64,
}

/// `[start, end?]`, half-open, the end not before the start.
fn span(range: &[u64]) -> Option<(u64, Option<u64>)> {
    match range {
        [start] => Some((*start, None)),
        [start, end] if start <= end => Some((*start, Some(*end))),
        _ => None,
    }
}

fn asked(start: u64, end: Option<u64>) -> Value {
    match end {
        Some(end) => json!([start, end]),
        None => json!([start]),
    }
}

/// `slice`: see the module.
pub(super) fn slice(
    body: &dyn ResultBody,
    reference: &str,
    input: Value,
    bounds: &ReadBounds<'_>,
) -> Result<Reply> {
    let input: SliceInput = match decode(input) {
        Ok(input) => input,
        Err(refused) => return Ok(Reply::Denied(refused)),
    };
    let text = body.kind() == CodeRunOutputKind::Text;
    let len = body.len();
    let mut scan = Scan::new(bounds.scan_bytes());
    let index = whole_index(body);
    let index = index.as_deref();
    let bytes_span = input.bytes.as_deref().map(span);
    let lines_span = input.lines.as_deref().map(span);
    // The range asked for, in bytes: by lines, its first line found by the
    // line index or a bounded scan, its end only within one reply of it.
    let (start, end, asked_end, by_lines) = match (bytes_span, lines_span) {
        (Some(Some((start, end))), None) => (
            start.min(len),
            end.map_or(len, |end| end.min(len)),
            end,
            None,
        ),
        (None, Some(Some((first, last)))) => {
            if !text {
                return Ok(Reply::Denied(refusal("lines_on_binary")));
            }
            let from = input.cursor.map_or(LinePos::START, |cursor| LinePos {
                offset: cursor.offset.min(len),
                lfs: cursor.line,
            });
            let start = match seek_line(body, index, from, first, &mut scan)? {
                Seek::At(start) => start,
                Seek::End(_) => len,
                Seek::Limit(at) => {
                    return Ok(Reply::Output(json!({
                        "ref": reference,
                        "done": false,
                        "scanned": [from.offset, at.offset],
                        "limit": scan_limit(),
                        "next": {
                            "lines": asked(first, last),
                            "cursor": {"offset": at.offset, "line": at.lfs},
                        },
                    })));
                }
            };
            let end = match last {
                None => len,
                Some(last) => {
                    let mut near = Scan::new(bounds.reply_bytes as u64 + 1);
                    let at = LinePos {
                        offset: start,
                        lfs: first,
                    };
                    match seek_line(body, None, at, last, &mut near)? {
                        Seek::At(end) => end,
                        Seek::End(_) => len,
                        Seek::Limit(at) => at.offset,
                    }
                }
            };
            (start, end, None, Some((first, last)))
        }
        _ => {
            return Ok(Reply::Denied(invalid_input(
                "slice takes bytes: [start, end?] or lines: [start, end?]",
            )));
        }
    };
    // Text starts on a character boundary: back to the start of a
    // character the range cuts, by at most three bytes.
    let behind = if text { start.min(3) } else { 0 };
    let from = start - behind;
    let room = if text {
        bounds.reply_bytes
    } else {
        (bounds.reply_bytes / 4 * 3).saturating_sub(4096)
    };
    let mut take = usize::try_from(end - start).unwrap_or(usize::MAX).min(room);
    // Four bytes past the cut show whether it splits a character.
    let bytes = body.read(from, behind as usize + take + 4)?;
    let first = if text && by_lines.is_none() {
        floor_boundary(&bytes, behind as usize)
    } else {
        behind as usize
    };
    let start = from + first as u64;
    let end_at = usize::try_from(end - from).unwrap_or(usize::MAX);
    let first_line = match by_lines {
        Some((line, _)) => Some(line),
        None if text => lfs_before(body, index, start, &mut scan)?,
        None => None,
    };
    loop {
        let mut cut_at = (first + take).min(bytes.len()).min(end_at);
        let cut = cut_at < end_at;
        let mut whole_lines = false;
        if cut
            && by_lines.is_some()
            && let Some(newline) = bytes[first..cut_at].iter().rposition(|byte| *byte == b'\n')
        {
            cut_at = first + newline + 1;
            whole_lines = true;
        }
        if text {
            cut_at = floor_boundary(&bytes, cut_at).max(first);
        }
        let content = &bytes[first..cut_at];
        let stop = from + cut_at as u64;
        let (shown, lossy) = view(content, text);
        let mut reply = json!({"ref": reference, "start": start, "end": stop, "done": !cut});
        reply[if text { "text" } else { "base64" }] = shown;
        if lossy {
            reply["lossy"] = json!(true);
        }
        if let Some(line) = first_line
            && let Some((_, before_last)) = content.split_last()
        {
            reply["lines"] = json!([line, line + count_lf(before_last)]);
        }
        if cut {
            reply["next"] = match (by_lines, first_line) {
                (Some((_, last)), Some(line)) if whole_lines => {
                    json!({"lines": asked(line + count_lf(content), last)})
                }
                (Some(_), _) => json!({"bytes": [stop, end]}),
                (None, _) => json!({"bytes": asked(stop, asked_end)}),
            };
        }
        if encoded_len(&reply) <= bounds.reply_bytes || take == 0 {
            return Ok(Reply::Output(reply));
        }
        take /= 2;
    }
}
