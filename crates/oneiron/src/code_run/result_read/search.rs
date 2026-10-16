//! `search`: the matches of a literal (by default) or a regex in a result,
//! each with its offset, line and context, and a cursor past the last.
//!
//! One engine serves both: a literal is an escaped regex. The body is read
//! in windows of 8 MiB that keep their last 1 MiB as a margin. A match that
//! ends inside the margin, before the body's end, is not taken from this
//! window: the next window starts at it, so a match no longer than the
//! margin is always found whole, and none is reported twice. A few bytes
//! before each window are kept, so `\b` and `(?m)^` see the byte before it.
//! The read stops at the scan bound with a cursor, never with a false "no
//! match".

use super::{
    LinePos, ReadBounds, Reply, ResultBody, Scan, ceil_boundary, count_lf, decode, encoded_len,
    floor_boundary, refusal, scan_limit, view,
};
use crate::Result;
use crate::code_run::CodeRunOutputKind;
use regex::bytes::RegexBuilder;
use serde::Deserialize;
use serde_json::{Value, json};

/// Bytes of one search window.
const WINDOW: u64 = 8 << 20;

/// Bytes at a window's end whose matches the next window takes.
const MARGIN: u64 = 1 << 20;

/// Bytes kept before a window for its look-behind.
const BEHIND: u64 = 4;

/// Matches one search returns unless it asks for fewer.
const DEFAULT_LIMIT: usize = 100;

/// Bytes of context on each side of a match unless it asks otherwise, and
/// at most.
const DEFAULT_CONTEXT: usize = 80;
const MAX_CONTEXT: usize = 1024;

/// Bytes of a match's own text a reply shows at most.
const MATCH_TEXT_BYTES: usize = 1024;

/// Bytes of a reply kept for its fields around the matches.
const REPLY_FIELD_BYTES: usize = 4 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SearchInput {
    pattern: String,
    #[serde(default)]
    regex: bool,
    #[serde(default)]
    ignore_case: bool,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    context: Option<usize>,
    #[serde(default)]
    cursor: Option<SearchCursor>,
}

/// Where a search goes on: a byte offset and the line it is on.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchCursor {
    offset: u64,
    line: u64,
}

/// `search`: see the module.
pub(super) fn search(
    body: &dyn ResultBody,
    reference: &str,
    input: Value,
    bounds: &ReadBounds<'_>,
) -> Result<Reply> {
    let input: SearchInput = match decode(input) {
        Ok(input) => input,
        Err(refused) => return Ok(Reply::Denied(refused)),
    };
    let text = body.kind() == CodeRunOutputKind::Text;
    if input.pattern.is_empty() {
        let mut refused = refusal("bad_pattern");
        refused["error"] = json!("the pattern is empty");
        return Ok(Reply::Denied(refused));
    }
    let source = if input.regex {
        input.pattern.clone()
    } else {
        regex::escape(&input.pattern)
    };
    // A text body matches by character; a binary one by byte, with the
    // pattern's own UTF-8 as its bytes.
    let regex = match RegexBuilder::new(&source)
        .unicode(text)
        .case_insensitive(input.ignore_case)
        .build()
    {
        Ok(regex) => regex,
        Err(error) => {
            let mut refused = refusal("bad_pattern");
            refused["error"] = json!(error.to_string());
            return Ok(Reply::Denied(refused));
        }
    };
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT).max(1);
    let context = input.context.unwrap_or(DEFAULT_CONTEXT).min(MAX_CONTEXT);
    let budget = bounds.reply_bytes.saturating_sub(REPLY_FIELD_BYTES);
    let len = body.len();
    let begin = input
        .cursor
        .as_ref()
        .map_or(0, |cursor| cursor.offset.min(len));
    let mut line = LinePos {
        offset: begin,
        lfs: input.cursor.as_ref().map_or(0, |cursor| cursor.line),
    };
    let mut scan = Scan::new(bounds.scan_bytes());
    let mut a = begin;
    let mut hay_start = a.saturating_sub(BEHIND);
    let mut hay: Vec<u8> = Vec::new();
    let mut matches = Vec::new();
    let mut size = 0;
    // Where the search stops short of the end, and whether the scan bound
    // stopped it.
    let mut stopped: Option<(LinePos, bool)> = None;
    while a < len && stopped.is_none() {
        // The window: [a, b), with the look-behind before it held.
        let keep = a.saturating_sub(BEHIND).max(hay_start);
        hay.drain(..usize::try_from(keep - hay_start).unwrap_or(hay.len()));
        hay_start = keep;
        let full = a.saturating_add(WINDOW).min(len);
        let mut b = hay_start + hay.len() as u64;
        while b < full {
            let want = usize::try_from(full - b).unwrap_or(usize::MAX);
            let piece = scan.read(body, b, want.min(super::READ_PIECE_BYTES))?;
            if piece.is_empty() {
                break;
            }
            b += piece.len() as u64;
            hay.extend_from_slice(&piece);
        }
        let last = b == len;
        let cut = !last && b < full;
        if !last && b <= a + MARGIN {
            stopped = Some((line, true));
            break;
        }
        let at = |offset: u64| usize::try_from(offset - hay_start).unwrap_or(usize::MAX);
        let mut pos = at(a);
        let mut deferred = None;
        let mut last_end = a;
        while let Some(found) = regex.find_at(&hay, pos) {
            if found.start() == found.end() {
                pos = found.end() + 1;
                if pos > hay.len() {
                    break;
                }
                continue;
            }
            let (s, e) = (
                hay_start + found.start() as u64,
                hay_start + found.end() as u64,
            );
            let whole = last || e < b - MARGIN;
            let truncated = !whole && s == a && !cut && b - a >= WINDOW;
            if !whole && !truncated {
                deferred = Some(s);
                break;
            }
            line.lfs += count_lf(&hay[at(line.offset)..found.start()]);
            line.offset = s;
            let entry = match_entry(
                &hay,
                hay_start,
                found.range(),
                line.lfs,
                context,
                text,
                truncated,
            );
            let entry_size = encoded_len(&entry) + 1;
            if size + entry_size > budget {
                stopped = Some((line, false));
                break;
            }
            size += entry_size;
            matches.push(entry);
            last_end = e;
            if matches.len() == limit {
                let after = LinePos {
                    offset: e,
                    lfs: line.lfs + count_lf(&hay[found.range()]),
                };
                stopped = Some((after, false));
                break;
            }
            pos = found.end();
        }
        if stopped.is_some() || (last && deferred.is_none()) {
            break;
        }
        let advance = deferred.unwrap_or_else(|| (b - MARGIN).max(last_end));
        line.lfs += count_lf(&hay[at(line.offset)..at(advance)]);
        line.offset = advance;
        if cut {
            stopped = Some((line, true));
            break;
        }
        a = advance;
    }
    let mut reply = json!({
        "ref": reference,
        "matches": matches,
        "encoding": if text { "utf8" } else { "base64" },
        "done": stopped.is_none(),
    });
    match stopped {
        None => reply["scanned"] = json!([begin, len]),
        Some((next, limited)) => {
            reply["scanned"] = json!([begin, next.offset]);
            reply["next"] = json!({"offset": next.offset, "line": next.lfs});
            if limited {
                reply["limit"] = scan_limit();
            }
        }
    }
    Ok(Reply::Output(reply))
}

/// One match as a reply shows it: where it is, its line, its text and the
/// context around it within the window read, each cut at a character
/// boundary in text and given as base64 otherwise.
fn match_entry(
    hay: &[u8],
    hay_start: u64,
    range: std::ops::Range<usize>,
    line: u64,
    context: usize,
    text: bool,
    truncated: bool,
) -> Value {
    let snap_back = |at: usize| if text { floor_boundary(hay, at) } else { at };
    let snap_on = |at: usize| if text { ceil_boundary(hay, at) } else { at };
    let shown = snap_back((range.start + MATCH_TEXT_BYTES).min(range.end)).max(range.start);
    let before = snap_on(range.start.saturating_sub(context)).min(range.start);
    let after = snap_back((range.end + context).min(hay.len())).max(range.end);
    let mut entry = json!({
        "offset": hay_start + range.start as u64,
        "len": range.len(),
        "line": line,
        "text": view(&hay[range.start..shown], text).0,
        "before": view(&hay[before..range.start], text).0,
        "after": view(&hay[range.end..after], text).0,
    });
    if truncated {
        entry["truncated"] = json!(true);
    }
    entry
}
