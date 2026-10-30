//! The strip rule (SBX-001 for the model-key adapter only, ARCH-0069
//! `#model-adapter-strip-forms`): before a reply leaves the broker, each form
//! of the key it injected becomes [`MARKER`], in the body and in every header.
//!
//! The forms are the raw key, its JSON-escaped form, `Bearer <key>`, its
//! percent-encoded form, and its base64 in the standard and URL-safe alphabets,
//! with and without padding. A key echoed inside a longer base64 text (say,
//! `Bearer <key>` encoded whole) shifts by its offset in that text, so the
//! part of the encoding that the key alone fixes is a form too, at all three
//! byte offsets.
//!
//! An echo may also wear the outer spellings in any composition: JSON may
//! spell any character `\uXXXX`, percent-encoding may spell any byte `%XX`,
//! and either may spell the other's escape characters. So each run of bytes
//! that could spell a form, holding a backslash or a `%`, is also read
//! through every chain of up to [`DEPTH`] such decodings, and every form is
//! searched in every reading. A run also crosses literal whitespace between
//! its escapes (FIX 8560), or past a trailing escape to raw base64 (FIX
//! 11564), so whitespace among them never splits it. Only
//! the source bytes of each match become [`MARKER`]. A run that some chain
//! of [`DEPTH`] decodings leaves still decodable could hide a form deeper
//! than that, so the whole run becomes
//! [`MARKER`]: text encoded that deep is over-redacted, never passed. The
//! broker sends only a key in the alphabet such a run holds ([`admits`]), so a
//! part-encoded echo never splits across runs. The whole reply is buffered
//! first, so a form cannot split across reads.
//!
//! A base64 form may also come wrapped, with whitespace among its characters
//! (a MIME body's lines, say). So each stretch of base64 characters and
//! whitespace, in the reply and in each reading of a run, is also searched
//! for the base64 forms with its whitespace skipped. Only the matched bytes,
//! with the whitespace between them, become [`MARKER`]; a stretch nothing
//! matches passes as it came.
//!
//! The rule works on bytes, never through a parsed JSON tree: each decoded
//! reading sits in a buffer wiped on drop.
//!
//! A reply that streams past the buffer (a binary body,
//! [`crate::Shape::streams`]) is read through [`KeyWatch`] instead: the same
//! forms, the same runs and the same wrapped base64, redacted at the matched
//! bytes as [`strip`] redacts them, chunk by chunk, and the stream goes on
//! (FIX 6103). It holds back only the bytes a match could still reach from
//! the bytes after them; the hold is a buffering bound, never a refusal: a
//! run or stretch that outgrows it is redacted from there to its end, and
//! nothing is cut.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::{Zeroize as _, Zeroizing};

/// What every stripped form becomes.
pub const MARKER: &[u8] = b"[redacted]";

/// Returns `bytes` with every form of `key` replaced by [`MARKER`]. Longer
/// forms go first, so `Bearer <key>` is taken whole before the raw key inside
/// it. Every intermediate copy is wiped when dropped.
#[must_use]
pub fn strip(key: &[u8], bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let forms = forms(key);
    let wrapped = base64_forms(key);
    let mut out = Zeroizing::new(bytes.to_vec());
    for form in &forms {
        if memchr::memmem::find(&out, form).is_some() {
            out = replace_all(&out, form);
        }
    }
    if memchr::memchr2(b'\\', b'%', &out).is_some() {
        out = strip_encoded_runs(key, &forms, &wrapped, &out);
    }
    let mut marked = vec![0_u64; out.len().div_ceil(64)];
    wrapped_base64_matches(&wrapped, &out, |start, end| {
        mark(&mut marked, start, end);
    });
    if marked.iter().any(|&word| word != 0) {
        let mut kept = Zeroizing::new(Vec::with_capacity(out.len()));
        write_marked(&out, &marked, &mut kept);
        out = kept;
    }
    out
}

/// How many decodings, one on another, a run is read through. A run still
/// decodable after that many goes whole.
const DEPTH: usize = 3;

/// Whether the rule can be trusted with `key`: each byte is one a URL-like
/// run holds, so an echo spelled in any mix of forms stays in one run the
/// rule reads, and none is a quote, backslash or percent sign, which a
/// reply's own JSON, escapes or percent-encoding could supply to complete a
/// match. No provider issues a key outside this alphabet. Nor is the key
/// any part of [`MARKER`], which would put it back in every reply it is
/// stripped from.
pub(crate) fn admits(key: &[u8]) -> bool {
    key.iter().all(|&byte| is_url_byte(byte) && byte != b'%')
        && memchr::memmem::find(MARKER, key).is_none()
}

/// Whether `bytes` holds any form of `key`, or a run encoded too deep to rule
/// one out.
#[must_use]
pub(crate) fn contains_key(key: &[u8], bytes: &[u8]) -> bool {
    strip(key, bytes).as_slice() != bytes
}

fn replace_all(haystack: &[u8], needle: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(haystack.len()));
    let mut rest = 0;
    for at in memchr::memmem::find_iter(haystack, needle) {
        // Matches can overlap (a key like `aaaa`); the next one starts after
        // the last replaced byte.
        if at < rest {
            continue;
        }
        out.extend_from_slice(&haystack[rest..at]);
        out.extend_from_slice(MARKER);
        rest = at + needle.len();
    }
    out.extend_from_slice(&haystack[rest..]);
    out
}

/// Every form of `key`, longest first, without repeats.
fn forms(key: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut forms: Vec<Zeroizing<Vec<u8>>> = vec![Zeroizing::new(key.to_vec())];
    let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
    bearer.extend_from_slice(key);
    forms.push(bearer);
    if let Ok(text) = std::str::from_utf8(key)
        && let Ok(quoted) = serde_json::to_string(text).map(Zeroizing::new)
    {
        forms.push(Zeroizing::new(
            quoted.as_bytes()[1..quoted.len() - 1].to_vec(),
        ));
    }
    forms.push(percent_encoded(key, b"0123456789ABCDEF"));
    forms.push(percent_encoded(key, b"0123456789abcdef"));
    forms.extend(base64_forms(key));
    forms.retain(|form| !form.is_empty());
    forms.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    forms.dedup();
    forms
}

/// The base64 forms of `key`: its encoding in both alphabets, with and
/// without padding, and the core of it at each byte offset.
fn base64_forms(key: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut forms = Vec::new();
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        forms.push(Zeroizing::new(engine.encode(key).into_bytes()));
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for offset in 0..3 {
            forms.push(base64_core(engine, key, offset));
        }
    }
    forms.retain(|form| !form.is_empty());
    forms
}

/// A byte a base64 text holds, in either alphabet, padding included.
fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"+/-_=".contains(&byte)
}

/// Calls `found` with the `text` range of each match of a form in `wrapped`
/// (the key's base64 forms) in a stretch of `text` that holds base64 bytes
/// with whitespace among them, read with that whitespace skipped. A range
/// runs from the match's first byte to its last, the whitespace between
/// them included. A stretch with no whitespace inside is the contiguous
/// search's, and is skipped.
fn wrapped_base64_matches(
    wrapped: &[Zeroizing<Vec<u8>>],
    text: &[u8],
    mut found: impl FnMut(usize, usize),
) {
    if wrapped.is_empty() || !text.iter().any(u8::is_ascii_whitespace) {
        return;
    }
    // Sized once, so the reply bytes it copies never move and leave a copy
    // behind; each byte's source in `text` is no secret.
    let mut squeezed = Zeroizing::new(Vec::with_capacity(text.len()));
    let mut sources = Vec::new();
    let mut at = 0;
    while at < text.len() {
        if !is_base64_byte(text[at]) {
            at += 1;
            continue;
        }
        squeezed.clear();
        sources.clear();
        while let Some(&byte) = text.get(at) {
            if is_base64_byte(byte) {
                squeezed.push(byte);
                sources.push(at);
            } else if !byte.is_ascii_whitespace() {
                break;
            }
            at += 1;
        }
        let (Some(&first), Some(&last)) = (sources.first(), sources.last()) else {
            continue;
        };
        if last - first + 1 == sources.len() {
            continue;
        }
        for form in wrapped {
            for start in memchr::memmem::find_iter(&squeezed, form.as_slice()) {
                found(sources[start], sources[start + form.len() - 1] + 1);
            }
        }
    }
}

/// Marks the bytes from `start` up to `end`.
fn mark(marked: &mut [u64], start: usize, end: usize) {
    for at in start..end {
        marked[at / 64] |= 1 << (at % 64);
    }
}

/// Writes `text` to `out` with one [`MARKER`] for each stretch of marked
/// bytes.
fn write_marked(text: &[u8], marked: &[u64], out: &mut Vec<u8>) {
    let is_marked = |at: usize| (marked[at / 64] >> (at % 64)) & 1 == 1;
    let mut at = 0;
    while at < text.len() {
        if is_marked(at) {
            out.extend_from_slice(MARKER);
            while at < text.len() && is_marked(at) {
                at += 1;
            }
        } else {
            out.push(text[at]);
            at += 1;
        }
    }
}

/// Each byte outside the URL-unreserved set as `%XX`, in the given hex case.
fn percent_encoded(key: &[u8], hex: &[u8; 16]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(key.len() * 3));
    for &byte in key {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte);
        } else {
            out.extend_from_slice(&[
                b'%',
                hex[usize::from(byte >> 4)],
                hex[usize::from(byte & 15)],
            ]);
        }
    }
    out
}

/// The characters of the key's base64 that only the key's own bits fix, when
/// the key sits `offset` bytes into a longer encoded text: the characters
/// before it mix in bits of the bytes ahead, and the last one mixes in bits of
/// the bytes after.
fn base64_core(
    engine: &base64::engine::GeneralPurpose,
    key: &[u8],
    offset: usize,
) -> Zeroizing<Vec<u8>> {
    let mut shifted = Zeroizing::new(vec![0; offset]);
    shifted.extend_from_slice(key);
    let encoded = Zeroizing::new(engine.encode(shifted.as_slice()).into_bytes());
    let first = (offset * 8).div_ceil(6);
    let end = ((offset + key.len()) * 8) / 6;
    Zeroizing::new(encoded.get(first..end).unwrap_or_default().to_vec())
}

/// A byte that can sit inside a URL or a percent-encoded value.
fn is_url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"%-._~!$&'()*+,;=:@/?#".contains(&byte)
}

/// `run` percent-decoded, and for each decoded byte where in `run` its
/// source starts.
fn percent_decoded_from(run: &[u8]) -> Decoded {
    let hex = |byte: u8| {
        char::from(byte)
            .to_digit(16)
            .and_then(|digit| u8::try_from(digit).ok())
    };
    let mut out = Zeroizing::new(Vec::with_capacity(run.len()));
    let mut from = Vec::with_capacity(run.len());
    let mut at = 0;
    while at < run.len() {
        let pair = (run[at] == b'%')
            .then(|| Some((hex(*run.get(at + 1)?)?, hex(*run.get(at + 2)?)?)))
            .flatten();
        let len = if let Some((high, low)) = pair {
            out.push((high << 4) | low);
            3
        } else {
            out.push(run[at]);
            1
        };
        from.push(at);
        at += len;
    }
    (out, from)
}

/// Replaces, in each run of bytes that could spell a form and holds a
/// backslash or a `%`, each match of a form in any reading of the run, at the
/// match's source bytes only. A provider may escape some characters of an
/// echo and not others, in a JSON body or not, and in a header value, so a run
/// is taken wherever its quotes fall.
fn strip_encoded_runs(
    key: &[u8],
    forms: &[Zeroizing<Vec<u8>>],
    wrapped: &[Zeroizing<Vec<u8>>],
    bytes: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut at = 0;
    while at < bytes.len() {
        let end = run_end(key, bytes, at);
        if end == at {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        let run = &bytes[at..end];
        if memchr::memchr2(b'\\', b'%', run).is_some() {
            strip_run(forms, wrapped, run, &mut out);
        } else {
            out.extend_from_slice(run);
        }
        at = end;
    }
    out
}

/// Where the run starting at `at` ends: it takes bytes that can spell a form
/// of the key or an escape of one, each JSON escape and each `%XX` whole,
/// and literal whitespace that sits between escapes (FIX 8560) or past a
/// trailing escape before raw base64 (FIX 11564), so a base64 form spelled
/// in escapes, or mixed raw and escaped, stays one run: each reading
/// decodes the escapes and passes the whitespace through, and the wrapped
/// base64 search skips it. Whitespace beside no escape still ends the run,
/// so words around an encoded echo stay out of it, but for the one raw
/// stretch a trailing escape joins.
fn run_end(key: &[u8], bytes: &[u8], mut at: usize) -> usize {
    let start = at;
    let mut last_was_escape = false;
    while let Some(&byte) = bytes.get(at) {
        if byte == b'\\' {
            let len = escape_len(&bytes[at..]);
            last_was_escape = len > 1;
            at += len;
        } else if byte == b'%' && starts_percent_escape(&bytes[at..]) {
            last_was_escape = true;
            at += 3;
        } else if is_url_byte(byte) || key.contains(&byte) {
            last_was_escape = false;
            at += 1;
        } else if byte.is_ascii_whitespace()
            && ws_bridges_escapes(key, bytes, start, at, last_was_escape)
        {
            at += 1;
        } else {
            break;
        }
    }
    at
}

/// Whether `rest` starts with a percent escape: `%` and two hex digits.
fn starts_percent_escape(rest: &[u8]) -> bool {
    rest.get(..3).is_some_and(|head| {
        head[0] == b'%' && head[1].is_ascii_hexdigit() && head[2].is_ascii_hexdigit()
    })
}

/// Whether `rest` starts with a JSON escape.
fn starts_json_escape(rest: &[u8]) -> bool {
    rest.first() == Some(&b'\\') && escape_len(rest) > 1
}

/// Whether the whitespace at `at` joins the run from `start` (FIX 8560): an
/// escape sequence starts past it and the run already holds one, or the run
/// ends with one and the next stretch holds one, or is raw base64 (FIX
/// 11564), the raw part of a mixed form. An escape always stands beside the
/// whitespace; the run's readings decode what it joins, and the wrapped
/// base64 search skips it.
fn ws_bridges_escapes(
    key: &[u8],
    bytes: &[u8],
    start: usize,
    at: usize,
    last_was_escape: bool,
) -> bool {
    let mut next = at;
    while bytes
        .get(next)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        next += 1;
    }
    let rest = &bytes[next..];
    let starts_escape = starts_percent_escape(rest) || starts_json_escape(rest);
    if starts_escape && memchr::memchr2(b'\\', b'%', &bytes[start..at]).is_some() {
        return true;
    }
    if !last_was_escape {
        return false;
    }
    let mut end = next;
    while let Some(&byte) = bytes.get(end) {
        if byte == b'\\' {
            end += escape_len(&bytes[end..]);
        } else if is_url_byte(byte) || key.contains(&byte) {
            end += 1;
        } else {
            break;
        }
    }
    let stretch = &bytes[next..end];
    // The raw part of a mixed form: past a trailing escape, a raw base64
    // stretch joins the run as an escape does (FIX 11564).
    memchr::memchr2(b'\\', b'%', stretch).is_some()
        || (!stretch.is_empty() && stretch.iter().all(|byte| is_base64_byte(*byte)))
}

/// A decoding of a reading: the decoded bytes, and for each where in the
/// reading its source starts. The sources tile the reading in order, so a
/// byte's source ends where the next different start begins.
type Decoded = (Zeroizing<Vec<u8>>, Vec<usize>);

/// A decoding, and the escape character it reads.
type Decoding = (u8, fn(&[u8]) -> Decoded);

/// Writes `run` to `out` with each match of a form, in the run as sent and
/// in each reading through up to [`DEPTH`] decodings (JSON-unescaped or
/// percent-decoded, in any order), replaced at the match's source bytes only:
/// one [`MARKER`] per stretch of marked bytes. A match marks one bit per run
/// byte, so overlapping and repeated matches cost no more room. A reading
/// [`DEPTH`] decodings deep that can still be decoded marks the whole run.
/// Each reading is also searched for the `wrapped` forms with the whitespace
/// inside its base64 stretches skipped.
fn strip_run(
    forms: &[Zeroizing<Vec<u8>>],
    wrapped: &[Zeroizing<Vec<u8>>],
    run: &[u8],
    out: &mut Vec<u8>,
) {
    write_marked(run, &run_marks(forms, wrapped, run), out);
}

/// The bytes of `run` that [`strip_run`] replaces, one bit per byte.
fn run_marks(forms: &[Zeroizing<Vec<u8>>], wrapped: &[Zeroizing<Vec<u8>>], run: &[u8]) -> Vec<u64> {
    let mut marked = vec![0_u64; run.len().div_ceil(64)];
    let reading = Reading {
        forms,
        wrapped,
        run_len: run.len(),
    };
    search(&reading, run, None, 0, &mut marked);
    marked
}

/// What every reading of one run is searched for, and the run's length.
struct Reading<'f> {
    forms: &'f [Zeroizing<Vec<u8>>],
    wrapped: &'f [Zeroizing<Vec<u8>>],
    run_len: usize,
}

/// Marks the run bytes of each form in `text`, a reading `depth` decodings
/// deep whose bytes' sources start at `starts` in the run (the run itself
/// when `None`), then reads it through each decoding that changes it. Depth
/// first, so only one chain of readings is held at a time. At [`DEPTH`], a
/// reading that can still be decoded marks every run byte.
fn search(
    reading: &Reading<'_>,
    text: &[u8],
    starts: Option<&[usize]>,
    depth: usize,
    marked: &mut [u64],
) {
    // The run span of `text[first..end]`: from its first byte's start to the
    // next different start after its last byte, or the run's end.
    let span = |first: usize, end: usize| match starts {
        Some(starts) => (
            starts[first],
            starts[end..]
                .iter()
                .copied()
                .find(|&start| start != starts[end - 1])
                .unwrap_or(reading.run_len),
        ),
        None => (first, end),
    };
    for form in reading.forms {
        for found in memchr::memmem::find_iter(text, form.as_slice()) {
            let (start, end) = span(found, found + form.len());
            mark(marked, start, end);
        }
    }
    wrapped_base64_matches(reading.wrapped, text, |first, end| {
        let (start, end) = span(first, end);
        mark(marked, start, end);
    });
    if depth == DEPTH {
        if still_decodes(text) {
            marked.fill(u64::MAX);
        }
        return;
    }
    let decodings: [Decoding; 2] = [(b'\\', json_unescaped_from), (b'%', percent_decoded_from)];
    for (escape, decode) in decodings {
        if memchr::memchr(escape, text).is_none() {
            continue;
        }
        let (decoded, from) = decode(text);
        if decoded.as_slice() == text {
            continue;
        }
        let from: Vec<usize> = match starts {
            Some(starts) => from.into_iter().map(|at| starts[at]).collect(),
            None => from,
        };
        search(reading, &decoded, Some(&from), depth + 1, marked);
    }
}

/// Whether a decoding would still read an escape in `text`: a `%` and two hex
/// digits, or a JSON escape. It allocates nothing, so failing closed costs no
/// room beyond the search.
fn still_decodes(text: &[u8]) -> bool {
    memchr::memchr2_iter(b'\\', b'%', text).any(|at| {
        if text[at] == b'%' {
            text.get(at + 1..at + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
        } else {
            escape_len(&text[at..]) > 1
        }
    })
}

/// `run` JSON-unescaped, and for each unescaped byte where in `run` its
/// source starts.
fn json_unescaped_from(run: &[u8]) -> Decoded {
    let mut text = Zeroizing::new(Vec::with_capacity(run.len()));
    let mut from = Vec::with_capacity(run.len());
    let mut at = 0;
    while at < run.len() {
        let len = unescape_one(&run[at..], &mut text);
        from.resize(text.len(), at);
        at += len;
    }
    (text, from)
}

/// The length of the escape `rest` starts with, or 1 for a lone backslash.
fn escape_len(rest: &[u8]) -> usize {
    match rest.get(1) {
        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => 2,
        Some(b'u') if hex4(rest.get(2..6)).is_some() => 6,
        _ => 1,
    }
}

fn hex4(digits: Option<&[u8]>) -> Option<u32> {
    let digits = digits?;
    if digits.len() != 4 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

/// Reads the escape or the byte `rest` starts with, pushes what it spells
/// onto `text`, and returns its length.
fn unescape_one(rest: &[u8], text: &mut Vec<u8>) -> usize {
    let simple = match rest.get(..2) {
        Some([b'\\', b'"']) => Some(b'"'),
        Some([b'\\', b'\\']) => Some(b'\\'),
        Some([b'\\', b'/']) => Some(b'/'),
        Some([b'\\', b'b']) => Some(8),
        Some([b'\\', b'f']) => Some(12),
        Some([b'\\', b'n']) => Some(b'\n'),
        Some([b'\\', b'r']) => Some(b'\r'),
        Some([b'\\', b't']) => Some(b'\t'),
        _ => None,
    };
    if let Some(byte) = simple {
        text.push(byte);
        return 2;
    }
    let unit = |from: usize| match rest.get(from..from + 2) {
        Some(b"\\u") => hex4(rest.get(from + 2..from + 6)),
        _ => None,
    };
    let (point, len) = match (unit(0), unit(6)) {
        (Some(high @ 0xD800..=0xDBFF), Some(low @ 0xDC00..=0xDFFF)) => {
            (0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00), 12)
        }
        (Some(point), _) => (point, 6),
        (None, _) => {
            text.push(rest[0]);
            return 1;
        }
    };
    match char::from_u32(point) {
        Some(c) => {
            let mut utf8 = [0; 4];
            text.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            utf8.zeroize();
            len
        }
        // A lone surrogate spells no character: read the backslash as itself.
        None => {
            text.push(rest[0]);
            1
        }
    }
}

mod watch;
pub(crate) use watch::KeyWatch;

#[cfg(test)]
mod tests;
