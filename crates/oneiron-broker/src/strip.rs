//! The strip rule (SBX-001 for the model-key adapter only, ARCH-0069
//! `#model-adapter-strip-forms`): before a reply leaves the broker, each form
//! of the key it injected becomes [`MARKER`], in the body and in every header.
//!
//! The forms are the raw key, its JSON-escaped form, `Bearer <key>`, its
//! percent-encoded form, and its base64 in the standard and URL-safe alphabets,
//! with and without padding. Two widenings keep an echo from slipping past on
//! spelling alone. A key echoed inside a longer base64 text (say, `Bearer
//! <key>` encoded whole) shifts by its offset in that text, so the part of the
//! encoding that the key alone fixes is stripped at all three byte offsets.
//! And percent-encoding may spell any byte as `%XX`, so a URL-like run that
//! decodes to text holding the key is stripped whole. JSON may spell any
//! character `\uXXXX`, so text holding an escape is also read unescaped. The
//! whole reply is buffered first, so a form cannot split across reads.
//!
//! The rule works on bytes, never through a parsed JSON tree: each decoded
//! reading sits in a buffer wiped on drop.

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
    let mut out = Zeroizing::new(bytes.to_vec());
    for form in &forms {
        if memchr::memmem::find(&out, form).is_some() {
            out = replace_all(&out, form);
        }
    }
    if memchr::memchr(b'\\', &out).is_some() {
        out = strip_escaped(key, &forms, &out);
    }
    if memchr::memchr(b'%', &out).is_some() {
        out = strip_percent_runs(key, &out);
    }
    out
}

/// Whether `bytes` holds any form of `key`.
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
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        forms.push(Zeroizing::new(engine.encode(key).into_bytes()));
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for offset in 0..3 {
            forms.push(base64_core(engine, key, offset));
        }
    }
    forms.retain(|form| !form.is_empty());
    forms.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    forms.dedup();
    forms
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

/// Replaces each URL-like run holding a `%` whose decoding holds the key.
fn strip_percent_runs(key: &[u8], bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut at = 0;
    while at < bytes.len() {
        let len = bytes[at..]
            .iter()
            .take_while(|byte| is_url_byte(**byte))
            .count();
        if len == 0 {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        let run = &bytes[at..at + len];
        let decoded = percent_decoded(run);
        if run.contains(&b'%') && memchr::memmem::find(&decoded, key).is_some() {
            out.extend_from_slice(MARKER);
        } else {
            out.extend_from_slice(run);
        }
        at += len;
    }
    out
}

fn percent_decoded(run: &[u8]) -> Zeroizing<Vec<u8>> {
    percent_decoded_from(run).0
}

/// `run` percent-decoded, and for each decoded byte the span of `run` it
/// came from.
fn percent_decoded_from(run: &[u8]) -> (Zeroizing<Vec<u8>>, Vec<(usize, usize)>) {
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
        from.push((at, at + len));
        at += len;
    }
    (out, from)
}

/// Replaces each span whose JSON-unescaped reading holds a form of the key.
/// JSON may spell any character `\uXXXX`, and a provider may escape some
/// characters of an echo and not others, in a JSON body or not, and in a
/// header value. So each run of bytes that could spell a form and holds an
/// escape is read unescaped, into a buffer wiped on drop, wherever its quotes
/// fall; only the source bytes of each match become [`MARKER`].
fn strip_escaped(key: &[u8], forms: &[Zeroizing<Vec<u8>>], bytes: &[u8]) -> Zeroizing<Vec<u8>> {
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
        if run.contains(&b'\\') {
            strip_run(key, forms, run, &mut out);
        } else {
            out.extend_from_slice(run);
        }
        at = end;
    }
    out
}

/// Where the run starting at `at` ends: it takes bytes that can spell a form
/// of the key, and each escape whole.
fn run_end(key: &[u8], bytes: &[u8], mut at: usize) -> usize {
    while let Some(&byte) = bytes.get(at) {
        if byte == b'\\' {
            at += escape_len(&bytes[at..]);
        } else if byte.is_ascii_alphanumeric() || b"+/=-_%".contains(&byte) || key.contains(&byte) {
            at += 1;
        } else {
            break;
        }
    }
    at
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

/// Writes `run` to `out` with each match of a form in its unescaped reading,
/// and each key in that reading's percent-decoding, replaced at the match's
/// source bytes only.
fn strip_run(key: &[u8], forms: &[Zeroizing<Vec<u8>>], run: &[u8], out: &mut Vec<u8>) {
    let mut text = Zeroizing::new(Vec::with_capacity(run.len()));
    // The source bytes each unescaped byte came from.
    let mut sources = Vec::with_capacity(run.len());
    let mut at = 0;
    while at < run.len() {
        let len = unescape_one(&run[at..], &mut text);
        sources.resize(text.len(), (at, at + len));
        at += len;
    }
    let mut spans: Vec<(usize, usize)> = forms
        .iter()
        .flat_map(|form| {
            memchr::memmem::find_iter(&text, form.as_slice())
                .map(|found| (sources[found].0, sources[found + form.len() - 1].1))
                .collect::<Vec<_>>()
        })
        .collect();
    if memchr::memchr(b'%', &text).is_some() {
        let (decoded, from) = percent_decoded_from(&text);
        spans.extend(memchr::memmem::find_iter(&decoded, key).map(|found| {
            let (first, last) = (from[found].0, from[found + key.len() - 1].1);
            (sources[first].0, sources[last - 1].1)
        }));
    }
    spans.sort_unstable();
    let mut rest = 0;
    for (start, end) in spans {
        if end <= rest {
            continue;
        }
        if start >= rest {
            out.extend_from_slice(&run[rest..start]);
            out.extend_from_slice(MARKER);
        }
        rest = end;
    }
    out.extend_from_slice(&run[rest..]);
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

#[cfg(test)]
mod tests;
