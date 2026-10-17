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
//! searched in every reading. Only the source bytes of each match become
//! [`MARKER`]. A run that some chain of [`DEPTH`] decodings leaves still
//! decodable could hide a form deeper than that, so the whole run becomes
//! [`MARKER`]: text encoded that deep is over-redacted, never passed. The
//! broker sends only a key in the alphabet such a run holds ([`admits`]), so a
//! part-encoded echo never splits across runs. The whole reply is buffered
//! first, so a form cannot split across reads.
//!
//! The rule works on bytes, never through a parsed JSON tree: each decoded
//! reading sits in a buffer wiped on drop.
//!
//! A reply that streams past the buffer (a binary body,
//! [`crate::Shape::streams`]) is read through [`KeyWatch`] instead: the same
//! forms and the same runs, checked chunk by chunk, and the body passed
//! unchanged or cut, never rewritten.

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
    if memchr::memchr2(b'\\', b'%', &out).is_some() {
        out = strip_encoded_runs(key, &forms, &out);
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
            strip_run(forms, run, &mut out);
        } else {
            out.extend_from_slice(run);
        }
        at = end;
    }
    out
}

/// Where the run starting at `at` ends: it takes bytes that can spell a form
/// of the key or an escape of one, and each JSON escape whole.
fn run_end(key: &[u8], bytes: &[u8], mut at: usize) -> usize {
    while let Some(&byte) = bytes.get(at) {
        if byte == b'\\' {
            at += escape_len(&bytes[at..]);
        } else if is_url_byte(byte) || key.contains(&byte) {
            at += 1;
        } else {
            break;
        }
    }
    at
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
fn strip_run(forms: &[Zeroizing<Vec<u8>>], run: &[u8], out: &mut Vec<u8>) {
    let mut marked = vec![0_u64; run.len().div_ceil(64)];
    search(forms, run, None, 0, run.len(), &mut marked);
    let is_marked = |at: usize| (marked[at / 64] >> (at % 64)) & 1 == 1;
    let mut at = 0;
    while at < run.len() {
        if is_marked(at) {
            out.extend_from_slice(MARKER);
            while at < run.len() && is_marked(at) {
                at += 1;
            }
        } else {
            out.push(run[at]);
            at += 1;
        }
    }
}

/// Marks the run bytes of each form in `text`, a reading `depth` decodings
/// deep whose bytes' sources start at `starts` in the run of `run_len` bytes
/// (the run itself when `None`), then reads it through each decoding that
/// changes it. Depth first, so only one chain of readings is held at a time.
/// At [`DEPTH`], a reading that can still be decoded marks every run byte.
fn search(
    forms: &[Zeroizing<Vec<u8>>],
    text: &[u8],
    starts: Option<&[usize]>,
    depth: usize,
    run_len: usize,
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
                .unwrap_or(run_len),
        ),
        None => (first, end),
    };
    for form in forms {
        for found in memchr::memmem::find_iter(text, form.as_slice()) {
            let (start, end) = span(found, found + form.len());
            for at in start..end {
                marked[at / 64] |= 1 << (at % 64);
            }
        }
    }
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
        search(forms, &decoded, Some(&from), depth + 1, run_len, marked);
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

/// The longest run a streamed reply may hold open across chunks. A run
/// that long cannot be read cheaply, so it cuts the reply, as a run encoded
/// too deep is redacted whole by [`strip`].
const MAX_HELD_RUN: usize = 1 << 20;

/// A form of the key, or a run too long to rule one out, in a streamed reply.
#[derive(Debug)]
pub(crate) struct KeyFound;

/// The strip rule for a reply read as it streams, whose body must pass
/// unchanged: it finds what [`strip`] would replace, and says so instead of
/// replacing it. A byte is cleared to pass once no form and no run that could
/// still grow from the bytes after it can reach back over it, so it holds
/// back the longest form's length less one, and the run still open.
pub(crate) struct KeyWatch<'k> {
    key: &'k [u8],
    forms: Vec<Zeroizing<Vec<u8>>>,
    /// The longest form's length less one.
    reach: usize,
    /// Bytes read and not yet cleared. They start where a run starts, or at
    /// a byte no run holds, as the whole body's reading would.
    held: Zeroizing<Vec<u8>>,
}

impl<'k> KeyWatch<'k> {
    pub(crate) fn new(key: &'k [u8]) -> Self {
        let forms = forms(key);
        let reach = forms.iter().map(|form| form.len()).max().unwrap_or(1) - 1;
        Self {
            key,
            forms,
            reach,
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// Takes the next chunk, and returns the bytes now cleared to pass.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyFound> {
        let mut data = Zeroizing::new(Vec::with_capacity(self.held.len() + chunk.len()));
        data.extend_from_slice(&self.held);
        data.extend_from_slice(chunk);
        let cleared = self.check(&data, false)?;
        self.held = Zeroizing::new(data[cleared..].to_vec());
        if self.held.len() > MAX_HELD_RUN + self.reach {
            return Err(KeyFound);
        }
        Ok(Zeroizing::new(data[..cleared].to_vec()))
    }

    /// Ends the reply, and returns the bytes still held, now cleared.
    pub(crate) fn finish(&mut self) -> Result<Zeroizing<Vec<u8>>, KeyFound> {
        self.check(&self.held, true)?;
        Ok(std::mem::take(&mut self.held))
    }

    /// Checks `data` for every form, and each run in it for every reading,
    /// and returns how many of its first bytes are cleared: up to the last
    /// run start at or before the reach of a form from the end, and never
    /// into a run that reaches the end and may go on. At the reply's `end`,
    /// every run is closed and every byte cleared.
    fn check(&self, data: &[u8], end: bool) -> Result<usize, KeyFound> {
        if self
            .forms
            .iter()
            .any(|form| memchr::memmem::find(data, form).is_some())
        {
            return Err(KeyFound);
        }
        let bound = if end {
            data.len()
        } else {
            data.len().saturating_sub(self.reach)
        };
        let mut cleared = 0;
        let mut at = 0;
        while at < data.len() {
            if at <= bound {
                cleared = at;
            }
            let stop = run_end(self.key, data, at);
            if stop == at {
                at += 1;
                continue;
            }
            if stop == data.len() && !end {
                return Ok(cleared);
            }
            let run = &data[at..stop];
            if memchr::memchr2(b'\\', b'%', run).is_some() {
                let mut read = Zeroizing::new(Vec::with_capacity(run.len()));
                strip_run(&self.forms, run, &mut read);
                if read.as_slice() != run {
                    return Err(KeyFound);
                }
            }
            at = stop;
        }
        if at <= bound {
            cleared = at;
        }
        Ok(cleared)
    }
}

#[cfg(test)]
mod tests;
