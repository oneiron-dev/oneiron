//! A known value spelled another way in incoming bytes (FIX 2725): standard
//! or URL-safe base64, padded or not; percent escapes, in either hex case,
//! all or some of its bytes; JSON string escapes (`\"`, `\\`, `\/`, `\b`,
//! `\f`, `\n`, `\r`, `\t` and `\uXXXX`, a surrogate pair included). Nothing
//! is stored for a spelling: the incoming bytes are read as each spelling
//! decodes them, into a guarded copy that keeps where each decoded byte came
//! from, and the index matches the decoded bytes as it matches raw ones. A
//! value found there masks the span its spelling takes, under the handle of
//! the record that holds the value.
//!
//! A base64 spelling is a whole run of base64 that decodes to exactly the
//! value. A value inside a longer base64 run, at an offset its quanta do not
//! align to, or a run folded over lines, is not read here.

use std::ops::Range;

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use zeroize::Zeroizing;

/// How many bytes of a spelling one byte of a value can take at most: a
/// JSON `\u00XX` escape's six (CALLS KNOWN_FORM_REACH_FACTOR, open). A
/// stream's sweep holds this many bytes for each byte of the longest value
/// it knows, so a spelling still arriving is held whole, never let through
/// in part; the stream's end lets everything through. One constant, so a
/// ruling changes one line.
pub(super) const KNOWN_FORM_REACH_FACTOR: usize = 6;

const PADDING_EITHER: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
const BASE64_STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, PADDING_EITHER);
const BASE64_URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, PADDING_EITHER);

/// Incoming bytes with one spelling's escapes decoded, guarded, and the
/// incoming span each decoded byte came from.
pub(super) struct View {
    pub(super) bytes: Zeroizing<Vec<u8>>,
    starts: Vec<usize>,
    lens: Vec<u8>,
}

impl View {
    fn with_capacity(len: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(len)),
            starts: Vec::with_capacity(len),
            lens: Vec::with_capacity(len),
        }
    }

    fn push(&mut self, byte: u8, from: usize, len: u8) {
        self.bytes.push(byte);
        self.starts.push(from);
        self.lens.push(len);
    }

    /// The incoming span decoded `span` came from, when an escape is part of
    /// it: a span read as it came in is the raw pass's.
    pub(super) fn source(&self, span: Range<usize>) -> Option<Range<usize>> {
        let lens = self.lens.get(span.clone())?;
        if !lens.iter().any(|len| *len > 1) {
            return None;
        }
        let start = *self.starts.get(span.start)?;
        let last = span.end.checked_sub(1)?;
        Some(start..self.starts.get(last)? + usize::from(*self.lens.get(last)?))
    }
}

/// `data` with each percent escape (`%` and two hex digits, either case)
/// decoded; `None` when it holds none.
pub(super) fn percent_view(data: &[u8]) -> Option<View> {
    if !data.contains(&b'%') {
        return None;
    }
    let mut view = View::with_capacity(data.len());
    let mut escaped = false;
    let mut at = 0;
    while let Some(&byte) = data.get(at) {
        let digit = |offset: usize| data.get(at + offset).and_then(|byte| hex_digit(*byte));
        match (byte, digit(1), digit(2)) {
            (b'%', Some(high), Some(low)) => {
                view.push((high << 4) | low, at, 3);
                escaped = true;
                at += 3;
            }
            _ => {
                view.push(byte, at, 1);
                at += 1;
            }
        }
    }
    escaped.then_some(view)
}

/// `data` with each JSON string escape decoded, a `\uXXXX` to its UTF-8
/// bytes; `None` when it holds none. An escape JSON does not take, or a lone
/// surrogate, reads as it came.
pub(super) fn json_view(data: &[u8]) -> Option<View> {
    if !data.contains(&b'\\') {
        return None;
    }
    let mut view = View::with_capacity(data.len());
    let mut escaped = false;
    let mut at = 0;
    while let Some(&byte) = data.get(at) {
        if byte == b'\\'
            && let Some((decoded, len)) = json_escape(&data[at..])
        {
            let mut utf8 = Zeroizing::new([0u8; 4]);
            for &decoded in decoded.encode_utf8(&mut utf8[..]).as_bytes() {
                view.push(decoded, at, len);
            }
            escaped = true;
            at += usize::from(len);
            continue;
        }
        view.push(byte, at, 1);
        at += 1;
    }
    escaped.then_some(view)
}

/// The character the JSON escape `rest` starts with stands for, and how many
/// bytes the escape takes.
fn json_escape(rest: &[u8]) -> Option<(char, u8)> {
    let simple = match rest.get(1)? {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'u' => return unicode_escape(rest),
        _ => return None,
    };
    Some((simple, 2))
}

/// A `\uXXXX` escape, or a surrogate pair of two.
fn unicode_escape(rest: &[u8]) -> Option<(char, u8)> {
    let unit = |at: usize| -> Option<u32> {
        let digits = rest.get(at..at + 4)?;
        digits.iter().try_fold(0u32, |held, byte| {
            Some((held << 4) | u32::from(hex_digit(*byte)?))
        })
    };
    let first = unit(2)?;
    if !(0xD800..0xDC00).contains(&first) {
        return char::from_u32(first).map(|decoded| (decoded, 6));
    }
    if rest.get(6..8)? != b"\\u" {
        return None;
    }
    let second = unit(8)?;
    if !(0xDC00..0xE000).contains(&second) {
        return None;
    }
    char::from_u32(0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00))
        .map(|decoded| (decoded, 12))
}

fn hex_digit(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

fn base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

/// Each whole run of base64 in `data` (its alphabet's characters, then up to
/// two `=`), no longer than `reach`, whose decoded length `fits`, decoded in
/// the alphabet it is spelled in: where it sits and its bytes, guarded. A
/// run that mixes the two alphabets, or decodes in neither, is passed over.
pub(super) fn base64_runs(
    data: &[u8],
    reach: usize,
    fits: impl Fn(usize) -> bool,
) -> Vec<(Range<usize>, Zeroizing<Vec<u8>>)> {
    let mut runs = Vec::new();
    let mut at = 0;
    while at < data.len() {
        if !base64_byte(data[at]) {
            at += 1;
            continue;
        }
        let start = at;
        let (mut standard, mut url_safe) = (false, false);
        while let Some(&byte) = data.get(at).filter(|byte| base64_byte(**byte)) {
            standard |= matches!(byte, b'+' | b'/');
            url_safe |= matches!(byte, b'-' | b'_');
            at += 1;
        }
        let body = at - start;
        while at - start < body + 2 && data.get(at) == Some(&b'=') {
            at += 1;
        }
        if at - start > reach || (standard && url_safe) || !fits(body * 3 / 4) {
            continue;
        }
        let engine = if url_safe {
            &BASE64_URL_SAFE
        } else {
            &BASE64_STANDARD
        };
        let mut decoded = Zeroizing::new(Vec::new());
        if engine.decode_vec(&data[start..at], &mut decoded).is_ok() && !decoded.is_empty() {
            runs.push((start..at, decoded));
        }
    }
    runs
}

/// What `bytes`, a whole span, reads as in each spelling it could be in:
/// base64, percent escapes, JSON escapes. Each copy is guarded.
pub(in crate::secret_custody) fn decodings(bytes: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut decoded: Vec<Zeroizing<Vec<u8>>> = base64_runs(bytes, bytes.len(), |_| true)
        .into_iter()
        .filter(|(run, _)| *run == (0..bytes.len()))
        .map(|(_, decoded)| decoded)
        .collect();
    decoded.extend(
        [percent_view(bytes), json_view(bytes)]
            .into_iter()
            .flatten()
            .map(|view| view.bytes),
    );
    decoded
}
