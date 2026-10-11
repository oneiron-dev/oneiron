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
//! decodes to text holding the key is stripped whole. A JSON body's strings
//! are checked once decoded too, since JSON may spell any character `\uXXXX`.
//! The whole reply is buffered first, so a form cannot split across reads.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// What every stripped form becomes.
pub const MARKER: &[u8] = b"[redacted]";

/// Returns `bytes` with every form of `key` replaced by [`MARKER`]. Longer
/// forms go first, so `Bearer <key>` is taken whole before the raw key inside
/// it. Every intermediate copy is wiped when dropped.
#[must_use]
pub fn strip(key: &[u8], bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(bytes.to_vec());
    for form in &forms(key) {
        if memchr::memmem::find(&out, form).is_some() {
            out = replace_all(&out, form);
        }
    }
    if memchr::memchr(b'%', &out).is_some() {
        out = strip_percent_runs(key, &out);
    }
    out
}

/// [`strip`] for a reply body: when the body is JSON, each string and object
/// key is checked in its decoded form first, and the body is written back out
/// only if one of them held the key.
#[must_use]
pub(crate) fn strip_body(key: &[u8], body: &[u8]) -> Zeroizing<Vec<u8>> {
    match strip_json_strings(key, body) {
        Some(rewritten) => strip(key, &rewritten),
        None => strip(key, body),
    }
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
    let hex = |byte: u8| {
        char::from(byte)
            .to_digit(16)
            .and_then(|digit| u8::try_from(digit).ok())
    };
    let mut out = Zeroizing::new(Vec::with_capacity(run.len()));
    let mut at = 0;
    while at < run.len() {
        let pair = (run[at] == b'%')
            .then(|| Some((hex(*run.get(at + 1)?)?, hex(*run.get(at + 2)?)?)))
            .flatten();
        if let Some((high, low)) = pair {
            out.push((high << 4) | low);
            at += 3;
        } else {
            out.push(run[at]);
            at += 1;
        }
    }
    out
}

/// The body with each JSON string and object key stripped in decoded form,
/// or `None` when the body is not JSON or no string held the key.
fn strip_json_strings(key: &[u8], body: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
    if !strip_value(key, &mut value) {
        return None;
    }
    serde_json::to_vec(&value).ok().map(Zeroizing::new)
}

fn strip_value(key: &[u8], value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => strip_text(key, text),
        serde_json::Value::Array(items) => items
            .iter_mut()
            .fold(false, |changed, item| strip_value(key, item) | changed),
        serde_json::Value::Object(map) => {
            let mut changed = false;
            *map = std::mem::take(map)
                .into_iter()
                .map(|(mut name, mut item)| {
                    changed |= strip_text(key, &mut name);
                    changed |= strip_value(key, &mut item);
                    (name, item)
                })
                .collect();
            changed
        }
        _ => false,
    }
}

fn strip_text(key: &[u8], text: &mut String) -> bool {
    let stripped = strip(key, text.as_bytes());
    if stripped.as_slice() == text.as_bytes() {
        return false;
    }
    *text = String::from_utf8_lossy(&stripped).into_owned();
    true
}

#[cfg(test)]
mod tests;
