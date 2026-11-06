//! The text form of a Git path (FIX 21326).
//!
//! Git names a tree entry with any bytes but NUL and `/`, while the engine's
//! records, maps, marks and views key a repository path by `String`. A path
//! whose bytes are UTF-8 is its own text, so every UTF-8 path, record, hash,
//! mark and ref keeps the bytes it has today. A path that is not UTF-8 keeps
//! each byte no UTF-8 sequence holds as NUL and two lowercase hex digits
//! (`[0x66, 0xff]` is `"f\u{0}ff"`). No Git path holds NUL, so that text
//! never equals the text of another path: the map is one-to-one, and
//! [`git_path_bytes`] gives back the exact bytes. Text that is not the
//! canonical form of some path's bytes is refused, so one path has one text.
//!
//! Every sink that hands a path to Git or to the OS turns its text back into
//! bytes ([`git_path_bytes`], [`git_path_os_str`]). A sink that does not
//! still refuses the text: every GitWire argv token, mktree record and file
//! name refuses NUL.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};

use crate::git_wire::failure::invalid;
use oneiron_base::error::Result;

/// The char that opens one escaped byte in a Git path's text.
pub const GIT_PATH_BYTE_ESCAPE: char = '\0';

/// The digits of an escaped byte, high nibble first.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The text of the Git path `bytes`: the bytes themselves when they are
/// UTF-8, otherwise each byte outside a UTF-8 sequence escaped.
///
/// # Errors
/// Bytes that hold NUL, which no Git path holds.
pub fn git_path_text(bytes: &[u8]) -> Result<Cow<'_, str>> {
    if bytes.contains(&0) {
        return Err(invalid("a Git path must not contain NUL"));
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok(Cow::Borrowed(text));
    }
    let mut text = String::with_capacity(bytes.len().saturating_add(8));
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        for byte in chunk.invalid() {
            text.push(GIT_PATH_BYTE_ESCAPE);
            text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    Ok(Cow::Owned(text))
}

/// [`git_path_text`] of owned bytes, which keeps a UTF-8 path's allocation.
///
/// # Errors
/// Bytes that hold NUL.
pub fn git_path_string(bytes: Vec<u8>) -> Result<String> {
    match String::from_utf8(bytes) {
        Ok(text) if !text.contains(GIT_PATH_BYTE_ESCAPE) => Ok(text),
        Ok(_) => Err(invalid("a Git path must not contain NUL")),
        Err(error) => git_path_text(error.as_bytes()).map(Cow::into_owned),
    }
}

/// The text of one file name the OS gave: its bytes on Unix. Off Unix a
/// name is UTF-16, so only a UTF-8 name has a Git path.
///
/// # Errors
/// A name that holds NUL, or, off Unix, a name that is not UTF-8.
pub fn git_path_text_of_os(name: &OsStr) -> Result<Cow<'_, str>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        git_path_text(name.as_bytes())
    }
    #[cfg(not(unix))]
    {
        let text = name
            .to_str()
            .ok_or(invalid("a file name off Unix must be UTF-8"))?;
        git_path_text(text.as_bytes())
    }
}

/// The exact bytes of the Git path whose text is `text`.
///
/// # Errors
/// Text that is not the canonical text of any Git path: an escape without two
/// lowercase hex digits, an escaped NUL, or an escaped byte that a UTF-8
/// sequence holds.
pub fn git_path_bytes(text: &str) -> Result<Cow<'_, [u8]>> {
    if !text.contains(GIT_PATH_BYTE_ESCAPE) {
        return Ok(Cow::Borrowed(text.as_bytes()));
    }
    let malformed = || invalid("a Git path's text must escape only bytes outside UTF-8");
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some(at) = rest.iter().position(|byte| *byte == 0) {
        bytes.extend_from_slice(&rest[..at]);
        let byte = rest
            .get(at + 1..at + 3)
            .and_then(escaped_byte)
            .ok_or_else(malformed)?;
        bytes.push(byte);
        rest = &rest[at + 3..];
    }
    bytes.extend_from_slice(rest);
    if git_path_text(&bytes).map_err(|_| malformed())?.as_ref() != text {
        return Err(malformed());
    }
    Ok(Cow::Owned(bytes))
}

/// The OS form of the Git path whose text is `text`, as an argv token or a
/// file name takes it.
///
/// # Errors
/// Text [`git_path_bytes`] refuses, or, off Unix, a path that is not UTF-8.
pub fn git_path_os_str(text: &str) -> Result<Cow<'_, OsStr>> {
    match git_path_bytes(text)? {
        Cow::Borrowed(_) => Ok(Cow::Borrowed(OsStr::new(text))),
        Cow::Owned(bytes) => os_string_of_bytes(bytes).map(Cow::Owned),
    }
}

/// The byte two lowercase hex digits name.
fn escaped_byte(digits: &[u8]) -> Option<u8> {
    let nibble = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    match digits {
        [high, low] => Some((nibble(*high)? << 4) | nibble(*low)?),
        _ => None,
    }
}

#[cfg(unix)]
fn os_string_of_bytes(bytes: Vec<u8>) -> Result<OsString> {
    use std::os::unix::ffi::OsStringExt;
    Ok(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn os_string_of_bytes(_bytes: Vec<u8>) -> Result<OsString> {
    Err(invalid(
        "a Git path that is not UTF-8 has no file name off Unix",
    ))
}
