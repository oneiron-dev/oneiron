//! The Python-behaviour helpers (DESIGN 3): Python's values, `json`, `str` methods, builtins and the regular
//! expressions `regex` cannot spell, each with the semantics of the reference interpreter, CPython 3.14.7 as nelly
//! runs it. Later PRs of the port use them and add to them only through their own PR.

pub(crate) mod builtins;
pub(crate) mod json;
pub(crate) mod re;
pub(crate) mod text;
pub(crate) mod value;

use std::fs;
use std::path::Path;

use crate::error::GenerateError;

/// Python's universal newlines on reading: `\r\n` and a lone `\r` both become `\n`.
fn universal_newlines(text: String) -> String {
    if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text
    }
}

/// `path.read_text()`: UTF-8 (nelly's Python runs in UTF-8 mode), strict, with universal newlines; a byte that is not
/// UTF-8 is Python's `UnicodeDecodeError` (its position counts the file's bytes), a failed read its `OSError`.
pub(crate) fn read_text(path: &Path) -> Result<String, GenerateError> {
    let bytes = fs::read(path).map_err(|error| GenerateError::os(&error, path))?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(universal_newlines(text)),
        Err(error) => Err(GenerateError::unicode_decode(
            &error.utf8_error(),
            error.as_bytes(),
        )),
    }
}

/// `path.read_text(errors='replace')` (`facade_types.py:412`, the Rust sources): each invalid UTF-8 sequence (its
/// maximal prefix of a valid sequence, as CPython's decoder reports it) becomes one U+FFFD.
pub(crate) fn read_text_replacing(path: &Path) -> Result<String, GenerateError> {
    let bytes = fs::read(path).map_err(|error| GenerateError::os(&error, path))?;
    Ok(universal_newlines(
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // python3 -c "print(repr(open(P).read()))" of a file holding b'a\r\nb\rc\n' on nelly: 'a\nb\nc\n'
    #[test]
    fn newlines_are_universal() {
        assert_eq!(
            universal_newlines("a\r\nb\rc\n\r".to_owned()),
            "a\nb\nc\n\n"
        );
        assert_eq!(universal_newlines("plain\n".to_owned()), "plain\n");
    }
}
