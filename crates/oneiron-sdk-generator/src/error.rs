//! `GenerateError`: the line the generator prints last on stderr when it refuses its inputs, as the Python generator
//! it replaced printed it.
//!
//! An uncaught Python exception ended its traceback with `<kind>: <message>`; `raise SystemExit(message)` printed the
//! message alone. Both exited with status 1, and so does the binary on a `GenerateError`. The port was proved by
//! comparing that last line between the two generators, so every message here keeps Python's text: a verb author's
//! refusal reads as it always did.

use std::fmt;
use std::io;
use std::path::Path;
use std::str::Utf8Error;

use crate::py::text::{repr_os_str, repr_str};

/// The generator's refusal, as the Python generator's last stderr line spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// An uncaught Python exception.
    Exception {
        /// The class as the traceback names it: `ValueError`, `KeyError`, `json.decoder.JSONDecodeError`, ...
        kind: &'static str,
        /// The exception's `str()`; empty for a bare `assert` (the traceback then prints the kind alone).
        message: String,
    },
    /// `raise SystemExit(message)`: Python prints the message alone.
    Exit(String),
}

impl GenerateError {
    /// `raise ValueError(message)`.
    pub(crate) fn value(message: impl Into<String>) -> Self {
        Self::exception("ValueError", message)
    }

    /// `assert condition, message` failing (an empty message for a bare `assert`).
    #[allow(
        dead_code,
        reason = "the asserts of outputs() and the emitters arrive with later PRs of the port"
    )]
    pub(crate) fn assertion(message: impl Into<String>) -> Self {
        Self::exception("AssertionError", message)
    }

    /// `raise SystemExit(message)`.
    pub(crate) fn exit(message: impl Into<String>) -> Self {
        Self::Exit(message.into())
    }

    /// `KeyError(key)` from `d[key]` on a dict without `key`: Python prints the key's `repr`.
    pub(crate) fn key(key: &str) -> Self {
        Self::exception("KeyError", repr_str(key))
    }

    /// A `TypeError` with Python's message.
    pub(crate) fn type_error(message: impl Into<String>) -> Self {
        Self::exception("TypeError", message)
    }

    /// `AttributeError`: `'<type>' object has no attribute '<name>'`.
    pub(crate) fn attribute(type_name: &str, name: &str) -> Self {
        Self::exception(
            "AttributeError",
            format!("'{type_name}' object has no attribute '{name}'"),
        )
    }

    /// An `IndexError` with Python's message.
    pub(crate) fn index(message: impl Into<String>) -> Self {
        Self::exception("IndexError", message)
    }

    /// Any other exception class.
    pub(crate) fn exception(kind: &'static str, message: impl Into<String>) -> Self {
        Self::Exception {
            kind,
            message: message.into(),
        }
    }

    /// The `OSError` subclass Python raises for a failed file operation on `path`:
    /// `IsADirectoryError: [Errno 21] Is a directory: '<path>'`.
    pub(crate) fn os(error: &io::Error, path: &Path) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::NotFound => "FileNotFoundError",
            io::ErrorKind::PermissionDenied => "PermissionError",
            io::ErrorKind::IsADirectory => "IsADirectoryError",
            io::ErrorKind::NotADirectory => "NotADirectoryError",
            io::ErrorKind::AlreadyExists => "FileExistsError",
            io::ErrorKind::Interrupted => "InterruptedError",
            io::ErrorKind::TimedOut => "TimeoutError",
            _ => "OSError",
        };
        let path = repr_os_str(path.as_os_str());
        match error.raw_os_error() {
            Some(errno) => {
                // Rust's text is the C library's strerror, as Python's, plus " (os error N)".
                let text = io::Error::from_raw_os_error(errno).to_string();
                let strerror = text
                    .strip_suffix(&format!(" (os error {errno})"))
                    .unwrap_or(&text);
                Self::exception(kind, format!("[Errno {errno}] {strerror}: {path}"))
            }
            None => Self::exception(kind, format!("{error}: {path}")),
        }
    }

    /// `UnicodeDecodeError` from `bytes.decode('utf-8')` (what `Path.read_text()` raises on a file that is not UTF-8).
    pub(crate) fn unicode_decode(error: &Utf8Error, bytes: &[u8]) -> Self {
        let start = error.valid_up_to();
        let (end, reason) = match error.error_len() {
            None => (bytes.len(), "unexpected end of data"),
            Some(len) => {
                // CPython reports a valid lead byte (C2-F4) with a bad follower as a bad continuation.
                let reason = if (0xC2..=0xF4).contains(&bytes[start]) {
                    "invalid continuation byte"
                } else {
                    "invalid start byte"
                };
                (start + len, reason)
            }
        };
        let message = if end - start == 1 {
            format!(
                "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}",
                bytes[start]
            )
        } else {
            format!(
                "'utf-8' codec can't decode bytes in position {start}-{}: {reason}",
                end - 1
            )
        };
        Self::exception("UnicodeDecodeError", message)
    }
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exception { kind, message } if message.is_empty() => f.write_str(kind),
            Self::Exception { kind, message } => write!(f, "{kind}: {message}"),
            Self::Exit(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for GenerateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_python_last_stderr_line() {
        assert_eq!(GenerateError::value("x: y").to_string(), "ValueError: x: y");
        assert_eq!(GenerateError::assertion("").to_string(), "AssertionError");
        assert_eq!(
            GenerateError::assertion("m").to_string(),
            "AssertionError: m"
        );
        assert_eq!(
            GenerateError::exit("SDK-GENERATED-STALE: a").to_string(),
            "SDK-GENERATED-STALE: a"
        );
        // python3 -c "{}['name']"; python3 -c "{}[\"it's\"]"
        assert_eq!(GenerateError::key("name").to_string(), "KeyError: 'name'");
        assert_eq!(GenerateError::key("it's").to_string(), "KeyError: \"it's\"");
        assert_eq!(
            GenerateError::attribute("list", "get").to_string(),
            "AttributeError: 'list' object has no attribute 'get'"
        );
    }

    // Expected: the traceback's last line on nelly (Python 3.14.7) of `python3 -c "b'\xe2A'.decode()"`, one run per
    // input.
    #[test]
    fn unicode_decode_messages() {
        let cases: &[(&[u8], &str)] = &[
            (b"\xff", "byte 0xff in position 0: invalid start byte"),
            (b"a\xffb", "byte 0xff in position 1: invalid start byte"),
            (b"\xe2\x82", "bytes in position 0-1: unexpected end of data"),
            (
                b"\xe2\x82A",
                "bytes in position 0-1: invalid continuation byte",
            ),
            (
                b"\xe2A",
                "byte 0xe2 in position 0: invalid continuation byte",
            ),
            (b"\xc0\x80", "byte 0xc0 in position 0: invalid start byte"),
            (
                b"\xed\xa0\x80",
                "byte 0xed in position 0: invalid continuation byte",
            ),
            (
                b"\xf4\x90\x80\x80",
                "byte 0xf4 in position 0: invalid continuation byte",
            ),
            (
                b"{\"a\": \"\xe9\"}",
                "byte 0xe9 in position 7: invalid continuation byte",
            ),
            (
                b"\xf0\x9f\x98",
                "bytes in position 0-2: unexpected end of data",
            ),
            (b"ab\xc3", "byte 0xc3 in position 2: unexpected end of data"),
            (b"\x80", "byte 0x80 in position 0: invalid start byte"),
            (
                b"\xe0\x80\x80",
                "byte 0xe0 in position 0: invalid continuation byte",
            ),
            (b"\xf5", "byte 0xf5 in position 0: invalid start byte"),
            (
                b"\xf0\x9f\x98A",
                "bytes in position 0-2: invalid continuation byte",
            ),
        ];
        for (bytes, expected) in cases {
            let error = std::str::from_utf8(bytes).expect_err("not UTF-8");
            assert_eq!(
                GenerateError::unicode_decode(&error, bytes).to_string(),
                format!("UnicodeDecodeError: 'utf-8' codec can't decode {expected}"),
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn os_errors_name_the_path() {
        let missing = Path::new("/nonexistent-oneiron-sdk-generator/x.json");
        let error = std::fs::read(missing).expect_err("missing");
        assert_eq!(
            GenerateError::os(&error, missing).to_string(),
            "FileNotFoundError: [Errno 2] No such file or directory: '/nonexistent-oneiron-sdk-generator/x.json'"
        );
    }
}
