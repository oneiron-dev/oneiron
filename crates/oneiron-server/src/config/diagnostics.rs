//! Config parse failures as diagnostics that are safe to print (FIX 9477):
//! the file and the place in it, never the parser's message, a source
//! excerpt or a value. A TOML error quotes the line it failed on and a
//! deserializer names the value it refused, either of which can be a secret
//! (`auth_secret`), so neither is kept, not even as an error's source.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

/// A config file that did not parse: which file and where, and nothing of
/// its text.
#[derive(Debug)]
pub(crate) struct ConfigParseError {
    /// The file, unless the caller's own context names it.
    path: Option<PathBuf>,
    /// One-based line and column of the parser's span, when it gave one.
    location: Option<(usize, usize)>,
}

impl fmt::Display for ConfigParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "parse config file {}: ", path.display())?;
        }
        write!(f, "invalid configuration")?;
        match self.location {
            Some((line, column)) => write!(f, " at line {line}, column {column}"),
            None => write!(f, " (location unavailable)"),
        }
    }
}

impl std::error::Error for ConfigParseError {}

/// `raw`, the text of the config file at `path`, read as `T`. A failure
/// keeps only the file and the parser's location; the parser's error itself
/// is dropped here.
pub(crate) fn parse_toml<T: DeserializeOwned>(
    path: &Path,
    raw: &str,
) -> Result<T, ConfigParseError> {
    toml::from_str(raw).map_err(|error: toml::de::Error| ConfigParseError {
        path: Some(path.to_path_buf()),
        location: located(raw, &error),
    })
}

/// Where `raw`, the text of a config file the caller's context names, fails
/// to read as `T`: for a failure met in a table settled from that text,
/// whose own error names the value it refused and no place, and is dropped
/// unread (FIX 10687). A text that reads clean gives the failure with no
/// place.
pub(crate) fn locate_toml_failure<T: DeserializeOwned>(raw: &str) -> ConfigParseError {
    ConfigParseError {
        path: None,
        location: toml::from_str::<T>(raw)
            .err()
            .and_then(|error| located(raw, &error)),
    }
}

/// The one-based line and column in `raw` of the span `error` gives.
fn located(raw: &str, error: &toml::de::Error) -> Option<(usize, usize)> {
    error
        .span()
        .and_then(|span| line_and_column(raw, span.start))
}

/// The one-based line and column (in characters) of byte `offset` in `raw`.
fn line_and_column(raw: &str, offset: usize) -> Option<(usize, usize)> {
    let before = raw.get(..offset)?;
    let line_start = before.rfind('\n').map_or(0, |newline| newline + 1);
    let line = before.matches('\n').count() + 1;
    let column = before[line_start..].chars().count() + 1;
    Some((line, column))
}
