//! Moved from `crates/oneiron/src/checkout/env_blueprint/values.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::checkout::env_blueprint::blueprint::EnvBlueprintError;
use crate::checkout::env_blueprint::blueprint::EnvBlueprintResult;
use serde::Deserialize;
use serde::Serialize;

/// Repository-root sentinel for [`RepoRelativePath`]. Wire form is exactly `.`.
pub const REPO_RELATIVE_ROOT: &str = ".";

/// A custody record name, never secret material. The name must be nonempty and
/// free of NUL and ASCII control bytes (`< 0x20`, `0x7F`) before it is checked
/// against the detector contract. The executor later passes [`EnvSecretRef::as_str`]
/// to L1-SECRET's custody contract and receives bytes only at the custody door;
/// nothing here resolves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvSecretRef(pub(super) String);

impl EnvSecretRef {
    pub fn parse_name(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_secret_ref(&value).map_err(invalid_value("secret_ref"))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Maps a context-free `check_*` failure onto the closed public error kind.
pub fn invalid_value(kind: &'static str) -> impl Fn(&'static str) -> EnvBlueprintError {
    move |reason| EnvBlueprintError::InvalidValue { kind, reason }
}

/// Nonempty and free of NUL and ASCII control bytes (`< 0x20`, `0x7F`). This is
/// the pre-check every author-controlled identifier passes before the detector,
/// so a rejected id is never echoed with control bytes intact.
pub fn check_printable_identifier(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return Err("must not contain NUL or ASCII control bytes");
    }
    Ok(())
}

pub fn check_step_id(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}

pub fn check_secret_ref(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}

pub fn check_repo_relative_path(value: &str) -> Result<(), &'static str> {
    if value == REPO_RELATIVE_ROOT {
        return Ok(());
    }
    check_repo_relative_segments(value)
}

pub fn check_repo_relative_glob(value: &str) -> Result<(), &'static str> {
    check_repo_relative_segments(value)
}

/// The shared containment grammar for paths and globs. `*`, `?`, and `**` are
/// ordinary bytes here: this checker contains traversal, it does not match.
pub fn check_repo_relative_segments(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return Err("must not contain NUL or ASCII control bytes");
    }
    if value.contains('\\') {
        return Err("must not contain a backslash separator");
    }
    if value.starts_with('/') {
        return Err("must be repository-relative, not absolute");
    }
    if value.ends_with('/') {
        return Err("must not end with a separator");
    }
    if has_windows_drive_prefix(value) {
        return Err("must not use a Windows drive prefix");
    }
    for segment in value.split('/') {
        if segment.is_empty() {
            return Err("must not contain an empty segment");
        }
        if segment == "." || segment == ".." {
            return Err("must not contain a `.` or `..` segment");
        }
    }
    Ok(())
}

pub fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

pub fn check_env_key(value: &str) -> Result<(), &'static str> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err("must not be empty");
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err("must start with an ASCII letter or underscore");
    }
    if !bytes.all(is_env_key_byte) {
        return Err("must contain only ASCII letters, digits, or underscores");
    }
    Ok(())
}

pub fn is_env_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
