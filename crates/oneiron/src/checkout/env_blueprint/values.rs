//! Typed string newtypes (step id, repo paths/globs, env keys, secret refs) and their shared check_* containment grammar.

use serde::{Deserialize, Serialize};

use super::blueprint::{EnvBlueprintError, EnvBlueprintResult};

/// Repository-root sentinel for [`RepoRelativePath`]. Wire form is exactly `.`.
const REPO_RELATIVE_ROOT: &str = ".";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvStepId(pub(super) String);

impl EnvStepId {
    /// Requires a nonempty value with no NUL or ASCII control byte
    /// (`< 0x20`, `0x7F`).
    pub fn parse(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_step_id(&value).map_err(invalid_value("step_id"))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical repository-relative path. Wire form always uses `/` separators.
///
/// Parsing is pure string-level: it rejects empty, absolute, Windows/drive
/// prefixed, NUL-bearing, backslash-bearing, leading/trailing `/`,
/// empty-segment, and `.`/`..`-segment values. The exact `.` root sentinel
/// returned by [`RepoRelativePath::root`] is the sole exception; no
/// normalization is performed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoRelativePath(pub(super) String);

impl RepoRelativePath {
    pub fn parse(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_repo_relative_path(&value).map_err(invalid_value("repo_relative_path"))?;
        Ok(Self(value))
    }

    /// The repository root, whose wire form is exactly `.`.
    pub fn root() -> Self {
        Self(REPO_RELATIVE_ROOT.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Repository-relative glob. Its rejection grammar is exactly the path grammar:
/// no empty value, absolute or Windows/drive prefix, NUL, backslash, leading or
/// trailing `/`, empty segment, or `.`/`..` segment. `*`, `?`, and `**` stay
/// literal data for the later KNOW consumer; nothing is expanded here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoRelativeGlob(pub(super) String);

impl RepoRelativeGlob {
    pub fn parse(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_repo_relative_glob(&value).map_err(invalid_value("repo_relative_glob"))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvKey(pub(super) String);

impl EnvKey {
    /// Accepts `[A-Za-z_][A-Za-z0-9_]*`; rejects empty, control, and NUL keys.
    pub fn parse(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_env_key(&value).map_err(invalid_value("env_key"))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
pub(super) fn invalid_value(kind: &'static str) -> impl Fn(&'static str) -> EnvBlueprintError {
    move |reason| EnvBlueprintError::InvalidValue { kind, reason }
}

/// A context-free `check_*` function selected at runtime by input variant.
pub(super) type ValueChecker = fn(&str) -> Result<(), &'static str>;

/// Nonempty and free of NUL and ASCII control bytes (`< 0x20`, `0x7F`). This is
/// the pre-check every author-controlled identifier passes before the detector,
/// so a rejected id is never echoed with control bytes intact.
fn check_printable_identifier(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return Err("must not contain NUL or ASCII control bytes");
    }
    Ok(())
}

pub(super) fn check_step_id(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}

pub(super) fn check_secret_ref(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}

pub(super) fn check_knowledge_source_id(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}

pub(super) fn check_repo_relative_path(value: &str) -> Result<(), &'static str> {
    if value == REPO_RELATIVE_ROOT {
        return Ok(());
    }
    check_repo_relative_segments(value)
}

pub(super) fn check_repo_relative_glob(value: &str) -> Result<(), &'static str> {
    check_repo_relative_segments(value)
}

/// The shared containment grammar for paths and globs. `*`, `?`, and `**` are
/// ordinary bytes here: this checker contains traversal, it does not match.
fn check_repo_relative_segments(value: &str) -> Result<(), &'static str> {
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

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

pub(super) fn check_env_key(value: &str) -> Result<(), &'static str> {
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

pub(super) fn is_env_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
