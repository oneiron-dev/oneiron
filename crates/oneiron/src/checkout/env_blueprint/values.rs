//! Typed string newtypes (step id, repo paths/globs, env keys, secret refs) and their shared check_* containment grammar.

use serde::{Deserialize, Serialize};

use super::blueprint::{EnvBlueprintError, EnvBlueprintResult};

#[doc(hidden)]
pub use oneiron_records::checkout::env_blueprint::values::EnvSecretRef;
#[doc(hidden)]
use oneiron_records::checkout::env_blueprint::values::{
    REPO_RELATIVE_ROOT, check_printable_identifier, check_repo_relative_segments,
    has_windows_drive_prefix,
};
#[doc(hidden)]
pub(super) use oneiron_records::checkout::env_blueprint::values::{
    check_env_key, check_repo_relative_glob, check_repo_relative_path, check_secret_ref,
    check_step_id, invalid_value, is_env_key_byte,
};

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

/// A context-free `check_*` function selected at runtime by input variant.
pub(super) type ValueChecker = fn(&str) -> Result<(), &'static str>;

pub(super) fn check_knowledge_source_id(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}
