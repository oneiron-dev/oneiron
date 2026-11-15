//! Moved from `crates/oneiron/src/checkout/env_blueprint/blueprint.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::checkout::env_blueprint::values::EnvSecretRef;
pub use crate::store::checkout_lease::MaterializationSpec;
use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum EnvValue {
    /// Non-secret configuration. NUL-bearing literals are rejected by a typed,
    /// non-echoing error before the detector sees them; the remaining bytes are
    /// swept through the ONE-1921 detector wrapper.
    Literal(String),
    /// Custody name only. It is checked against the detector contract but never
    /// resolved here.
    SecretRef(EnvSecretRef),
}

pub type EnvBlueprintResult<T> = Result<T, EnvBlueprintError>;

#[derive(Debug, thiserror::Error)]
pub enum EnvBlueprintError {
    #[error("environment blueprint row is empty")]
    EmptyRow,
    #[error("unsupported environment blueprint schema version {found}")]
    UnsupportedSchemaVersion { found: u8 },
    #[error("environment blueprint schema header/body mismatch: {header}/{body}")]
    SchemaVersionMismatch { header: u8, body: u8 },
    #[error("environment blueprint repository identity does not match its key")]
    RepoKeyMismatch,
    #[error("invalid {kind}: {reason}")]
    InvalidValue {
        kind: &'static str,
        reason: &'static str,
    },
    #[error("environment step id is duplicated")]
    DuplicateStepId { id: String },
    #[error("environment step argv is empty")]
    EmptyArgv { step_id: String },
    #[error("environment step argv is invalid")]
    InvalidArgv {
        step_id: String,
        reason: &'static str,
    },
    #[error("environment step uses a shell-string command")]
    ShellStringCommand { step_id: String },
    #[error("environment step uses a command-string interpreter")]
    ShellInterpreterCommand { step_id: String },
    #[error("environment step cwd is invalid")]
    InvalidCwd { step_id: String, cwd: String },
    #[error("environment key is invalid")]
    InvalidEnvKey { step_id: String, key: String },
    #[error("environment secret reference is empty")]
    EmptySecretRef { step_id: String, key: String },
    #[error("environment blueprint contains secret-shaped bytes")]
    SecretShapedBytes { location: String, reason: String },
    #[error("knowledge source id is duplicated")]
    DuplicateKnowledgeSourceId { id: String },
    #[error("knowledge source is invalid")]
    InvalidKnowledgeSource { id: String, reason: &'static str },
    #[error("environment blueprint row encoding is invalid")]
    Encode(String),
    #[error(transparent)]
    Store(#[from] oneiron_base::error::Error),
}
