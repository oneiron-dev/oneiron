//! Moved from `crates/oneiron/src/build_cache.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_store::code_snapshot::repo_ref::RepoRef;
use oneiron_store::code_snapshot::snapshot::CodebaseForkHash;
use oneiron_store::side_table::codec::RawValue;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Cursor;

pub type BuildCacheResult<T> = Result<T, BuildCacheError>;

#[derive(Debug, thiserror::Error)]
pub enum BuildCacheError {
    #[error("account cache tenant mismatch")]
    AccountMismatch,
    #[error("action is already running or requires recovery: {action_key}")]
    ActionInFlight { action_key: String },
    #[error("invalid build action: {0}")]
    InvalidAction(&'static str),
    #[error("invalid declared output path: {0}")]
    InvalidOutputPath(String),
    #[error("result contains undeclared output path: {path}")]
    UndeclaredOutput { path: String },
    #[error("invalid artifact version reference: {0}")]
    InvalidArtifactRef(String),
    #[error("artifact version is unavailable: {artifact_ref}")]
    ArtifactUnavailable { artifact_ref: String },
    #[error("artifact taint refuses cached result: {artifact_ref}")]
    TaintedResult { artifact_ref: String },
    #[error("unknown build-cache schema version: {found}")]
    UnknownSchemaVersion { found: u8 },
    #[error("corrupt build-cache record: {0}")]
    CorruptRecord(&'static str),
    #[error("referenced byte accounting overflow")]
    ReferencedBytesOverflow,
    #[error(transparent)]
    Store(#[from] Error),
}

impl From<std::io::Error> for BuildCacheError {
    fn from(error: std::io::Error) -> Self {
        Self::Store(Error::from(error))
    }
}
pub mod command_spec;
