//! Core half of `origin::smart_http::paths`: its store-layer items live in `oneiron_store::origin::smart_http::paths` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::smart_http::paths::*;

use crate::Vault;
use crate::credential_door::CredentialDoorError;
use crate::error::{CodeError, Error, Result};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Carries a door refusal out through the crate error surface without ever
/// carrying a secret: the door's messages name paths and reason codes only.
pub(super) fn door_refused(error: &CredentialDoorError) -> Error {
    Error::Code(CodeError::ReceivePackDoorRejected {
        reason: error.to_string(),
    })
}

/// The serving root of one vault: the `GIT_PROJECT_ROOT` of every invocation.
pub fn origin_serving_root(vault: &Vault) -> Result<PathBuf> {
    let root = vault.store.env.path().join(ORIGIN_SERVING_ROOT_NAME);
    fs::create_dir_all(&root)?;
    Ok(root.canonicalize()?)
}

/// The per-request door root. Never inside the serving root, so it is never
/// addressable as a repository.
pub fn origin_door_root(vault: &Vault) -> Result<PathBuf> {
    let root = vault.store.env.path().join(ORIGIN_DOOR_ROOT_NAME);
    fs::create_dir_all(&root)?;
    Ok(root.canonicalize()?)
}

/// Resolves an existing served repository directory.
///
/// Phase A serves; it does not create. A name that resolves to nothing is a
/// miss, never an implicit `git init`.
pub fn origin_repo_dir(vault: &Vault, repo_name: &str) -> Result<PathBuf> {
    validate_repo_name(repo_name)?;
    let root = origin_serving_root(vault)?;
    let dir = root.join(format!("{repo_name}{ORIGIN_REPO_DIR_SUFFIX}"));
    if !dir.is_dir() {
        return Err(Error::Code(CodeError::GitHttpRepoNotFound {
            repo: repo_name.to_owned(),
        }));
    }
    let dir = dir.canonicalize()?;
    if !dir.starts_with(&root) {
        return Err(Error::Code(CodeError::GitHttpInvalidRepoName(
            "origin repo path escapes the serving root",
        )));
    }
    Ok(dir)
}
