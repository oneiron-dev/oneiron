//! Persisted, deterministic Rust API, schema and command-output contracts.
//! Source parsing is syntactic (all cfg branches), not a compiler/semver substitute.
mod graph;
mod rust_api;
mod storage;
#[cfg(test)]
mod tests;
mod types;

pub use graph::{AffectedTests, WorkspaceGraph};
pub use rust_api::rust_public_names;
pub use storage::ContractOracle;
pub use types::{
    CommandOutput, ContractBaseline, ContractDiff, ContractSnapshot, ContractSpec, ContractVerdict,
};

use crate::error::{CodeError, Error, Result};
use std::path::{Component, Path, PathBuf};

pub(crate) fn invalid(reason: &'static str) -> Error {
    Error::Code(CodeError::InvalidRepoMutationRecord(reason))
}

// Resolve each component without following symlinks, including the final file.
pub(crate) fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty() || relative.contains('\\') {
        return Err(invalid("contract path must be a relative file path"));
    }
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return Err(invalid("contract path contains a non-normal component"));
        };
        if name.to_string_lossy().eq_ignore_ascii_case(".git") {
            return Err(invalid("contract path cannot name git administration"));
        }
        path.push(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(invalid("contract path crosses a symlink"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}
