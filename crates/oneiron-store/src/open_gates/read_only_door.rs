//! Read-only door: rows of an existing vault's `vault_meta`, read without
//! opening it as a vault, beside another process that may hold it (a side
//! restore of the vault a running server serves).

use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{EnvFlags, EnvOpenOptions};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::VaultRootProblem;

use crate::open_gates::vault_root_bind::vault_root_preflight_error;

/// Rows of one existing vault's metadata database (its `vault_meta`, or the
/// `hnsw_meta` that holds its model pin).
pub struct VaultMetaRows {
    pub rows: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The canonical root at `path`; a missing one refuses with nothing created.
pub fn canonical_existing_root(path: &Path) -> Result<PathBuf> {
    match path.canonicalize() {
        Ok(root) => Ok(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(not_an_existing_root(path, false))
        }
        Err(error) => Err(error.into()),
    }
}

pub fn not_an_existing_root(root: &Path, after_environment_open: bool) -> Error {
    vault_root_preflight_error(
        root,
        VaultRootProblem::NotAnExistingVaultRoot {
            after_environment_open,
        },
    )
}

