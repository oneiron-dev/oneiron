//! Create-capable open door: `Store::open` and its helpers.

use std::path::Path;

use crate::config::VaultConfig;
use crate::writer_lease::VaultWriterLease;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::open_gates::vault_root_bind::VaultRootPreflight;
use crate::open_gates::vault_root_bind::preflight_vault_root;

/// Reads the LMDB pair through the bound root (`/proc/self/fd/<n>` on Linux)
/// but names the root the caller asked for in a refusal: the descriptor path
/// means nothing outside this process.
pub fn preflight_named_root(
    storage_path: &Path,
    canonical_path: &Path,
) -> Result<VaultRootPreflight> {
    preflight_vault_root(storage_path).map_err(|error| match error {
        Error::Store(oneiron_base::error::StoreError::VaultRootPreflight { problem, .. }) => {
            Error::Store(oneiron_base::error::StoreError::VaultRootPreflight {
                path: canonical_path.to_path_buf(),
                problem,
            })
        }
        other => other,
    })
}
