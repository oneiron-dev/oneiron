//! Create-capable open door: `Store::open` and its helpers.

use std::path::Path;

use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::store::{Store, VaultWriterLease};

use super::open_version_keys::{DefaultPolicySeedMode, STORAGE_ABI_VERSION};
use super::vault_root_bind::{VaultRootPreflight, preflight_vault_root};

impl Store {
    /// Opens or creates a store at `path` and initializes all named databases.
    pub fn open(path: impl AsRef<Path>, config: &VaultConfig) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::Required,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_with_storage_abi_version_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            storage_abi_version,
            DefaultPolicySeedMode::Required,
        )
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn open_unseeded_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::TestUnseeded,
        )
    }

    pub(super) fn open_with_storage_abi_version(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
        seed_mode: DefaultPolicySeedMode,
    ) -> Result<Self> {
        Self::open_with_lease(path, config, storage_abi_version, seed_mode, None)
    }

    pub(in crate::store) fn open_with_lease(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
        seed_mode: DefaultPolicySeedMode,
        lease: Option<&VaultWriterLease>,
    ) -> Result<Self> {
        let (mut torn_creation_cleanup, env, registered_path, is_new_vault) =
            super::create_env::create_env(path, config, lease)?;
        let (db_open_guard, wtxn, dbs, vault_meta_view) =
            super::create_dbs::create_dbs(&env, is_new_vault, storage_abi_version)?;
        let raw = super::create_commit::create_commit(
            wtxn,
            db_open_guard,
            &dbs,
            &vault_meta_view,
            &registered_path,
            is_new_vault,
            seed_mode,
            &mut torn_creation_cleanup,
        )?;
        super::create_preflight::create_preflight(env, raw, registered_path, config, seed_mode)
    }
}

/// Reads the LMDB pair through the bound root (`/proc/self/fd/<n>` on Linux)
/// but names the root the caller asked for in a refusal: the descriptor path
/// means nothing outside this process.
pub(super) fn preflight_named_root(
    storage_path: &Path,
    canonical_path: &Path,
) -> Result<VaultRootPreflight> {
    preflight_vault_root(storage_path).map_err(|error| match error {
        Error::Store(crate::error::StoreError::VaultRootPreflight { problem, .. }) => {
            Error::Store(crate::error::StoreError::VaultRootPreflight {
                path: canonical_path.to_path_buf(),
                problem,
            })
        }
        other => other,
    })
}
