//! Core half of `store::open_gates::open_create_door`: its store-layer items live in `oneiron_store::open_gates::open_create_door` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::open_gates::open_create_door::*;

use super::open_version_keys::{DefaultPolicySeedMode, STORAGE_ABI_VERSION};
use super::vault_root_bind::{VaultRootPreflight, preflight_vault_root};
use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::store::{Store, StoreHooks, VaultWriterLease};
use std::path::Path;

impl Store {
    /// Opens or creates a store at `path` and initializes all named databases.
    pub fn open(path: impl AsRef<Path>, config: &VaultConfig, hooks: StoreHooks) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::Required,
            hooks,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_with_storage_abi_version_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
        hooks: StoreHooks,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            storage_abi_version,
            DefaultPolicySeedMode::Required,
            hooks,
        )
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn open_unseeded_for_test(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        hooks: StoreHooks,
    ) -> Result<Self> {
        Self::open_with_storage_abi_version(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::TestUnseeded,
            hooks,
        )
    }

    pub(super) fn open_with_storage_abi_version(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
        seed_mode: DefaultPolicySeedMode,
        hooks: StoreHooks,
    ) -> Result<Self> {
        Self::open_with_lease(path, config, storage_abi_version, seed_mode, None, hooks)
    }

    pub(in crate::store) fn open_with_lease(
        path: impl AsRef<Path>,
        config: &VaultConfig,
        storage_abi_version: u16,
        seed_mode: DefaultPolicySeedMode,
        lease: Option<&VaultWriterLease>,
        hooks: StoreHooks,
    ) -> Result<Self> {
        let (mut torn_creation_cleanup, env, registered_path, is_new_vault) =
            super::create_env::create_env(path, config, lease)?;
        let (db_open_guard, wtxn, dbs, vault_meta_view) =
            super::create_dbs::create_dbs(&env, is_new_vault, storage_abi_version)?;
        let clock = config.store_clock.for_store();
        let raw = super::create_commit::create_commit(
            wtxn,
            db_open_guard,
            &dbs,
            &vault_meta_view,
            &registered_path,
            is_new_vault,
            seed_mode,
            hooks.gate_hooks,
            &clock,
            &mut torn_creation_cleanup,
        )?;
        super::create_preflight::create_preflight(
            env,
            raw,
            registered_path,
            config,
            seed_mode,
            hooks,
            clock,
        )
    }
}
