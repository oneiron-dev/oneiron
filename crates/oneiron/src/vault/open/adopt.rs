//! The process-owned open under [`OpenOptions`] (FIX 3375, L01 04:55): a
//! device that joins its home from an empty vault creates its store under
//! the home's storage id ([`OpenOptions::adopt_storage_id`]).

use std::path::Path;

use super::config_validation::validate_open_config;
use crate::config::VaultConfig;
use crate::error::Result;
use crate::store::VaultWriterLease;
use crate::vault::{OpenOptions, Vault};

impl Vault {
    /// [`Self::open_owned`] under `options`.
    pub fn open_owned_with(
        path: impl AsRef<Path>,
        config: VaultConfig,
        options: OpenOptions,
    ) -> Result<Self> {
        validate_open_config(&config)?;
        std::fs::create_dir_all(path.as_ref())?;
        let canonical = path.as_ref().canonicalize()?;
        let lease = VaultWriterLease::acquire_after_owner_act(&canonical)?;
        Self::open_leased(&canonical, config, lease, options)
    }
}
