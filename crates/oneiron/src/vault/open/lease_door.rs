//! The open a restore uses for its copy: under the writer lease the restore
//! took when it made the copy's directory, and keeps until the restore
//! commits, so no other owner opens the copy between the restore's opens.

use super::Vault;
use super::config_validation::validate_open_config;
use crate::config::VaultConfig;
use crate::error::Result;
use crate::store::{DefaultPolicySeedMode, Store, VaultWriterLease};
use std::path::Path;

impl Vault {
    /// [`Vault::open_owned`] under `lease`, which the caller holds and keeps.
    pub(crate) fn open_under_lease(
        path: &Path,
        config: VaultConfig,
        lease: &VaultWriterLease,
    ) -> Result<Self> {
        validate_open_config(&config)?;
        let canonical = path.canonicalize()?;
        lease.validate_directory(&canonical)?;
        let store = Store::open_with_writer_lease(&canonical, &config, lease)?;
        Self::finish_open(
            store,
            config,
            DefaultPolicySeedMode::Required,
            super::super::OpenOptions::default(),
        )
    }

    /// The config checks [`Vault::open_owned`] makes before it touches the
    /// disk.
    pub(crate) fn check_open_config(config: &VaultConfig) -> Result<()> {
        validate_open_config(config)
    }

    /// Hands this vault the writer lease it was opened under, as
    /// [`Vault::open_owned`] would have.
    pub(crate) fn adopt_writer_lease(&mut self, lease: VaultWriterLease) {
        self.writer_lease = Some(lease);
    }
}
