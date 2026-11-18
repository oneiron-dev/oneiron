//! Core half of `store::writer_lease`: its store-layer items live in `oneiron_store::writer_lease` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::writer_lease::*;

#[cfg(unix)]
use super::root_directory::{file_identity, named_directory_identity, open_root_directory};
use super::{DefaultPolicySeedMode, STORAGE_ABI_VERSION, Store};
use crate::{Error, Result, VaultConfig};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

impl Store {
    pub(crate) fn open_with_writer_lease(
        path: &Path,
        config: &VaultConfig,
        lease: &VaultWriterLease,
        hooks: crate::store::StoreHooks,
    ) -> Result<Self> {
        let mut store = Self::open_with_lease(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::Required,
            Some(lease),
            hooks,
        )?;
        store.owner.opened_with_writer_lease = true;
        // A crashed lease holder's journaled decision times rise into the
        // clock floor before any admission (review #4484 P1-B).
        store.replay_authorization_lease_journal()?;
        Ok(store)
    }

    /// The canonical root this store opened at, the path its process-wide
    /// registries key on.
    pub(crate) fn canonical_root(&self) -> &Path {
        &self.owner._registered_path.path
    }

    /// This open took the vault's writer lease, though no handle holds it yet.
    pub(crate) fn opened_with_writer_lease(&self) -> bool {
        self.owner.opened_with_writer_lease
    }
}

impl crate::Vault {
    /// This process's writer lease on the very directory this handle opened,
    /// for one owner act by a host that opened without it (FIX 5885: the
    /// desktop re-key). Taken without waiting: another holder, this handle's
    /// own lease included, refuses `ConcurrentWrite(VAULT_WRITER_LEASE_HELD)`
    /// at once. It is marked on the lock file, so an owned open that meets it
    /// waits up to `OWNER_ACT_LEASE_WAIT` before it refuses as today.
    /// Dropping it releases the lease: hold it for the act alone.
    pub fn hold_writer_lease_for_owner_act(&self) -> Result<VaultWriterLease> {
        let lease = self.try_acquire_writer_lease()?;
        #[cfg(unix)]
        lease.mark_owner_act()?;
        Ok(lease)
    }

    /// This process's writer lease on the very directory this handle opened,
    /// for a host that opened without it, taken without waiting and without
    /// a mark: another holder, this handle's own lease included, refuses
    /// `ConcurrentWrite(VAULT_WRITER_LEASE_HELD)` at once. An owned open
    /// that meets it looks once again before it refuses as today. Dropping
    /// it releases the lease: a writer's nonce spend holds it for that spend
    /// alone (FIX 12023 W0).
    pub(crate) fn try_acquire_writer_lease(&self) -> Result<VaultWriterLease> {
        #[cfg(unix)]
        {
            let root = self
                .store
                .owner
                .env
                ._bound_root_dir
                .as_ref()
                .ok_or(Error::InvariantViolation("vault root descriptor missing"))?;
            VaultWriterLease::acquire_held(
                root.try_clone()?,
                &self.store.owner._registered_path.path,
            )
        }
        #[cfg(not(unix))]
        {
            let _ = self;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "vault writer leases require a supported OS locking primitive",
            )
            .into())
        }
    }
}
