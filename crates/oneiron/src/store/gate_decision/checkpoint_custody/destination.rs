//! The directory a restore makes for its copy, held under the copy's writer
//! lease until the restore commits (moved out of `checkpoint_custody`).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
#[cfg(unix)]
use crate::store::root_directory::{
    FileIdentity, file_identity, make_directory, parent_or_here, refuse_shared_path,
    refuse_shared_vault_root, remove_held_directory,
};
use crate::store::{Store, VaultWriterLease};

#[cfg(test)]
use super::AFTER_RESTORE_DESTINATION_MADE;
#[cfg(unix)]
use super::opened_directory;

/// The directory a restore made for its copy, and the copy's writer lease.
/// Each open of the copy goes by name, and is checked against the directory
/// made: rows are written into, and a mark lifted from, only that one, never a
/// directory moved in under its name since.
///
/// The lease is taken as the directory is made and held to the commit, where
/// the copy's vault takes it over ([`MadeDestination::keep`]): no other owner
/// opens the copy between the restore's opens. Dropped before that, after the
/// copy's vault has closed, this removes the directory it made with
/// everything in it, through the descriptor it holds and still under the
/// lease. A directory moved in under the name since is left as it is, and so
/// is one another owner leased first (review r1, both F1). Off unix, with no
/// identity to check, it removes the destination by name, still only under
/// the copy's lease, as main's discard did once the copy had opened; no lease
/// is granted off unix today, so there it removes nothing.
pub(crate) struct MadeDestination {
    destination: PathBuf,
    #[cfg(unix)]
    made: std::fs::File,
    #[cfg(unix)]
    identity: FileIdentity,
    lease: Option<VaultWriterLease>,
    /// The page-seal mirror a sealed copy's open writes beside it (OF-570),
    /// removed with the copy.
    mirror: Option<PathBuf>,
    kept: bool,
}

impl MadeDestination {
    /// Makes `destination`, which must not exist yet, owner-only, and takes
    /// its writer lease. It is refused unless no other user can move an entry
    /// on the way to it, or, for a copy that will replace the live vault at
    /// `home`, on the way to that vault or inside it: on such a path no name
    /// this restore makes, opens or exchanges can be changed under it.
    pub(crate) fn make(destination: &Path, home: Option<&Path>) -> Result<Self> {
        #[cfg(unix)]
        let made = {
            refuse_shared_path(parent_or_here(destination.parent().unwrap_or(destination)))?;
            if let Some(home) = home {
                refuse_shared_vault_root(home)?;
            }
            make_directory(destination)?
        };
        #[cfg(not(unix))]
        {
            let _ = home;
            std::fs::create_dir(destination)?;
        }
        let mut guard = Self {
            destination: destination.to_owned(),
            #[cfg(unix)]
            identity: file_identity(&made.metadata()?),
            #[cfg(unix)]
            made,
            lease: None,
            mirror: None,
            kept: false,
        };
        #[cfg(test)]
        if let Some(callback) = AFTER_RESTORE_DESTINATION_MADE.with(|slot| slot.borrow_mut().take())
        {
            callback();
        }
        // Through the directory made, so nothing is locked or written in one
        // moved in under the name (review r2, Astra F2).
        #[cfg(unix)]
        let lease =
            VaultWriterLease::acquire_held(guard.made.try_clone()?, &destination.canonicalize()?)?;
        #[cfg(not(unix))]
        let lease = VaultWriterLease::acquire(&destination.canonicalize()?)?;
        guard.lease = Some(lease);
        Ok(guard)
    }

    /// Takes the page-seal mirror beside the copy as this restore's, for a
    /// copy made sealed: none may be there yet, since a mirror with no vault
    /// is another vault's custody, and a refusal removes the one the copy's
    /// open writes.
    pub(crate) fn owns_page_seal_mirror(&mut self) -> Result<()> {
        let mirror = crate::world_keys::page_seal_custody_path(&self.destination)?;
        if std::fs::symlink_metadata(&mirror).is_ok() {
            return Err(Error::InvalidConfig(
                "a page-seal mirror is already beside a restore's copy".into(),
            ));
        }
        self.mirror = Some(mirror);
        Ok(())
    }

    /// The copy's writer lease, for each open of it.
    pub(crate) fn lease(&self) -> Result<&VaultWriterLease> {
        self.lease
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("a restore's copy holds no writer lease".into()))
    }

    /// Refuses unless `store` is open on the directory made.
    pub(crate) fn holds(&self, store: &Store) -> Result<()> {
        #[cfg(unix)]
        if opened_directory(store)? != self.identity {
            return Err(moved());
        }
        #[cfg(not(unix))]
        let _ = store;
        Ok(())
    }

    /// Keeps the copy, its restore committed: `copy`, its vault, takes over
    /// the writer lease.
    pub(crate) fn keep(mut self, copy: &mut crate::Vault) {
        self.kept = true;
        if let Some(lease) = self.lease.take() {
            copy.adopt_writer_lease(lease);
        }
    }

    /// Arms the copy, and its page-seal mirror, to stay where they are
    /// whatever follows (`true`), while the restore's last publication may
    /// have happened, or disarms it once that publication is known not to
    /// have (FIX 6782). Its lease still goes with it, after the copy's vault
    /// has closed.
    pub(crate) fn preserve(&mut self, preserved: bool) {
        self.kept = preserved;
    }
}

/// A restore's copy is no longer where the restore made it.
fn moved() -> Error {
    Error::InvalidConfig("a restore's copy no longer sits where it was made".into())
}

impl Drop for MadeDestination {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        // Only under its own lease: without it, the copy is another owner's,
        // or, off unix, was never opened (review r3, Sol F3).
        let removed = self.lease.take().is_some_and(|lease| {
            #[cfg(unix)]
            let removed = remove_held_directory(&self.destination, &self.made).is_ok();
            // With no directory identity to check, the destination goes by
            // name after the copy's vault has closed, as main's discard took
            // it (Engine ruling on review r1's F2).
            #[cfg(not(unix))]
            let removed = std::fs::remove_dir_all(&self.destination).is_ok();
            drop(lease);
            removed
        });
        if !removed {
            tracing::warn!("a refused restore left the copy it made in place");
            return;
        }
        if let Some(mirror) = self.mirror.take()
            && let Err(error) = std::fs::remove_file(&mirror)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!("a refused restore left the page-seal mirror it wrote in place");
        }
    }
}

/// Deletes the `vault_meta` rows of `keys` in `wtxn`: an activation's prune
/// of the body rows whose instances its source retired (KS-2A).
pub(super) fn delete_vault_meta_in_txn(
    env: &heed::Env,
    wtxn: &mut heed::RwTxn<'_>,
    keys: &std::collections::BTreeSet<Vec<u8>>,
) -> Result<()> {
    let vault_meta = env
        .open_database::<heed::types::Bytes, heed::types::Bytes>(wtxn, Some("vault_meta"))?
        .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
    for key in keys {
        vault_meta.delete(wtxn, key)?;
    }
    Ok(())
}

/// Replaces every host-order row of a vault with `rows`, in `wtxn`. Rows
/// outside the family are refused (moved here whole from
/// `checkpoint_custody`).
pub(crate) fn replace_host_holds_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<()> {
    if rows
        .iter()
        .any(|(key, _)| !key.starts_with(super::HOST_HOLD_PREFIX))
    {
        return Err(Error::CorruptedIndex("host-order legal hold rows"));
    }
    let vault_meta = store
        .env
        .open_database::<heed::types::Bytes, heed::types::Bytes>(wtxn, Some("vault_meta"))?
        .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
    let stale: Vec<Vec<u8>> = vault_meta
        .prefix_iter(wtxn, super::HOST_HOLD_PREFIX)?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<std::result::Result<_, _>>()?;
    for key in stale {
        vault_meta.delete(wtxn, &key)?;
    }
    for (key, value) in rows {
        vault_meta.put(wtxn, key, value)?;
    }
    Ok(())
}
