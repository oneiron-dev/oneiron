//! A host's disk-floor hold for encoded values about to enter this vault.
//! The host binds it to the vault filesystem and shares its existing claims.
//! This accounts for the values, not LMDB page/split amplification.

use std::{io, sync::Arc};

use crate::Vault;

/// A floor on the filesystem holding the vault's store. It must share pending
/// writes with the host's other work on that filesystem.
pub trait StorageDiskFloor: Send + Sync {
    /// Admits `bytes` of encoded values before their transaction writes them.
    ///
    /// # Errors
    /// The measured disk floor, or the error reading its free space.
    fn hold(&self, bytes: u64) -> io::Result<Box<dyn StorageDiskHold>>;
}

/// A pending write's bytes on that floor. Dropping releases an uncommitted
/// hold; `landed` releases it once the filesystem's free space counts it.
pub trait StorageDiskHold: Send + Sync {
    fn landed(&self);
}

impl Vault {
    /// Lends this vault the host's existing disk floor, bound to the actual
    /// store filesystem. The first lend holds; an embedded host may lend none.
    pub fn lend_storage_disk_floor(&self, floor: Arc<dyn StorageDiskFloor>) {
        let _ = self.storage_disk_floor.set(floor);
    }

    pub(crate) fn hold_storage_disk(
        &self,
        bytes: u64,
    ) -> io::Result<Option<Box<dyn StorageDiskHold>>> {
        self.storage_disk_floor
            .get()
            .map(|floor| floor.hold(bytes))
            .transpose()
    }
}
