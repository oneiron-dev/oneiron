//! Host-lent disk floor for checkpoint and recovery writes.

use oneiron_base::error::Error;

/// The free-space floor a host keeps under what it writes, lent to a backup
/// or a rehearsal for its own writes. Each call replaces the claim the work
/// held so far.
pub trait RecoveryWriteBudget: Send + Sync {
    /// Claims `bytes` still to write in place of the claim held so far;
    /// `false`, the claim staying as it was, when they would take the disk
    /// below its floor past every other claim.
    fn hold(&self, bytes: u64) -> bool;

    /// Whether this budget keeps a floor at all. Work under one that keeps
    /// none claims nothing ahead, so a restore does not work out its bound.
    fn floored(&self) -> bool {
        true
    }
}

/// Why a backup's or a rehearsal's write was refused: the disk is at the
/// floor its host keeps ([`RecoveryWriteBudget`]). It comes as an
/// [`std::io::ErrorKind::StorageFull`] error, so a caller names capacity as
/// the reason and tells the floor from a full disk.
#[derive(Debug)]
pub struct AtWriteFloor;

impl AtWriteFloor {
    /// Whether `error` is this refusal.
    #[must_use]
    pub fn is_in(error: &Error) -> bool {
        let Error::Io(io) = error else {
            return false;
        };
        matches!(io.get_ref(), Some(inner) if inner.is::<Self>())
    }
}

impl std::fmt::Display for AtWriteFloor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "the disk is at its free-space floor: the writes would take it below the reserve its \
             host keeps",
        )
    }
}

impl std::error::Error for AtWriteFloor {}
