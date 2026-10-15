//! Room a host lends the origin to read whole LFS manifests in memory.
//!
//! A check that a published ref's LFS objects are readable reads each
//! object's whole manifest. A host that holds its LFS reads to a room in
//! memory lends that room here, so these checks wait for it as its own reads
//! do, by the bytes of the manifest's stored row.

use std::any::Any;
use std::sync::{Arc, PoisonError};

use super::LfsOid;
use crate::Vault;
use crate::error::{CodeError, Error, Result};

/// A host's room for reading whole LFS manifests.
pub trait LfsReadRoom: Send + Sync {
    /// Waits for room to read a manifest whose stored row is `row_bytes`,
    /// held until the answer drops; `None` when the wait ran out. Called on
    /// a thread that may block.
    fn hold(&self, row_bytes: u64) -> Option<Box<dyn Any + Send>>;
}

/// Room held for one manifest read, if the host lent any.
pub(crate) struct LfsReadHold {
    _held: Option<Box<dyn Any + Send>>,
}

impl Vault {
    /// Lends the origin's availability checks this host's room for LFS
    /// reads: each takes room for the manifest it reads before reading it.
    pub fn set_lfs_read_room(&self, room: Arc<dyn LfsReadRoom>) {
        *self
            .lfs_read_room
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(room);
    }

    /// Room to read `oid`'s whole manifest, sized by its stored row; `None`
    /// when the object is not stored, so there is nothing to read. A wait
    /// for the host's room that runs out is
    /// [`CodeError::LfsReadRoomWaitedOut`].
    pub(crate) fn lfs_manifest_read_room(&self, oid: LfsOid) -> Result<Option<LfsReadHold>> {
        let Some(row_bytes) = self.lfs_manifest_row_bytes(oid)? else {
            return Ok(None);
        };
        let room = self
            .lfs_read_room
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(room) = room else {
            return Ok(Some(LfsReadHold { _held: None }));
        };
        match room.hold(row_bytes) {
            Some(held) => Ok(Some(LfsReadHold { _held: Some(held) })),
            None => Err(Error::Code(CodeError::LfsReadRoomWaitedOut)),
        }
    }
}
