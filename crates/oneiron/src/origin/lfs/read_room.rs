//! Core half of `origin::lfs::read_room`: its store-layer items live in `oneiron_store::origin::lfs::read_room` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::lfs::read_room::*;

use super::LfsOid;
use crate::Vault;
use crate::error::{CodeError, Error, Result};
use std::any::Any;
use std::sync::{Arc, PoisonError};

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
    /// when no manifest row is stored for it, so there is nothing to read. A wait
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
