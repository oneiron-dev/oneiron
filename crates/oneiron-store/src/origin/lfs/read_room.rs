//! Room a host lends the origin to read whole LFS manifests in memory.
//!
//! A check that a published ref's LFS objects are readable reads each
//! object's whole manifest. A host that holds its LFS reads to a room in
//! memory lends that room here, so these checks wait for it as its own reads
//! do, by the bytes of the manifest's stored row.

use std::any::Any;
use std::sync::{Arc, PoisonError};

use crate::origin::lfs::oid::LfsOid;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// A host's room for reading whole LFS manifests.
pub trait LfsReadRoom: Send + Sync {
    /// Waits for room to read a manifest whose stored row is `row_bytes`,
    /// held until the answer drops; `None` when the wait ran out. Called on
    /// a thread that may block.
    fn hold(&self, row_bytes: u64) -> Option<Box<dyn Any + Send>>;
}

/// Room held for one manifest read, if the host lent any.
pub struct LfsReadHold {
    pub _held: Option<Box<dyn Any + Send>>,
}

