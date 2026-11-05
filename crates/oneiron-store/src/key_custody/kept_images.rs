//! What keeps a body instance's key past its last row (FIX 6022, 6228):
//! the in-flight leases of this process and the kept copies a vault's
//! custody holds a record of.
//!
//! - A lease names an instance a mint, a reserve or a spill holds before
//!   any row names it, from before its entry is published until the writer
//!   that names it is done. Memory only: a restart leaves no writer that
//!   could still name one.
//! - A holder record names every instance one kept copy carries: a
//!   checkpoint image (registered under its snapshot's guard before the
//!   image is written) or a parked archive (registered before its swap).
//!   It sits beside the journal, outside every image, synced. Only the
//!   custodian of a copy releases it: a local copy's durable unlink, its
//!   directory synced first, releases the local holder; a stage ack never
//!   releases a remote copy. A record that does not read keeps everything.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use crate::key_custody::files::read_whole;
use crate::key_custody::files::replace_file;
use crate::key_custody::files::write_once;
use crate::key_custody::log::log_corrupt;
use crate::key_custody::platform;
use oneiron_base::error::Result;

pub const IMAGES: &str = "images";
const RECORD_MAGIC: &[u8; 4] = b"OKIH";
const RECORD_VERSION: u8 = 1;
/// `magic | version | copy (32, zero until named) | u32be count`.
const RECORD_HEADER: usize = 4 + 1 + 32 + 4;

/// The instances this process leases, by how many leases each holds.
#[derive(Default)]
pub struct InstanceLeases(pub Mutex<BTreeMap<[u8; 16], usize>>);

/// One lease of a body instance: released when dropped.
pub struct BodyLease {
    pub leases: Arc<InstanceLeases>,
    pub instance: [u8; 16],
}

impl Drop for BodyLease {
    fn drop(&mut self) {
        let mut held = self.leases.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.instance) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.instance);
            }
        }
    }
}

impl InstanceLeases {
    /// Leases `instance` until the returned lease drops: no retention
    /// retires it meanwhile. Taken before the instance's entry is
    /// published.
    pub fn lease(self: &Arc<Self>, instance: [u8; 16]) -> BodyLease {
        *self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(instance)
            .or_default() += 1;
        BodyLease {
            leases: Arc::clone(self),
            instance,
        }
    }
}

/// One kept copy's holder record, registered: named once its copy is.
pub struct ImageHolder {
    pub dir: PathBuf,
    pub name: String,
    pub instances: Vec<[u8; 16]>,
}

pub fn encode(copy: &[u8; 32], instances: &[[u8; 16]]) -> Vec<u8> {
    let mut out = RECORD_MAGIC.to_vec();
    out.push(RECORD_VERSION);
    out.extend_from_slice(copy);
    out.extend_from_slice(&(instances.len() as u32).to_be_bytes());
    for instance in instances {
        out.extend_from_slice(instance);
    }
    out
}

/// A record's copy and instances; `None` when it does not decode.
pub fn decode(bytes: &[u8]) -> Option<([u8; 32], Vec<[u8; 16]>)> {
    if bytes.get(..4)? != RECORD_MAGIC || *bytes.get(4)? != RECORD_VERSION {
        return None;
    }
    let copy = bytes.get(5..37)?.try_into().ok()?;
    let count = u32::from_be_bytes(bytes.get(37..RECORD_HEADER)?.try_into().ok()?) as usize;
    let body = bytes.get(RECORD_HEADER..)?;
    if body.len() != count.checked_mul(16)? {
        return None;
    }
    let instances = body
        .chunks_exact(16)
        .filter_map(|chunk| chunk.try_into().ok())
        .collect();
    Some((copy, instances))
}

impl ImageHolder {
    /// Names the copy this record keeps by `copy`, the digest its custodian
    /// knows it by, synced: what its release finds it by.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub fn name(&self, copy: &[u8; 32]) -> Result<()> {
        replace_file(&self.dir, &self.name, &encode(copy, &self.instances))
    }
}
