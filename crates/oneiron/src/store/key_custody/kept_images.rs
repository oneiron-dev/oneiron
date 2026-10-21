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

use super::KeyCustody;
use super::files::{LocalCustody, read_whole, replace_file, write_once};
use super::identity::CustodyKind;
use super::log::{LogEntry, log_corrupt, open_frame};
use super::platform;
use crate::error::Result;

const IMAGES: &str = "images";
const RECORD_MAGIC: &[u8; 4] = b"OKIH";
const RECORD_VERSION: u8 = 1;
/// `magic | version | copy (32, zero until named) | u32be count`.
const RECORD_HEADER: usize = 4 + 1 + 32 + 4;

/// The instances this process leases, by how many leases each holds.
#[derive(Default)]
pub(crate) struct InstanceLeases(Mutex<BTreeMap<[u8; 16], usize>>);

/// One lease of a body instance: released when dropped.
pub(crate) struct BodyLease {
    leases: Arc<InstanceLeases>,
    instance: [u8; 16],
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
    pub(crate) fn lease(self: &Arc<Self>, instance: [u8; 16]) -> BodyLease {
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

impl KeyCustody {
    /// This vault's lease registry, shared by every handle on its store.
    pub(crate) fn leases(&self) -> Arc<InstanceLeases> {
        Arc::clone(&self.leases)
    }

    /// Whether a lease holds `instance` now.
    pub(crate) fn body_leased(&self, instance: &[u8; 16]) -> bool {
        self.leases
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(instance)
    }
}

/// One kept copy's holder record, registered: named once its copy is.
pub(crate) struct ImageHolder {
    dir: PathBuf,
    name: String,
    instances: Vec<[u8; 16]>,
}

fn encode(copy: &[u8; 32], instances: &[[u8; 16]]) -> Vec<u8> {
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
fn decode(bytes: &[u8]) -> Option<([u8; 32], Vec<[u8; 16]>)> {
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

impl LocalCustody<'_> {
    fn images_dir(&self) -> Result<PathBuf> {
        self.open_compartment()?;
        self.journal()?.sub(IMAGES)
    }

    /// Registers a holder of `instances`, a kept copy's, synced, before the
    /// copy is written or swapped: until its custodian releases it, no
    /// retention retires any of them.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn hold_image_instances(
        &self,
        instances: &BTreeSet<[u8; 16]>,
    ) -> Result<ImageHolder> {
        let dir = self.images_dir()?;
        let mut token = [0u8; 16];
        crate::world_keys::os_fill(&mut token)?;
        let name = super::protocol::hex(&token);
        let instances: Vec<[u8; 16]> = instances.iter().copied().collect();
        if !write_once(&dir, &name, &encode(&[0; 32], &instances))? {
            return Err(log_corrupt());
        }
        Ok(ImageHolder {
            dir,
            name,
            instances,
        })
    }

    /// Every instance a holder record keeps, each record read: one that
    /// does not read refuses the whole read, so its instances stay kept.
    ///
    /// # Errors
    ///
    /// Custody faults, and a record that does not decode.
    pub(crate) fn kept_image_instances(&self) -> Result<BTreeSet<[u8; 16]>> {
        let mut kept = BTreeSet::new();
        for (_, (_, instances)) in self.holder_records()? {
            kept.extend(instances);
        }
        Ok(kept)
    }

    fn holder_records(&self) -> Result<Vec<(PathBuf, ([u8; 32], Vec<[u8; 16]>))>> {
        let dir = self.journal()?.dir().join(IMAGES);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_none_or(|name| name.starts_with('.'))
            {
                continue;
            }
            let path = entry.path();
            let bytes = read_whole(&path)?.ok_or_else(log_corrupt)?;
            records.push((path, decode(&bytes).ok_or_else(log_corrupt)?));
        }
        Ok(records)
    }

    /// The body instances this lineage minted on this host: each Mint
    /// frame of its local log after the base. A lineage a takeover landed
    /// from a head holds older instances whose copies' holder records
    /// stayed with the old host.
    ///
    /// # Errors
    ///
    /// Custody faults, and a log that does not open.
    pub(crate) fn minted_body_instances(&self) -> Result<BTreeSet<[u8; 16]>> {
        let journal = self.journal()?;
        let mut minted = BTreeSet::new();
        let Some(control) = journal.control()? else {
            return Ok(minted);
        };
        let at = journal.position()?;
        for seq in control.base_seq().saturating_add(1)..=at.seq {
            let frame = journal.frame(seq)?.ok_or_else(log_corrupt)?;
            if let (_, LogEntry::Mint(id)) = open_frame(&control, &frame)?
                && id.kind() == CustodyKind::BodyInstance
                && let Some(instance) = id.subject().item().get(..16)
            {
                minted.insert(instance.try_into().map_err(|_| log_corrupt())?);
            }
        }
        Ok(minted)
    }

    /// Releases the local holder of the kept copy `copy` names (its
    /// [`ImageHolder::name`]), after the copy's durable unlink: its record
    /// goes, the directory synced. `false` when no record names it, which
    /// releases nothing.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn release_image_copy(&self, copy: &[u8; 32]) -> Result<bool> {
        let mut released = false;
        for (path, (named, _)) in self.holder_records()? {
            if named == *copy {
                std::fs::remove_file(&path)?;
                released = true;
            }
        }
        if released {
            platform::sync_dir(&self.journal()?.dir().join(IMAGES))?;
        }
        Ok(released)
    }
}

impl LocalCustody<'_> {
    /// Names each holder record of the copy `from` by `to` instead, synced:
    /// the copy's custodian moved it where it is known by `to`. `false`
    /// when none names `from`.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn rename_image_copy(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<bool> {
        let mut renamed = false;
        for (path, (named, instances)) in self.holder_records()? {
            if named != *from {
                continue;
            }
            let (Some(dir), Some(name)) =
                (path.parent(), path.file_name().and_then(|n| n.to_str()))
            else {
                continue;
            };
            replace_file(dir, name, &encode(to, &instances))?;
            renamed = true;
        }
        Ok(renamed)
    }
}

impl ImageHolder {
    /// Names the copy this record keeps by `copy`, the digest its custodian
    /// knows it by, synced: what its release finds it by.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn name(&self, copy: &[u8; 32]) -> Result<()> {
        replace_file(&self.dir, &self.name, &encode(copy, &self.instances))
    }
}
