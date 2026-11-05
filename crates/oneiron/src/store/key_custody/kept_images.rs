//! Core half of `store::key_custody::kept_images`: its store-layer items live in `oneiron_store::key_custody::kept_images` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::kept_images::*;

use super::KeyCustody;
use super::files::{LocalCustody, read_whole, replace_file, write_once};
use super::log::log_corrupt;
use super::platform;
use crate::error::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

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
        crate::key_material::os_fill(&mut token)?;
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
        let Some(control) = journal.control()? else {
            return Ok(BTreeSet::new());
        };
        journal.minted_body_instances_cached(&control, &journal.position()?)
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
