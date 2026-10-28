//! The world pad compartments a restore left unopened, kept beside this
//! host's custody (PAD-3, FIX 11133).
//!
//! Each sits in its pad's own subject directory as `.carried-<origin key id
//! hex>`, apart from the pad's generation entries and markers: no census,
//! generation scan or read takes it for an entry, and it is never read as a
//! 32-byte pad. It is ciphertext under keys this host does not hold, and it
//! leaves only inside a custody head, wrapped to the pad's world's admitted
//! machines and roots as it came. A retirement of the pad unlinks it after
//! the pad's marker, and an erase's receipt completes only once none is
//! left. A pad no restore epoch owes any longer, rested here or erased, has
//! its carried copies pruned once the transaction that settled it commits.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use heed::RoTxn;

use crate::error::Result;
use crate::store::Store;

use super::files::{LocalCustody, custody_present, open_dir, read_whole, write_once};
use super::head::{CARRIED_PREFIX, CarriedWorldPad};
use super::identity::{CustodyKind, CustodySubject};
use super::platform;

/// Every carried compartment's file in the subject directory `dir`, in name
/// order; none when it has no directory.
fn carried_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let names = match fs::read_dir(dir) {
        Ok(names) => names,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut files = Vec::new();
    for name in names {
        let entry = name?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(CARRIED_PREFIX))
        {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

impl LocalCustody<'_> {
    /// Keeps `carried` beside its pad, synced, once per origin compartment.
    /// A pad a marker retires keeps none.
    pub(super) fn put_carried(&self, carried: &CarriedWorldPad) -> Result<()> {
        let id = carried.id();
        if self.retired(id)? {
            return Ok(());
        }
        self.open_compartment()?;
        let dir = self.subject_dir(id.subject())?;
        open_dir(&dir, true, Some(CustodyKind::WorldPad))?;
        write_once(&dir, &carried.file_name(), &carried.to_bytes()?)?;
        Ok(())
    }

    /// Every carried compartment this custody keeps, in subject and name
    /// order. A file that does not read as one of this custody's pads stays
    /// where it is, warned, and is not carried on.
    pub(super) fn carried(&self) -> Result<Vec<CarriedWorldPad>> {
        let mut carried = Vec::new();
        for subject in self.subjects_with_prefix(CustodyKind::WorldPad, &[])? {
            for path in carried_files(&self.subject_dir(&subject)?)? {
                let Some(bytes) = read_whole(&path)? else {
                    continue;
                };
                match CarriedWorldPad::from_bytes(&bytes) {
                    Ok(pad) if pad.id().subject() == &subject => carried.push(pad),
                    _ => tracing::warn!(
                        "a carried world pad compartment did not read as this custody's; it is \
                         not carried on"
                    ),
                }
            }
        }
        Ok(carried)
    }

    /// Whether a carried compartment of `subject` is still here; never for a
    /// kind other than a world pad.
    pub(super) fn carries(&self, subject: &CustodySubject) -> Result<bool> {
        if subject.kind() != CustodyKind::WorldPad {
            return Ok(false);
        }
        Ok(!carried_files(&self.subject_dir(subject)?)?.is_empty())
    }

    /// Unlinks every carried compartment of `subject`, then syncs its
    /// directory.
    pub(super) fn drop_carried(&self, subject: &CustodySubject) -> Result<()> {
        if subject.kind() != CustodyKind::WorldPad {
            return Ok(());
        }
        let dir = self.subject_dir(subject)?;
        let files = carried_files(&dir)?;
        if files.is_empty() {
            return Ok(());
        }
        for path in files {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        platform::sync_dir(&dir)
    }
}

impl Store {
    /// Drops the carried compartments of every pad `owed` does not name,
    /// under the custody write guard: `owed` reads, in a snapshot taken under
    /// it, the full ids some restore epoch still owes. A pad rested here or
    /// erased needs no carried copy. Run only once the transaction that
    /// settled them committed. Nothing goes from an archived vault's custody
    /// or another root's.
    ///
    /// # Errors
    ///
    /// Storage and custody faults.
    pub(crate) fn prune_carried_world_pads(
        &self,
        owed: impl FnOnce(&RoTxn<'_>) -> Result<BTreeSet<[u8; 40]>>,
    ) -> Result<()> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let root = custody.binding().root();
        if self.core.gate_custody_archived()
            || root != self.core.key_custody.home()
            || !custody_present(root)?
        {
            return Ok(());
        }
        let _custody = self.core.key_custody.write_guard()?;
        let owed = owed(&self.env.read_txn()?)?;
        let mut settled = BTreeSet::new();
        for pad in custody.carried()? {
            let item = pad.id().subject().item();
            if !<[u8; 40]>::try_from(item).is_ok_and(|item| owed.contains(&item)) {
                settled.insert(pad.id().subject().clone());
            }
        }
        for subject in &settled {
            custody.drop_carried(subject)?;
        }
        Ok(())
    }
}
