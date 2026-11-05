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

use oneiron_base::error::Result;

use crate::key_custody::files::custody_present;
use crate::key_custody::files::open_dir;
use crate::key_custody::files::read_whole;
use crate::key_custody::files::write_once;
use crate::key_custody::head::carried_pads::CARRIED_PREFIX;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySubject;
use crate::key_custody::platform;

/// Every carried compartment's file in the subject directory `dir`, in name
/// order; none when it has no directory.
pub fn carried_files(dir: &Path) -> Result<Vec<PathBuf>> {
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

