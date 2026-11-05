//! Restore planning and the fork a copy served beside its source takes
//! (ARCH-0038 #erasure-completeness, "Key custody in a side restore").
//!
//! A restore plans before it creates its destination: each id its rows need
//! is live, or retired (destroyed, or committed to be), and a missing one is
//! lost custody that refuses the restore. A fork then gives the copy custody
//! of its own, in a new namespace beside the copy's root: every retirement
//! fact of the source is copied, the live entries the plan needs are copied
//! byte for byte (never hard-linked, never re-encrypted), and everything is
//! synced before the copy's binding commits.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::PathBuf;

use crate::restore_admission::Rejected;
use crate::restore_admission::RestoreAdmissionReason as R;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::files::EntryState;
use crate::key_custody::files::container;
use crate::key_custody::files::entry_name;
use crate::key_custody::files::make_new_dir;
use crate::key_custody::files::marker_name;
use crate::key_custody::holders::HolderDebt;
use crate::key_custody::identity::CustodyBinding;
use crate::key_custody::identity::CustodyId;
use crate::key_custody::identity::CustodySubject;
use crate::key_custody::identity::custody_corrupt;
use crate::key_custody::platform;

/// What a restore needs of one required id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// Its entry is live: the client authenticates what it decrypts.
    Live,
    /// Destroyed, or committed to be: the client drops what it decrypts.
    Retired,
}

/// A custody directory a fork created, named by device and inode so its
/// cleanup never removes a directory that replaced it. The directory stays
/// open for the fork's life, so no other directory can take its inode number
/// while the cleanup may still compare against it.
pub struct ForkedCustodyDir {
    pub path: PathBuf,
    pub identity: (u64, u64),
    pub directory: File,
}

impl ForkedCustodyDir {
    /// The custody directory a restore just made at `path` and holds open
    /// as `directory`: a disaster recovery's landing (KS-4), removed as a
    /// fork's is when the restore fails.
    pub fn made(path: PathBuf, directory: File) -> oneiron_base::error::Result<Self> {
        Ok(Self {
            identity: directory_identity(&directory.metadata()?).ok_or_else(custody_corrupt)?,
            path,
            directory,
        })
    }

    /// Syncs the directory the fork or landing made.
    pub fn sync(&self) -> oneiron_base::error::Result<()> {
        platform::sync_held(&self.directory, &self.path)
    }

    /// Removes the fork's entries and markers, for a restore that failed or
    /// was refused after it; best effort, and only while the path still
    /// names the directory the fork created.
    pub fn remove(self) {
        if fs::symlink_metadata(&self.path)
            .ok()
            .and_then(|meta| directory_identity(&meta))
            == Some(self.identity)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub fn directory_identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    platform::directory_identity(meta)
}

/// Every generation one subject's directory `dir` holds an entry or a
/// retirement marker for, by its canonical name, with its state; a name the
/// engine would not write is not one it reads.
pub fn subject_generations(dir: &std::path::Path) -> Result<Vec<(u64, EntryState)>> {
    let mut generations = Vec::new();
    for file in fs::read_dir(dir)? {
        let name = file?.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let (hex, state) = match name.strip_prefix(".retired-g") {
            Some(hex) => (hex, EntryState::Retired),
            None => match name.strip_prefix('g') {
                Some(hex) => (hex, EntryState::Live),
                None => continue,
            },
        };
        let Ok(generation) = u64::from_str_radix(hex, 16) else {
            continue;
        };
        let canonical = match state {
            EntryState::Retired => marker_name(generation),
            _ => entry_name(generation),
        };
        if canonical == name {
            generations.push((generation, state));
        }
    }
    Ok(generations)
}
