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

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::PathBuf;

use crate::error::Result;

use super::files::{EntryState, LocalCustody, container, entry_name, make_new_dir, marker_name};
use super::identity::{CustodyBinding, CustodyId, CustodySubject, custody_corrupt};
use super::retirement::RetirementIntent;

/// What a restore needs of one required id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Requirement {
    /// Its entry is live: the client authenticates what it decrypts.
    Live,
    /// Destroyed, or committed to be: the client drops what it decrypts.
    Retired,
}

/// What a restore needs from custody: the custody its image binds
/// (`source`) and, per subject, the newest generation a requirement or an
/// intent names, with the newest one a carried-out retirement destroys.
pub(crate) struct CustodyPlan {
    source: Option<CustodyBinding>,
    subjects: BTreeMap<CustodySubject, (u64, Option<u64>)>,
}

impl CustodyPlan {
    /// `retirements`: each intent with whether it is carried out now (its
    /// client's readiness; an erase's always). A later intent for a subject
    /// wins over an earlier one: a live source's over its image's.
    pub(crate) fn new(
        source: Option<CustodyBinding>,
        retirements: Vec<(RetirementIntent, bool)>,
    ) -> Self {
        let mut subjects = BTreeMap::new();
        for (intent, carried) in retirements {
            subjects.insert(
                intent.subject,
                (intent.through, carried.then_some(intent.through)),
            );
        }
        Self { source, subjects }
    }

    /// The custody the image binds, when it binds one.
    pub(crate) fn source(&self) -> Option<&CustodyBinding> {
        self.source.as_ref()
    }

    /// What a restore needs of `id`, recorded for the fork: retired when a
    /// carried-out retirement covers it or a marker in the source names it,
    /// live when its entry is published there. Missing refuses: an image
    /// supplies a binding, never a key, so lost custody is never papered
    /// over.
    pub(crate) fn require(&mut self, id: &CustodyId) -> Result<Requirement> {
        let source = self.source.as_ref().ok_or_else(|| id.kind().corrupt())?;
        let (through, committed) = self
            .subjects
            .entry(id.subject().clone())
            .or_insert((id.generation(), None));
        *through = (*through).max(id.generation());
        if committed.is_some_and(|newest| id.generation() <= newest) {
            return Ok(Requirement::Retired);
        }
        match LocalCustody::at(source).state(id)? {
            EntryState::Retired => Ok(Requirement::Retired),
            EntryState::Live => Ok(Requirement::Live),
            EntryState::Missing => Err(id.kind().corrupt()),
        }
    }
}

/// A custody directory a fork created, named by device and inode so its
/// cleanup never removes a directory that replaced it. The directory stays
/// open for the fork's life, so no other directory can take its inode number
/// while the cleanup may still compare against it.
pub(crate) struct ForkedCustodyDir {
    path: PathBuf,
    identity: (u64, u64),
    directory: File,
}

impl ForkedCustodyDir {
    /// The custody directory a restore just made at `path` and holds open
    /// as `directory`: a disaster recovery's landing (KS-4), removed as a
    /// fork's is when the restore fails.
    pub(super) fn made(path: PathBuf, directory: File) -> crate::error::Result<Self> {
        Ok(Self {
            identity: directory_identity(&directory.metadata()?).ok_or_else(custody_corrupt)?,
            path,
            directory,
        })
    }

    /// Syncs the directory the fork or landing made.
    pub(super) fn sync(&self) -> crate::error::Result<()> {
        Ok(self.directory.sync_all()?)
    }

    /// Removes the fork's entries and markers, for a restore that failed or
    /// was refused after it; best effort, and only while the path still
    /// names the directory the fork created.
    pub(crate) fn remove(self) {
        if fs::symlink_metadata(&self.path)
            .ok()
            .and_then(|meta| directory_identity(&meta))
            == Some(self.identity)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(unix)]
fn directory_identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    meta.is_dir().then(|| (meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn directory_identity(_: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

impl LocalCustody<'_> {
    /// Every generation this custody holds an entry or a retirement marker
    /// for, whatever its subject, in id order, with its state (a marker
    /// dominates). A name the engine would not write is not one it reads;
    /// temporaries are not entries. A reader that needs a consistent census
    /// holds [`super::KeyCustody::read_guard`] across it: the fork reads its
    /// source's retirement facts here, and the KS-4 custody head reads every
    /// live entry and retirement fact the same way.
    pub(crate) fn census(&self) -> Result<Vec<(CustodyId, EntryState)>> {
        let subjects = match fs::read_dir(self.compartment()?) {
            Ok(subjects) => subjects,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut census = BTreeMap::new();
        for entry in subjects {
            let entry = entry?;
            let Some(subject) = entry
                .file_name()
                .to_str()
                .and_then(|name| CustodySubject::from_dir_name(self.binding().vault(), name))
            else {
                continue;
            };
            for file in fs::read_dir(entry.path())? {
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
                    let slot = census
                        .entry(subject.at(generation))
                        .or_insert(EntryState::Live);
                    if state == EntryState::Retired {
                        *slot = state;
                    }
                }
            }
        }
        Ok(census.into_iter().collect())
    }

    /// Forks this custody into a new one for `destination`, beside its root,
    /// which must hold no custody yet. Every generation this custody
    /// retired stays retired there, whatever its subject. For each subject
    /// `plan` names, through its newest generation, one a carried-out
    /// retirement destroys is retired there as well, and every other entry
    /// still live here is copied, each re-checked here as it is copied. The
    /// copy thus counts generations as this custody does, so its own
    /// retirements reach every entry it holds. Everything is synced before
    /// this returns; a fork that fails removes what it created. `None` when
    /// there is nothing to copy.
    pub(crate) fn fork(
        &self,
        destination: &CustodyBinding,
        plan: &CustodyPlan,
    ) -> Result<Option<ForkedCustodyDir>> {
        let retired: Vec<CustodyId> = self
            .census()?
            .into_iter()
            .filter_map(|(id, state)| (state == EntryState::Retired).then_some(id))
            .collect();
        if retired.is_empty() && plan.subjects.is_empty() {
            return Ok(None);
        }
        let target = LocalCustody::at(destination);
        let path = container(destination.root())?;
        let directory = make_new_dir(&path, None)?;
        let forked = ForkedCustodyDir {
            identity: directory_identity(&directory.metadata()?).ok_or_else(custody_corrupt)?,
            path,
            directory,
        };
        let copied = (|| -> Result<()> {
            target.open_compartment()?;
            for id in &retired {
                if self.retired(id)? {
                    target.retire_local(id)?;
                }
            }
            for (subject, (through, committed)) in &plan.subjects {
                for generation in 0..=*through {
                    let id = subject.at(generation);
                    if committed.is_some_and(|newest| generation <= newest) {
                        target.retire_local(&id)?;
                    } else if self.state(&id)? == EntryState::Live {
                        target.publish(&id, &self.read(&id)?)?;
                    }
                }
            }
            forked.directory.sync_all()?;
            Ok(())
        })();
        match copied {
            Ok(()) => Ok(Some(forked)),
            Err(err) => {
                forked.remove();
                Err(err)
            }
        }
    }
}
