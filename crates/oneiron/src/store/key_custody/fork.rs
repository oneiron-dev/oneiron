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

use crate::error::{Error, Result};
use crate::recovery::checkpoint::{Rejected, RestoreAdmissionReason as R};

use super::credential_faults::{forgone, fork_step};
use super::files::{EntryState, LocalCustody, container, entry_name, make_new_dir, marker_name};
use super::holders::HolderDebt;
use super::identity::{CustodyBinding, CustodyId, CustodySubject, custody_corrupt};
use super::platform;
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
/// A subject required by exact id (a holder's known-value history, KS-3)
/// copies those ids alone: no slot an aborted writer left, nor one no row
/// commits to. A subject a restore may land without (a world key pad, KS-5;
/// the host issuer seed escrow) is optional: a fork that cannot read it
/// there copies it not, warned with its kind.
pub(crate) struct CustodyPlan {
    source: Option<CustodyBinding>,
    subjects: BTreeMap<CustodySubject, (u64, Option<u64>)>,
    exact: BTreeMap<CustodySubject, BTreeSet<u64>>,
    optional: BTreeSet<CustodySubject>,
    /// Each holder debt the copy carries (FIX 12192): planned from the
    /// debts standing at the source, never required, and copied only
    /// while it still stands there when the fork runs.
    holders: BTreeSet<HolderDebt>,
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
        Self {
            source,
            subjects,
            exact: BTreeMap::new(),
            optional: BTreeSet::new(),
            holders: BTreeSet::new(),
        }
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
        self.require_rejected(id).map_err(Error::from)
    }

    /// [`Self::require`] with the reason a restore names its refusal by
    /// (FIX 6474): no custody to hold `id`, or none of its entry there, is
    /// `custody_key_missing` beside the same error; a failed read of its
    /// state is typed by its kind.
    pub(crate) fn require_rejected(
        &mut self,
        id: &CustodyId,
    ) -> std::result::Result<Requirement, Rejected> {
        let missing = || Rejected::new(R::CustodyKeyMissing, id.kind().corrupt());
        let source = self.source.as_ref().ok_or_else(missing)?;
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
            EntryState::Missing => Err(missing()),
        }
    }

    /// [`Self::require`], with `id` the only generation of its subject a
    /// fork copies besides the others required this way (KS-3).
    pub(crate) fn require_exact(&mut self, id: &CustodyId) -> Result<Requirement> {
        let requirement = self.require(id)?;
        self.exact
            .entry(id.subject().clone())
            .or_default()
            .insert(id.generation());
        Ok(requirement)
    }

    /// [`Self::require`] for an id a restore may land without (KS-5, FIX
    /// 5686 part 2): a world key pad an image row names, or the host issuer
    /// seed escrow a side restore carries. `None` when no custody is there
    /// to hold it, or its entry there is missing; its subject is planned all
    /// the same, optional, and a fork copies nothing it lacks or cannot
    /// read. The row's restore decides what a missing one means.
    pub(crate) fn require_present(&mut self, id: &CustodyId) -> Result<Option<Requirement>> {
        self.optional.insert(id.subject().clone());
        let (through, committed) = self
            .subjects
            .entry(id.subject().clone())
            .or_insert((id.generation(), None));
        *through = (*through).max(id.generation());
        if committed.is_some_and(|newest| id.generation() <= newest) {
            return Ok(Some(Requirement::Retired));
        }
        let Some(source) = self.source.as_ref() else {
            return Ok(None);
        };
        Ok(match LocalCustody::at(source).state(id)? {
            EntryState::Retired => Some(Requirement::Retired),
            EntryState::Live => Some(Requirement::Live),
            EntryState::Missing => None,
        })
    }

    /// [`Self::require_exact`] for a credential value an image or an
    /// archive commits to (KS-6, CALLS `KS-6 required restore set`): `id`
    /// is the only generation of its subject a fork copies, planned before
    /// its state is read, so a read fault never widens the fork to older
    /// generations. `None` when no custody is there to hold it, or its entry
    /// there is missing: the caller decides what that absence means. A
    /// failed read of its state is an error, never absence.
    pub(crate) fn require_exact_present(&mut self, id: &CustodyId) -> Result<Option<Requirement>> {
        self.exact
            .entry(id.subject().clone())
            .or_default()
            .insert(id.generation());
        let (through, committed) = self
            .subjects
            .entry(id.subject().clone())
            .or_insert((id.generation(), None));
        *through = (*through).max(id.generation());
        if committed.is_some_and(|newest| id.generation() <= newest) {
            return Ok(Some(Requirement::Retired));
        }
        let Some(source) = self.source.as_ref() else {
            return Ok(None);
        };
        Ok(match LocalCustody::at(source).state(id)? {
            EntryState::Retired => Some(Requirement::Retired),
            EntryState::Live => Some(Requirement::Live),
            EntryState::Missing => None,
        })
    }

    /// Plans `debt` for the copy to carry (FIX 12192): a fork copies it
    /// while it still stands at the source, never required and never a
    /// refusal when it does not.
    pub(crate) fn plan_holder_debt(&mut self, debt: HolderDebt) {
        self.holders.insert(debt);
    }

    /// Whether a fork copies `id` while it is live: every generation of a
    /// subject not required by exact id, else only those required.
    fn copies(&self, id: &CustodyId) -> bool {
        self.exact
            .get(id.subject())
            .is_none_or(|generations| generations.contains(&id.generation()))
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
        platform::sync_held(&self.directory, &self.path)
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

fn directory_identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    platform::directory_identity(meta)
}

impl LocalCustody<'_> {
    /// Every generation this custody holds an entry or a retirement marker
    /// for, whatever its subject, in id order, with its state (a marker
    /// dominates). A name the engine would not write is not one it reads;
    /// temporaries are not entries. A reader that needs a consistent census
    /// holds [`super::KeyCustody::read_guard`] across it: the fork reads its
    /// source's retirement facts here, and the KS-4 custody head reads every
    /// live entry and retirement fact the same way. A credential's directory
    /// that does not list is left out, warned (KS-6): its keys stay where
    /// they are for that pass.
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
            let generations = match subject_generations(&entry.path()) {
                Ok(generations) => generations,
                Err(error) => {
                    forgone(&subject, error, "its directory did not list")?;
                    continue;
                }
            };
            for (generation, state) in generations {
                let slot = census
                    .entry(subject.at(generation))
                    .or_insert(EntryState::Live);
                if state == EntryState::Retired {
                    *slot = state;
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
    /// still live here is copied (of a subject required by exact id, only
    /// those ids), each re-checked here as it is copied; an optional one
    /// this custody cannot read is not copied, warned. Each holder debt
    /// `plan` carries that still stands here is copied as well (FIX
    /// 12192). The copy thus counts generations as this custody does, so
    /// its own retirements reach every entry it holds. Everything is
    /// synced before
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
        if retired.is_empty() && plan.subjects.is_empty() && plan.holders.is_empty() {
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
            // KS-6: a credential's key a fork cannot copy stays behind,
            // warned, and the fork goes on as it did (fork_step). A
            // connector call's resume key (FIX 9157) stays behind the same
            // way.
            for id in &retired {
                let step = self.retired(id).and_then(|retired| {
                    if retired {
                        target.retire_local(id)
                    } else {
                        Ok(())
                    }
                });
                fork_step(id, step)?;
            }
            for (subject, (through, committed)) in &plan.subjects {
                for generation in 0..=*through {
                    let id = subject.at(generation);
                    if committed.is_some_and(|newest| generation <= newest) {
                        fork_step(&id, target.retire_local(&id))?;
                    } else if plan.copies(&id) {
                        let read_live = || match self.state(&id)? {
                            EntryState::Live => self.read(&id).map(Some),
                            EntryState::Retired | EntryState::Missing => Ok(None),
                        };
                        // A key its restore may land without (a world key
                        // pad, KS-5; the host issuer seed escrow): a failed
                        // read never stops the fork; its restore decides.
                        let live = match read_live() {
                            Err(error) if crate::store::credential_kind(subject.kind()) => {
                                fork_step(&id, Err(error))?;
                                None
                            }
                            Err(error) if plan.optional.contains(subject) => {
                                tracing::warn!(
                                    subject = ?subject.kind(),
                                    generation,
                                    kind = ?error.kind(),
                                    "an optional key custody could not read was not forked"
                                );
                                None
                            }
                            live => live?,
                        };
                        if let Some(secret) = live {
                            fork_step(&id, target.publish(&id, &secret))?;
                        }
                    }
                }
            }
            // Every holder debt the plan carries that still stands here
            // (FIX 12192): a retired key's copy kept elsewhere still
            // reads `custody_remote_retirement_pending(<holder>)` at the
            // copy. The debts are re-listed here, so one cleared after
            // the plan is not copied; a fault listing them is warned and
            // none are copied, as for an unreadable optional subject,
            // while a fault writing one fails the fork, as any other
            // copied entry's does.
            if !plan.holders.is_empty() {
                match self.holder_debts() {
                    Ok(standing) => {
                        for debt in plan.holders.intersection(&standing) {
                            target.put_holder_debt(debt)?;
                        }
                    }
                    Err(error) => tracing::warn!(
                        kind = ?error.kind(),
                        "the holder debts did not list for this fork;                          the copy carries none of them"
                    ),
                }
            }
            forked.sync()?;
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

/// Every generation one subject's directory `dir` holds an entry or a
/// retirement marker for, by its canonical name, with its state; a name the
/// engine would not write is not one it reads.
fn subject_generations(dir: &std::path::Path) -> Result<Vec<(u64, EntryState)>> {
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
