//! Core half of `store::key_custody::files`: its store-layer items live in `oneiron_store::key_custody::files` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::key_custody::files::*;

use super::identity::{
    CustodyBinding, CustodyId, CustodyKind, CustodySecret, CustodySubject, custody_corrupt,
};
use super::platform;
use crate::error::{Error, Result};
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// One binding's custody on this host's filesystem. It owns storage and
/// lifecycle only: whether a subject may be read, published or retired is
/// its client's policy.
#[derive(Clone, Copy)]
pub(crate) struct LocalCustody<'a> {
    binding: &'a CustodyBinding,
}

impl<'a> LocalCustody<'a> {
    pub(crate) fn at(binding: &'a CustodyBinding) -> Self {
        Self { binding }
    }

    pub(crate) fn binding(&self) -> &'a CustodyBinding {
        self.binding
    }
}

impl LocalCustody<'_> {
    /// This binding's compartment in its container.
    pub(super) fn compartment(&self) -> Result<PathBuf> {
        Ok(container(self.binding.root())?.join(self.binding.compartment_name()))
    }

    /// Opens this binding's compartment, making it and its container when
    /// absent.
    pub(super) fn open_compartment(&self) -> Result<()> {
        open_dir(&container(self.binding.root())?, true, None)?;
        open_dir(&self.compartment()?, true, None)?;
        Ok(())
    }

    /// `subject`'s directory; refused for another vault's subject.
    pub(super) fn subject_dir(&self, subject: &CustodySubject) -> Result<PathBuf> {
        if subject.vault() != self.binding.vault() {
            return Err(subject.kind().corrupt());
        }
        Ok(self.compartment()?.join(subject.dir_name()))
    }

    /// Opens the directories down to `subject`'s, each checked on the way,
    /// making the missing ones `create` names.
    fn open_subject(&self, subject: &CustodySubject, create: Create) -> Result<(PathBuf, File)> {
        let kind = Some(subject.kind());
        let dir = self.subject_dir(subject)?;
        open_dir(
            &container(self.binding.root())?,
            create == Create::All,
            kind,
        )?;
        open_dir(&self.compartment()?, create == Create::All, kind)?;
        // FIX 11208: an erasable key's ref is filed before its directory.
        if create != Create::Nothing && subject.kind() == CustodyKind::ErasableKey {
            self.index_erasable(subject)?;
        }
        let file = open_dir(&dir, create != Create::Nothing, kind)?;
        Ok((dir, file))
    }

    pub(crate) fn retired(&self, id: &CustodyId) -> Result<bool> {
        retired_in(&self.subject_dir(id.subject())?, id.generation(), id.kind())
    }

    /// Whether an entry was published for `id` and is still there. No
    /// custody directory means no entry at all.
    pub(crate) fn published(&self, id: &CustodyId) -> Result<bool> {
        exists(
            &self
                .subject_dir(id.subject())?
                .join(entry_name(id.generation())),
        )
    }

    /// Retired dominates: a crash between a marker and its unlink leaves an
    /// entry no one may read.
    pub(crate) fn state(&self, id: &CustodyId) -> Result<EntryState> {
        Ok(if self.retired(id)? {
            EntryState::Retired
        } else if self.published(id)? {
            EntryState::Live
        } else {
            EntryState::Missing
        })
    }

    /// The first generation of `subject` no marker retires.
    pub(crate) fn first_unretired(&self, subject: &CustodySubject) -> Result<u64> {
        let mut generation = 0_u64;
        while self.retired(&subject.at(generation))? {
            generation = generation
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("key custody generation"))?;
        }
        Ok(generation)
    }

    /// Reads a live entry, strictly: a retired, short or long one is damaged,
    /// and a missing one fails.
    pub(crate) fn read(&self, id: &CustodyId) -> Result<CustodySecret> {
        let kind = id.kind();
        let (dir, _directory) = self.open_subject(id.subject(), Create::Nothing)?;
        if retired_in(&dir, id.generation(), kind)? {
            return Err(kind.corrupt());
        }
        #[cfg(test)]
        AFTER_KEY_MARKER_CHECK.with(|slot| {
            if let Some(callback) = slot.borrow_mut().take() {
                callback();
            }
        });
        let mut file = safe_open(
            &dir.join(entry_name(id.generation())),
            false,
            false,
            Some(kind),
        )?;
        strict_read(&mut file, kind)
    }

    /// Opens `id`'s subject directory for a publication, making what is
    /// missing, with interrupted temporaries removed and the directory
    /// synced. A retired id is refused.
    fn prepare(&self, id: &CustodyId) -> Result<(PathBuf, File)> {
        let (dir, directory) = self.open_subject(id.subject(), Create::All)?;
        clean_pending(&dir)?;
        platform::sync_held(&directory, &dir)?;
        if retired_in(&dir, id.generation(), id.kind())? {
            return Err(id.kind().corrupt());
        }
        Ok((dir, directory))
    }

    /// Publishes `secret` as `id`'s entry, synced before this returns, so
    /// before any reference to it commits. The same bytes already there are
    /// accepted; other bytes, a retired id, or a secret not the kind's width
    /// are refused.
    pub(crate) fn publish(&self, id: &CustodyId, secret: &CustodySecret) -> Result<()> {
        let kind = id.kind();
        if secret.expose().len() != kind.secret_len() {
            return Err(kind.corrupt());
        }
        let (dir, directory) = self.prepare(id)?;
        let path = dir.join(entry_name(id.generation()));
        let published =
            !exists(&path)? && write_entry(&dir, &path, id.generation(), secret.expose(), kind)?;
        platform::sync_held(&directory, &dir)?;
        if !published && self.read(id)?.expose() != secret.expose() {
            return Err(kind.corrupt());
        }
        Ok(())
    }

    /// Publishes `secret`, bytes its client computed, as the new entry `id`
    /// and journals its Mint (KS-3): the entry synced, then the frame synced,
    /// both before this returns, so before any reference to it commits. The
    /// client takes `id` past every generation its subject holds, so an
    /// interrupted call's entry is never published again: it is debris an
    /// erase of the subject still retires.
    pub(crate) fn publish_minted(&self, id: &CustodyId, secret: &CustodySecret) -> Result<()> {
        self.publish(id, secret)?;
        self.journal_mint(id)
    }

    /// Journals `id`'s Mint, synced, unless its mark says a frame already
    /// holds it; then marks it (FIX 5798, 6781). An entry whose Mint append
    /// failed, or whose writer aborted after publishing it, is journaled
    /// here at its next use, before any row sealed under it commits: one
    /// frame per entry, not one per use. A mark lost to a crash only
    /// journals the Mint again, which moves the log on and changes no set.
    fn journal_mint(&self, id: &CustodyId) -> Result<()> {
        let dir = self.subject_dir(id.subject())?;
        if exists(&dir.join(journaled_name(id.generation())))? {
            return Ok(());
        }
        self.journal_entry(&super::log::LogEntry::Mint(id.clone()))?;
        write_once(&dir, &journaled_name(id.generation()), &[])?;
        Ok(())
    }

    /// The newest generation `subject` holds an entry or a retirement marker
    /// for, an unpublished temporary aside; `None` when it holds neither, or
    /// has no directory yet.
    pub(crate) fn newest_generation(&self, subject: &CustodySubject) -> Result<Option<u64>> {
        let names = match fs::read_dir(self.subject_dir(subject)?) {
            Ok(names) => names,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let mut newest = None;
        for name in names {
            let name = name?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let generation = name
                .strip_prefix(".retired-g")
                .or_else(|| name.strip_prefix('g'))
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .filter(|&generation| {
                    name == entry_name(generation) || name == marker_name(generation)
                });
            newest = newest.max(generation);
        }
        Ok(newest)
    }

    /// Every subject of `kind` whose item begins with `prefix` that has a
    /// directory in this compartment, read from the directory names alone,
    /// in id order: every pad instance of one world (KS-5). No compartment
    /// holds none.
    pub(crate) fn subjects_with_prefix(
        &self,
        kind: CustodyKind,
        prefix: &[u8],
    ) -> Result<Vec<CustodySubject>> {
        let names = match fs::read_dir(self.compartment()?) {
            Ok(names) => names,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let lead = format!(
            "{:02x}.{}",
            kind.tag(),
            crate::entity_id::bytes_to_hex_lower(prefix)
        );
        let mut subjects = Vec::new();
        for name in names {
            let name = name?.file_name();
            let Some(name) = name.to_str().filter(|name| name.starts_with(&lead)) else {
                continue;
            };
            if let Some(subject) = CustodySubject::from_dir_name(self.binding.vault(), name)
                && subject.kind() == kind
            {
                subjects.push(subject);
            }
        }
        subjects.sort();
        Ok(subjects)
    }

    /// `id`'s entry, minting it only while unpublished, its Mint journaled
    /// whether this call minted it or found it, for every client (FIX 5798,
    /// 6781): an entry an earlier call published before its Mint failed to
    /// append, or its writer aborted, is journaled here, before any row
    /// sealed under it commits. Every reader of the log takes a Mint as a
    /// set member, so one journaled again only moves the log on. A damaged
    /// entry is never treated as absent; only an unpublished temporary is
    /// discarded. A retired id is refused, never minted again; a found key
    /// is kept.
    pub(crate) fn get_or_create(&self, id: &CustodyId) -> Result<CustodySecret> {
        let kind = id.kind();
        let (dir, directory) = self.prepare(id)?;
        let path = dir.join(entry_name(id.generation()));
        let secret = if exists(&path)? {
            self.read(id)?
        } else {
            let secret = CustodySecret::random(kind.secret_len());
            let published = write_entry(&dir, &path, id.generation(), secret.expose(), kind)?;
            platform::sync_held(&directory, &dir)?;
            if published { secret } else { self.read(id)? }
        };
        // KS-4: the mint is journaled, synced, before a row sealed under it
        // may commit.
        self.journal_mint(id)?;
        Ok(secret)
    }

    /// Destroys precisely `id`: its marker is synced, then its entry is
    /// unlinked and the directory synced, then a world pad's carried
    /// compartments go too (PAD-3). Neither an old snapshot nor a
    /// delayed retirement can revive or destroy another generation. Ordering
    /// against readers and the durable intent is the caller's
    /// ([`crate::store::Store::finish_custody_retirements`]).
    pub(crate) fn retire_local(&self, id: &CustodyId) -> Result<()> {
        let kind = id.kind();
        let (dir, directory) = self.open_subject(id.subject(), Create::Subject)?;
        match safe_open(
            &dir.join(marker_name(id.generation())),
            true,
            false,
            Some(kind),
        ) {
            Ok(file) => file.sync_all()?,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if !retired_in(&dir, id.generation(), kind)? {
                    return Err(kind.corrupt());
                }
            }
            Err(err) => return Err(err),
        }
        platform::sync_held(&directory, &dir)?;
        match fs::remove_file(dir.join(entry_name(id.generation()))) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        platform::sync_held(&directory, &dir)?;
        self.drop_carried(id.subject())
    }
}
