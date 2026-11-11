//! Erasable keys (FIX 8875): one independent custody key per parent and
//! incarnation, for a client whose content must stop opening once its parent
//! is erased, wherever the key was copied. A key is named by 32 random bytes
//! (its ref), never by its parent or its content; its custody item carries
//! purpose, parent, incarnation and ref, so every key of one parent is found
//! by its directory names, an aborted writer's orphans included.
//!
//! A home handoff's actor content is the first client
//! (`crate::store::home_handoff_custody`); a grant's scope opening (KC-B,
//! FIX 7907, 7958) the second. Custody owns storage and lifecycle only: a
//! key is minted once and journaled before anything sealed under it
//! commits, a retry finds and keeps it, a retired one is never minted again,
//! and its retirement runs through custody's one finisher. Each key's
//! metadata row (`key_custody:erasable_ref:v1:`) names it by ref; the
//! exterior holder debt of a copy sent elsewhere is [`super::holders`]'s.
//!
//! `<compartment>/.erasable-refs/<ref hex>` holds each key's item, written
//! and synced before its directory is made, whichever path makes it (a
//! mint, an install, a fork's or a landing's copy, a retirement), and kept
//! as long as that directory: a key is found by its ref in one open and one
//! stat, never a listing of the compartment (FIX 11208). One ref names one
//! item; a second item under the same ref is refused.
//!
//! `<compartment>/.erasable-leads/<lead hex>` holds the item of the first
//! key filed for each purpose, parent and incarnation, filed on the same
//! path just after its ref entry (FIX 16230): a mint, or its retry, finds
//! its key in one open, never a listing of the compartment. A second key of
//! one lead (a copy's, or a racing writer's) keeps its own ref entry and
//! directory, and a listing of the parent's keys still finds it.
//!
//! `<compartment>/.erasable-tombstones/<subject directory name>` stands
//! for a drafter artifact key whose retirement is final (FIX 16230): its
//! marker was synced, its entry unlinked and its intent cleared, so its
//! directory goes and the compartment lists live keys only. A tombstone
//! retires its key as a marker does, for every reader of a retirement (a
//! state read, a mint, a publication, an install, the census a fork or a
//! custody head reads), so a tombstoned key is never minted or installed
//! again. Other purposes keep their directories: a home handoff's or a
//! grant's key may have copies whose holders are listed by parent.

use std::fs;
use std::path::PathBuf;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;

use super::files::{EntryState, LocalCustody, exists, open_dir, read_whole, write_once};
use super::identity::{CustodyId, CustodyKind, CustodySecret, CustodySubject};
use super::platform;
use super::retirement::{
    RetireCause, RetirementIntent, retirements_in_txn, stage_retirement_in_txn,
};

/// What an erasable key serves: its item's first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ErasablePurpose {
    /// One actor's content in a home handoff: parent = the actor.
    HomeHandoff,
    /// One federation grant's scope opening: parent = the grant.
    GrantScope,
    /// One sealed artifact of a vault's own drafter (FIX 12569): parent =
    /// the drafter version, incarnation = derived from the artifact's id.
    DrafterArtifact,
    /// A person's authenticator-app enrollment; incarnation = enrollment id.
    TotpEnrollment,
}

impl ErasablePurpose {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::HomeHandoff => 1,
            Self::GrantScope => 2,
            Self::DrafterArtifact => 3,
            Self::TotpEnrollment => 4,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::HomeHandoff),
            2 => Some(Self::GrantScope),
            3 => Some(Self::DrafterArtifact),
            4 => Some(Self::TotpEnrollment),
            _ => None,
        }
    }
}

/// The width of an erasable key's item: purpose (1) | parent (16) |
/// incarnation (32) | ref (32).
const ITEM_LEN: usize = 81;

/// The compartment's directory of each key's item, by ref (FIX 11208).
const REF_INDEX: &str = ".erasable-refs";

/// The compartment's directory of each lead's first key item (FIX 16230).
const LEAD_INDEX: &str = ".erasable-leads";

/// The compartment's directory of the tombstones of drafter artifact keys
/// whose retirement is final (FIX 16230).
const TOMBSTONES: &str = ".erasable-tombstones";

/// One erasable key's full name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ErasableItem {
    pub(crate) purpose: ErasablePurpose,
    pub(crate) parent: [u8; 16],
    pub(crate) incarnation: [u8; 32],
    pub(crate) key_ref: [u8; 32],
}

impl ErasableItem {
    /// The custody item: purpose | parent | incarnation | ref.
    fn item(&self) -> [u8; ITEM_LEN] {
        let mut item = [0u8; ITEM_LEN];
        item[0] = self.purpose.code();
        item[1..17].copy_from_slice(&self.parent);
        item[17..49].copy_from_slice(&self.incarnation);
        item[49..].copy_from_slice(&self.key_ref);
        item
    }

    /// The key a custody item names; `None` for one custody would not
    /// write.
    pub(crate) fn of_item(item: &[u8]) -> Option<Self> {
        if item.len() != ITEM_LEN {
            return None;
        }
        Some(Self {
            purpose: ErasablePurpose::from_code(item[0])?,
            parent: item[1..17].try_into().ok()?,
            incarnation: item[17..49].try_into().ok()?,
            key_ref: item[49..].try_into().ok()?,
        })
    }

    /// The parent a custody subject of this kind names: its item's bytes 1
    /// to 17; `None` for another kind.
    pub(crate) fn parent_of(subject: &CustodySubject) -> Option<[u8; 16]> {
        if subject.kind() != CustodyKind::ErasableKey {
            return None;
        }
        subject.item().get(1..17)?.try_into().ok()
    }

    /// Its custody subject in `custody`'s binding.
    pub(crate) fn subject(&self, custody: &LocalCustody<'_>) -> Result<CustodySubject> {
        custody
            .binding()
            .subject(CustodyKind::ErasableKey, &self.item())
    }

    /// Its one generation in `custody`'s binding.
    pub(crate) fn id(&self, custody: &LocalCustody<'_>) -> Result<CustodyId> {
        Ok(self.subject(custody)?.at(0))
    }

    fn row(&self) -> RefRow {
        RefRow {
            purpose: self.purpose.code(),
            parent: self.parent,
            incarnation: self.incarnation,
        }
    }
}

/// The lead every key of `purpose` for `parent` files under, and of one
/// `incarnation` of it when given.
fn lead(purpose: ErasablePurpose, parent: &[u8; 16], incarnation: Option<&[u8; 32]>) -> Vec<u8> {
    let mut lead = vec![purpose.code()];
    lead.extend_from_slice(parent);
    if let Some(incarnation) = incarnation {
        lead.extend_from_slice(incarnation);
    }
    lead
}

/// `<ref hex>`: a key's ref index entry.
fn ref_name(key_ref: &[u8; 32]) -> String {
    crate::entity_id::bytes_to_hex_lower(key_ref)
}

/// `<lead hex>`: the lead index entry of `item`'s purpose, parent and
/// incarnation.
fn lead_name(item: &ErasableItem) -> String {
    crate::entity_id::bytes_to_hex_lower(&lead(item.purpose, &item.parent, Some(&item.incarnation)))
}

/// One key's metadata row: its purpose, parent and incarnation, by ref.
/// Never the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RefRow {
    purpose: u8,
    parent: [u8; 16],
    incarnation: [u8; 32],
}

/// Each erasable key's metadata, by its ref.
const REFS: SideTable<[u8; 32], RefRow, Named> =
    SideTable::new(&side_table::KEY_CUSTODY_ERASABLE_REF);

/// Every key of `purpose` whose metadata names `parent` in `txn`.
pub(crate) fn erasable_refs_of_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    purpose: ErasablePurpose,
    parent: &[u8; 16],
) -> Result<Vec<ErasableItem>> {
    Ok(REFS
        .scan(dbs, txn)?
        .into_iter()
        .filter(|(_, row)| row.purpose == purpose.code() && &row.parent == parent)
        .map(|(key_ref, row)| ErasableItem {
            purpose,
            parent: row.parent,
            incarnation: row.incarnation,
            key_ref,
        })
        .collect())
}

/// Puts `item`'s metadata row in `wtxn`, the writer that commits what is
/// sealed under it.
pub(crate) fn put_erasable_ref_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    item: &ErasableItem,
) -> Result<()> {
    REFS.put(dbs, wtxn, &item.key_ref, &item.row())
}

/// Deletes `item`'s metadata row in `wtxn`: an erase of its parent.
pub(crate) fn delete_erasable_ref_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    item: &ErasableItem,
) -> Result<()> {
    REFS.delete(dbs, wtxn, &item.key_ref)?;
    Ok(())
}

/// Stages the retirement of `item`'s key in `wtxn`: an erase's intent,
/// which custody's finisher carries out after commit. One already retired
/// stages nothing.
pub(crate) fn stage_erasable_retirement_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    custody: &LocalCustody<'_>,
    item: &ErasableItem,
) -> Result<()> {
    let id = item.id(custody)?;
    if custody.retired(&id)? {
        return Ok(());
    }
    stage_retirement_in_txn(
        dbs,
        wtxn,
        &RetirementIntent {
            subject: id.subject().clone(),
            through: 0,
            cause: RetireCause::Erase,
        },
    )
}

impl LocalCustody<'_> {
    /// Every erasable key of `purpose` this custody holds for `parent`,
    /// live, retired or never published, from its directory names alone. A
    /// tombstoned key has no directory and is not listed: its retirement is
    /// final (FIX 16230).
    pub(crate) fn erasable_keys_of(
        &self,
        purpose: ErasablePurpose,
        parent: &[u8; 16],
    ) -> Result<Vec<ErasableItem>> {
        Ok(self
            .subjects_with_prefix(CustodyKind::ErasableKey, &lead(purpose, parent, None))?
            .iter()
            .filter_map(|subject| ErasableItem::of_item(subject.item()))
            .collect())
    }

    /// The key of `purpose` for `parent` at `incarnation`: the one an
    /// earlier attempt filed, kept (a retry reuses it), or a new one under a
    /// fresh random ref. Its entry is synced and its Mint journaled before
    /// this returns, so before anything sealed under it commits. A retired
    /// or tombstoned one is refused, never minted again. The earlier key is
    /// found by its lead index entry in one open, whatever the compartment
    /// holds (FIX 16230).
    pub(crate) fn mint_erasable(
        &self,
        purpose: ErasablePurpose,
        parent: &[u8; 16],
        incarnation: &[u8; 32],
    ) -> Result<(ErasableItem, CustodySecret)> {
        let mut item = ErasableItem {
            purpose,
            parent: *parent,
            incarnation: *incarnation,
            key_ref: [0u8; 32],
        };
        if let Some(filed) = read_whole(&self.lead_index_dir()?.join(lead_name(&item)))? {
            let filed = ErasableItem::of_item(&filed)
                .filter(|filed| {
                    filed.purpose == purpose
                        && &filed.parent == parent
                        && &filed.incarnation == incarnation
                })
                .ok_or_else(|| CustodyKind::ErasableKey.corrupt())?;
            let id = filed.id(self)?;
            if self.state(&id)? == EntryState::Retired {
                return Err(CustodyKind::ErasableKey.corrupt());
            }
            return Ok((filed, self.get_or_create(&id)?));
        }
        crate::key_material::os_fill(&mut item.key_ref)?;
        let secret = self.get_or_create(&item.id(self)?)?;
        Ok((item, secret))
    }

    /// The key of ref `key_ref` this custody holds a directory or a
    /// tombstone for, live, retired or never published: its ref index entry,
    /// then its directory or tombstone, one open and at most two stats
    /// whatever the compartment holds (FIX 11208, FIX 16230). No metadata
    /// row is needed, so a writer that minted it and has not committed finds
    /// it too; an entry whose directory was never made names none.
    pub(crate) fn erasable_by_ref(&self, key_ref: &[u8; 32]) -> Result<Option<ErasableItem>> {
        let Some(filed) = read_whole(&self.ref_index_dir()?.join(ref_name(key_ref)))? else {
            return Ok(None);
        };
        let item = ErasableItem::of_item(&filed)
            .filter(|item| &item.key_ref == key_ref)
            .ok_or_else(|| CustodyKind::ErasableKey.corrupt())?;
        let subject = item.subject(self)?;
        Ok(
            (exists(&self.subject_dir(&subject)?)? || self.erasable_tombstoned(&subject)?)
                .then_some(item),
        )
    }

    fn ref_index_dir(&self) -> Result<PathBuf> {
        Ok(self.compartment()?.join(REF_INDEX))
    }

    fn lead_index_dir(&self) -> Result<PathBuf> {
        Ok(self.compartment()?.join(LEAD_INDEX))
    }

    fn tombstone_dir(&self) -> Result<PathBuf> {
        Ok(self.compartment()?.join(TOMBSTONES))
    }

    /// Whether `subject`, an erasable key, stands tombstoned here: its
    /// retirement is final and its directory gone (FIX 16230). One stat.
    pub(super) fn erasable_tombstoned(&self, subject: &CustodySubject) -> Result<bool> {
        if subject.kind() != CustodyKind::ErasableKey || subject.vault() != self.binding().vault() {
            return Ok(false);
        }
        exists(&self.tombstone_dir()?.join(subject.dir_name()))
    }

    /// Every tombstoned erasable key here, from the tombstones' names alone:
    /// each is retired at its one generation, for the census (FIX 16230). No
    /// tombstone directory holds none; a temporary is no tombstone.
    pub(super) fn erasable_tombstones(&self) -> Result<Vec<CustodySubject>> {
        let names = match fs::read_dir(self.tombstone_dir()?) {
            Ok(names) => names,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut subjects = Vec::new();
        for name in names {
            let name = name?.file_name();
            let Some(subject) = name
                .to_str()
                .and_then(|name| CustodySubject::from_dir_name(self.binding().vault(), name))
            else {
                continue;
            };
            if subject.kind() == CustodyKind::ErasableKey {
                subjects.push(subject);
            }
        }
        subjects.sort();
        Ok(subjects)
    }

    /// Replaces the directory of `subject`, an erasable key whose retirement
    /// is final, with its tombstone (FIX 16230): the tombstone is synced
    /// first, then the directory (its marker, its journal mark, any
    /// temporary) is removed and the compartment synced. A crash between
    /// leaves both, which retire the key alike, and the next pass removes
    /// the directory. A key that is not retired, or whose entry is still
    /// there, is left as it is.
    fn tombstone_erasable(&self, subject: &CustodySubject) -> Result<()> {
        let dir = self.subject_dir(subject)?;
        if !exists(&dir)? {
            return Ok(());
        }
        let id = subject.at(0);
        if !self.retired(&id)? || self.published(&id)? {
            return Ok(());
        }
        let tombstones = self.tombstone_dir()?;
        open_dir(&tombstones, true, Some(CustodyKind::ErasableKey))?;
        write_once(&tombstones, &subject.dir_name(), &[])?;
        fs::remove_dir_all(&dir)?;
        platform::sync_dir(&self.compartment()?)?;
        Ok(())
    }

    /// Files `subject`'s item under its ref, synced, before its directory
    /// is made (FIX 11208): every path that makes an erasable key's
    /// directory comes through here. An item already filed is kept; another
    /// item under the same ref is refused. An item custody would not write
    /// is not filed, as no lookup by ref ever named it.
    pub(super) fn index_erasable(&self, subject: &CustodySubject) -> Result<()> {
        let Some(item) = ErasableItem::of_item(subject.item()) else {
            return Ok(());
        };
        let dir = self.ref_index_dir()?;
        let name = ref_name(&item.key_ref);
        let path = dir.join(&name);
        let written = if exists(&path)? {
            false
        } else {
            open_dir(&dir, true, Some(CustodyKind::ErasableKey))?;
            write_once(&dir, &name, subject.item())?
        };
        if !written && read_whole(&path)?.as_deref() != Some(subject.item()) {
            return Err(CustodyKind::ErasableKey.corrupt());
        }
        // FIX 16230: the first key filed for its lead is the one a mint
        // finds; a second key of one lead keeps the first's entry.
        let leads = self.lead_index_dir()?;
        let lead = lead_name(&item);
        if !exists(&leads.join(&lead))? {
            open_dir(&leads, true, Some(CustodyKind::ErasableKey))?;
            write_once(&leads, &lead, subject.item())?;
        }
        Ok(())
    }

    /// Where `item`'s key stands here.
    pub(crate) fn erasable_state(&self, item: &ErasableItem) -> Result<EntryState> {
        self.state(&item.id(self)?)
    }

    /// `item`'s live key, read strictly: a retired, damaged or missing one
    /// is an error.
    pub(crate) fn read_erasable(&self, item: &ErasableItem) -> Result<CustodySecret> {
        self.read(&item.id(self)?)
    }

    /// Installs `secret`, a key another holder sent, as `item`'s entry:
    /// synced and its Mint journaled before this returns. The same bytes
    /// already there are accepted; other bytes, or a retired key, refused.
    pub(crate) fn install_erasable(
        &self,
        item: &ErasableItem,
        secret: &CustodySecret,
    ) -> Result<()> {
        self.publish_minted(&item.id(self)?, secret)
    }
}

impl Store {
    /// Carries out every staged erasable key retirement (FIX 8875), an
    /// interrupted process's included, in the custody finisher's order:
    /// whether any was owed. Only an erase retires one.
    ///
    /// # Errors
    /// An archived vault with a retirement standing, an intent of another
    /// cause, and custody faults: the next pass retries.
    pub(crate) fn finish_erasable_retirements(&self) -> Result<bool> {
        let owed = retirements_in_txn(self, &self.env.read_txn()?, CustodyKind::ErasableKey)?;
        if owed.is_empty() {
            return Ok(false);
        }
        self.finish_custody_retirements_then(
            CustodyKind::ErasableKey,
            |_, intent| {
                if intent.cause == RetireCause::Erase {
                    Ok(true)
                } else {
                    Err(Error::CorruptedIndex(
                        "erasable keys retire for an erase only",
                    ))
                }
            },
            tombstone_final_drafter_key,
        )?;
        Ok(true)
    }
}

/// Tombstones a drafter artifact key once its retirement is carried out
/// (FIX 16230): its directory is replaced by a tombstone under the
/// finisher's custody lock and writer, before its intent clears, so an
/// interrupted or failed tombstone stays owed and the next pass makes it
/// again (a tombstoned key reads retired, and an absent directory is
/// already done). Other purposes keep their directories.
fn tombstone_final_drafter_key(custody: LocalCustody<'_>, intent: &RetirementIntent) -> Result<()> {
    let drafter = ErasableItem::of_item(intent.subject.item())
        .is_some_and(|item| item.purpose == ErasablePurpose::DrafterArtifact);
    if drafter {
        custody.tombstone_erasable(&intent.subject)?;
    }
    Ok(())
}
