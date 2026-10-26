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

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;

use super::files::{EntryState, LocalCustody};
use super::identity::{CustodyId, CustodyKind, CustodySecret, CustodySubject};
use super::retirement::{
    RetireCause, RetirementIntent, retirements_in_txn, stage_retirement_in_txn,
};

/// What an erasable key serves: its item's first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ErasablePurpose {
    /// One actor's content in a home handoff: parent = the actor.
    HomeHandoff,
    /// One federation grant's scope opening: parent = the grant.
    #[allow(
        dead_code,
        reason = "KC-B's per-grant adapter (FIX 7907, 7958) mints under it"
    )]
    GrantScope,
}

impl ErasablePurpose {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::HomeHandoff => 1,
            Self::GrantScope => 2,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::HomeHandoff),
            2 => Some(Self::GrantScope),
            _ => None,
        }
    }
}

/// The width of an erasable key's item: purpose (1) | parent (16) |
/// incarnation (32) | ref (32).
const ITEM_LEN: usize = 81;

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
    /// live, retired or never published, from its directory names alone.
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
    /// earlier attempt published, kept (a retry reuses it), or a new one
    /// under a fresh random ref. Its entry is synced and its Mint journaled
    /// before this returns, so before anything sealed under it commits. A
    /// retired one is refused, never minted again.
    pub(crate) fn mint_erasable(
        &self,
        purpose: ErasablePurpose,
        parent: &[u8; 16],
        incarnation: &[u8; 32],
    ) -> Result<(ErasableItem, CustodySecret)> {
        let lead = lead(purpose, parent, Some(incarnation));
        for subject in self.subjects_with_prefix(CustodyKind::ErasableKey, &lead)? {
            let Some(item) = ErasableItem::of_item(subject.item()) else {
                continue;
            };
            if self.state(&subject.at(0))? == EntryState::Retired {
                return Err(CustodyKind::ErasableKey.corrupt());
            }
            return Ok((item, self.get_or_create(&subject.at(0))?));
        }
        let mut key_ref = [0u8; 32];
        crate::world_keys::os_fill(&mut key_ref)?;
        let item = ErasableItem {
            purpose,
            parent: *parent,
            incarnation: *incarnation,
            key_ref,
        };
        let secret = self.get_or_create(&item.id(self)?)?;
        Ok((item, secret))
    }

    /// The key of ref `key_ref` this custody holds a directory for, live,
    /// retired or never published, from its directory names alone: no
    /// metadata row is needed, so a writer that minted it and has not
    /// committed finds it too.
    pub(crate) fn erasable_by_ref(&self, key_ref: &[u8; 32]) -> Result<Option<ErasableItem>> {
        Ok(self
            .subjects_with_prefix(CustodyKind::ErasableKey, &[])?
            .iter()
            .filter_map(|subject| ErasableItem::of_item(subject.item()))
            .find(|item| &item.key_ref == key_ref))
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
        let owed =
            !retirements_in_txn(self, &self.env.read_txn()?, CustodyKind::ErasableKey)?.is_empty();
        if owed {
            self.finish_custody_retirements(CustodyKind::ErasableKey, |_, intent| {
                if intent.cause == RetireCause::Erase {
                    Ok(true)
                } else {
                    Err(Error::CorruptedIndex(
                        "erasable keys retire for an erase only",
                    ))
                }
            })?;
        }
        Ok(owed)
    }
}
