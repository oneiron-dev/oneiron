//! The exterior holder debt of erasable keys (FIX 8875): which other
//! machines hold a copy of a key this custody sent or received, kept beside
//! the vault and outside its image like every custody entry, so a rollback
//! of the vault never forgets a copy.
//!
//! `<compartment>/.holders/` holds one empty file per debt,
//! `<ref hex>.<holder machine hex>`: written and synced before an export
//! releases the key, and removed only once that holder's retirement of it
//! is verified. A retired key whose debt stands reads
//! `custody_remote_retirement_pending(<holder>)`, never complete.
//!
//! Each debt recorded or cleared is journaled after its file is written or
//! removed (FIX 11206), again on a retry after a failed append (FIX 12191),
//! so every member's custody head is sealed again
//! carrying the debts that stand (`head::holder_debts`), and a disaster
//! recovery's landing keeps them.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

use super::erasable::ErasablePurpose;
use super::files::{EntryState, LocalCustody, custody_present, open_dir, write_once};
use super::identity::{CustodySubject, hex_decode};
use super::log::LogEntry;
use super::platform;

const HOLDERS: &str = ".holders";

/// One copy another machine holds: the key's ref and the holder.
pub(crate) type HolderDebt = ([u8; 32], EntityId);

fn debt_name(key_ref: &[u8; 32], holder: &EntityId) -> String {
    format!(
        "{}.{}",
        crate::entity_id::bytes_to_hex_lower(key_ref),
        holder.to_hex()
    )
}

/// The debt a file name names; `None` for a name custody would not write.
fn debt_of_name(name: &str) -> Option<HolderDebt> {
    let (key_ref, holder) = name.split_once('.')?;
    let key_ref = <[u8; 32]>::try_from(hex_decode(key_ref)?).ok()?;
    let holder = EntityId::from_bytes(<[u8; 16]>::try_from(hex_decode(holder)?).ok()?).ok()?;
    (debt_name(&key_ref, &holder) == name).then_some((key_ref, holder))
}

/// `standing (1) | ref (32) | holder (16)`: a log frame's body after its op
/// (FIX 11206); `standing` is 0 for a debt cleared.
pub(super) fn encode_debt(debt: &HolderDebt, standing: bool) -> [u8; 49] {
    let mut out = [0u8; 49];
    out[0] = u8::from(standing);
    out[1..33].copy_from_slice(&debt.0);
    out[33..].copy_from_slice(debt.1.as_bytes());
    out
}

/// The debt and whether it stands a frame's body names; `None` for one
/// custody would not write.
pub(super) fn decode_debt(bytes: &[u8]) -> Option<(HolderDebt, bool)> {
    let (&standing, rest) = bytes.split_first()?;
    let (key_ref, holder) = rest.split_first_chunk::<32>()?;
    let holder = EntityId::from_bytes(<[u8; 16]>::try_from(holder).ok()?).ok()?;
    let standing = match standing {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some(((*key_ref, holder), standing))
}

impl LocalCustody<'_> {
    fn holders_dir(&self) -> Result<PathBuf> {
        Ok(self.compartment()?.join(HOLDERS))
    }

    /// Records that `holder` holds a copy of the key `key_ref`, synced
    /// before this returns: before the export that sends it releases it.
    /// Every record is journaled after its file (FIX 11206), so every head
    /// sealed at the position it moves the log to carries it; a retry
    /// after a failed append journals its frame again (FIX 12191), and a
    /// repeated frame replays as one insert.
    pub(crate) fn record_holder(&self, key_ref: &[u8; 32], holder: &EntityId) -> Result<()> {
        let debt = (*key_ref, *holder);
        self.put_holder_debt(&debt)?;
        self.journal_entry(&LogEntry::HolderDebt {
            debt,
            standing: true,
        })?;
        Ok(())
    }

    /// Keeps `debt`, synced, journaling nothing: whether it was not kept
    /// already. A disaster recovery's landing keeps each debt its head
    /// carried this way (FIX 11206).
    pub(super) fn put_holder_debt(&self, debt: &HolderDebt) -> Result<bool> {
        self.open_compartment()?;
        let dir = self.holders_dir()?;
        open_dir(&dir, true, None)?;
        write_once(&dir, &debt_name(&debt.0, &debt.1), &[])
    }

    /// Every holder debt standing here, in order. No directory holds none.
    pub(crate) fn holder_debts(&self) -> Result<BTreeSet<HolderDebt>> {
        let names = match fs::read_dir(self.holders_dir()?) {
            Ok(names) => names,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
            Err(err) => return Err(err.into()),
        };
        let mut debts = BTreeSet::new();
        for name in names {
            let name = name?.file_name();
            if let Some(debt) = name.to_str().and_then(debt_of_name) {
                debts.insert(debt);
            }
        }
        Ok(debts)
    }

    /// The holders of the key `key_ref` whose debt stands.
    pub(crate) fn holders_of(&self, key_ref: &[u8; 32]) -> Result<Vec<EntityId>> {
        Ok(self
            .holder_debts()?
            .into_iter()
            .filter(|(held, _)| held == key_ref)
            .map(|(_, holder)| holder)
            .collect())
    }

    /// Clears `holder`'s debt for the key `key_ref`, the directory synced:
    /// its retirement of the copy was verified. None standing journals a
    /// removal all the same: a retry after a failed append is no
    /// different from a clear that finds none (FIX 12191), and a repeated
    /// frame replays as one removal. No head sealed at the position the
    /// frame moves the log to carries the debt.
    pub(crate) fn clear_holder(&self, key_ref: &[u8; 32], holder: &EntityId) -> Result<()> {
        let dir = self.holders_dir()?;
        match fs::remove_file(dir.join(debt_name(key_ref, holder))) {
            Ok(()) => platform::sync_dir(&dir)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        self.journal_entry(&LogEntry::HolderDebt {
            debt: (*key_ref, *holder),
            standing: false,
        })?;
        Ok(())
    }
}

impl Store {
    /// Each erasable key custody holds whose parent is `parent` (an erased
    /// actor's, FIX 8875), with every holder whose copy's retirement is not
    /// verified yet: an erase receipt's remote steps. No custody holds none.
    pub(crate) fn erasable_holders_of(
        &self,
        parent: &[u8; 16],
    ) -> Result<Vec<(CustodySubject, Vec<EntityId>)>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Vec::new());
        };
        if !custody_present(custody.binding().root())? {
            return Ok(Vec::new());
        }
        let debts = custody.holder_debts()?;
        custody
            .erasable_keys_of(ErasablePurpose::HomeHandoff, parent)?
            .into_iter()
            .map(|item| {
                let holders = debts
                    .iter()
                    .filter(|(key_ref, _)| key_ref == &item.key_ref)
                    .map(|(_, holder)| *holder)
                    .collect();
                Ok((item.subject(&custody)?, holders))
            })
            .collect()
    }

    /// Every holder, by machine hex and once, whose copy of a key this
    /// custody retired is not verified retired yet (FIX 8875): the status
    /// read's remote steps.
    pub(crate) fn erasable_holders_pending(&self) -> Result<Vec<String>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Vec::new());
        };
        if !custody_present(custody.binding().root())? {
            return Ok(Vec::new());
        }
        let mut holders = BTreeSet::new();
        for (key_ref, holder) in custody.holder_debts()? {
            let retired = match custody.erasable_by_ref(&key_ref)? {
                Some(item) => custody.erasable_state(&item)? == EntryState::Retired,
                None => false,
            };
            if retired {
                holders.insert(holder.to_hex());
            }
        }
        Ok(holders.into_iter().collect())
    }
}
