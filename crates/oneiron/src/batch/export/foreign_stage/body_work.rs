//! What a confirmed staged import still owes its rows (FIX 12408): the
//! by-reference ASSET bodies its admitted artifact names that no landing has
//! brought yet.
//!
//! A staged artifact's metadata lands at its confirmation. A by-ref ASSET
//! whose body was not supplied then stays pending, its facet stamps held on
//! the receipt's lane. When any is owed, the confirmation keeps the artifact's
//! admitted content and staged stamps beside a work row naming each owed
//! body, so a later delivery lands it under the same receipt: digest-pinned,
//! at the receipt's tier, through the usual body landing door, and releasing
//! the stamps its birth frees. The work row names the receipt a retained copy
//! of every row the kept content carries, so an erase of any of them drops
//! the work with the content and stamps it keeps. The last owed body
//! settled, or a cancellation, drops all three; the confirmation itself is
//! never undone.
//!
//! The owner may attach a host-registered producer to the work, the source
//! home that serves the artifact's window: the sync client then fetches the
//! owed bodies from it on its own. Each attachment bumps the work's
//! generation, so a fetch begun under an earlier one lands nothing more.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::sync::federation_burst::erase::{CarriedBy, forget_in_txn, register_in_txn};

use super::export_foreign_receipt::{CONTENT, Hex64, STAMPS};

/// The bodies one confirmed staged import still owes. Key: hex64 (receipt).
const BODY_WORK: SideTable<Hex64, Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_IMPORT_BODY_WORK);

const WORK_VERSION: u8 = 1;
const WORK_LABEL: &str = "staged import body work";

/// One confirmed staged import's owed bodies and the rows its kept content
/// carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StagedImportBodyWork {
    v: u8,
    /// Each body still owed, sorted.
    pub(crate) owed: Vec<OwedBody>,
    /// Every row the kept admitted content carries, sorted.
    carried: Vec<[u8; 16]>,
    /// The host-registered producer the owner attached to fetch the owed
    /// bodies; `None` until one is.
    #[serde(default)]
    pub(crate) source: Option<[u8; 32]>,
    /// Bumped at each attachment: a fetch begun under an earlier one lands
    /// nothing more.
    #[serde(default)]
    pub(crate) generation: u64,
}

/// One owed body: the window of the admitted part that brings its row, and
/// the row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct OwedBody {
    pub(crate) window: String,
    pub(crate) entity: [u8; 16],
}

impl StagedImportBodyWork {
    /// The work of a confirmation that left `owed` bodies over content
    /// carrying `carried` rows.
    pub(crate) fn new(
        mut owed: Vec<OwedBody>,
        carried: impl IntoIterator<Item = EntityId>,
    ) -> Self {
        owed.sort();
        owed.dedup();
        let mut carried: Vec<[u8; 16]> = carried.into_iter().map(|id| *id.as_bytes()).collect();
        carried.sort_unstable();
        carried.dedup();
        Self {
            v: WORK_VERSION,
            owed,
            carried,
            source: None,
            generation: 0,
        }
    }

    fn carried_ids(&self) -> Vec<EntityId> {
        self.carried
            .iter()
            .filter_map(|bytes| EntityId::from_bytes(*bytes).ok())
            .collect()
    }

    fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|_| Error::InvariantViolation(WORK_LABEL))
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        let work: Self =
            rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(WORK_LABEL))?;
        if work.v != WORK_VERSION {
            return Err(Error::CorruptedIndex(WORK_LABEL));
        }
        Ok(work)
    }
}

/// What delivery a confirmed staged import still owes, and what one delivery
/// landed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StagedImportBodyProgress {
    /// Each body still owed: its admitted part's window and its row.
    pub owed: Vec<(String, EntityId)>,
    /// The rows whose bodies this call landed.
    pub landed: Vec<EntityId>,
}

impl StagedImportBodyProgress {
    pub(crate) fn of(owed: &[OwedBody], landed: Vec<EntityId>) -> Self {
        Self {
            owed: owed
                .iter()
                .filter_map(|body| {
                    EntityId::from_bytes(body.entity)
                        .ok()
                        .map(|id| (body.window.clone(), id))
                })
                .collect(),
            landed,
        }
    }
}

/// The bodies the confirmed receipt `id` still owes; `None` when it owes
/// none.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub(crate) fn staged_import_body_work(
    vault: &Vault,
    id: &[u8; 32],
) -> Result<Option<StagedImportBodyWork>> {
    let txn = vault.store.env.read_txn()?;
    BODY_WORK
        .get(&vault.store, &txn, &Hex64(*id))?
        .map(|raw| StagedImportBodyWork::decode(&raw))
        .transpose()
}

/// Every receipt's body work that has a producer attached, by receipt id in
/// key order. A row that does not decode is left to the doors that settle
/// or drop it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn attached_staged_import_body_work(
    vault: &Vault,
) -> Result<Vec<([u8; 32], StagedImportBodyWork)>> {
    let txn = vault.store.env.read_txn()?;
    Ok(BODY_WORK
        .scan(&vault.store, &txn)?
        .into_iter()
        .filter_map(|(key, raw)| {
            let work = StagedImportBodyWork::decode(&raw).ok()?;
            work.source.is_some().then_some((key.0, work))
        })
        .collect())
}

/// Attaches the host-registered producer `source` to the body work of the
/// confirmed receipt `id`, in one write, and answers the work's generation
/// after: a new producer bumps it, the one already attached keeps it.
/// `None` when the receipt owes no body.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub(crate) fn attach_staged_import_body_source(
    vault: &Vault,
    id: &[u8; 32],
    source: [u8; 32],
) -> Result<Option<u64>> {
    vault.with_write_txn_grouped(|w| {
        let Some(raw) = BODY_WORK.get(&vault.store, w, &Hex64(*id))? else {
            return Ok(None);
        };
        let mut work = StagedImportBodyWork::decode(&raw)?;
        if work.source == Some(source) {
            return Ok(Some(work.generation));
        }
        work.source = Some(source);
        work.generation = work
            .generation
            .checked_add(1)
            .ok_or(Error::InvariantViolation(WORK_LABEL))?;
        BODY_WORK.put(&vault.store, w, &Hex64(*id), &work.encode()?)?;
        Ok(Some(work.generation))
    })
}

/// Keeps `work` for the receipt `id` in `w`, beside the content and stamps
/// its confirmation keeps, and names the receipt a retained copy of every
/// row that content carries.
pub(super) fn keep_body_work_in_txn(
    store: &Store,
    w: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
    work: &StagedImportBodyWork,
) -> Result<()> {
    BODY_WORK.put(store, w, &Hex64(*id), &work.encode()?)?;
    register_in_txn(store, w, &work.carried_ids(), &CarriedBy::StagedImport(*id))
}

/// Rewrites what the confirmed receipt `id` still owes as `owed`, in one
/// write. The last owed body settled drops the work with the content and
/// stamps it kept. A work row gone meanwhile (cancelled, or dropped by an
/// erase) stays gone.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn settle_staged_import_body_work(
    vault: &Vault,
    id: &[u8; 32],
    owed: Vec<OwedBody>,
) -> Result<()> {
    vault.with_write_txn_grouped(|w| {
        let Some(raw) = BODY_WORK.get(&vault.store, w, &Hex64(*id))? else {
            return Ok(());
        };
        let Ok(mut work) = StagedImportBodyWork::decode(&raw) else {
            return drop_staged_import_body_work_in_txn(&vault.store, w, id);
        };
        if owed.is_empty() {
            return drop_staged_import_body_work_in_txn(&vault.store, w, id);
        }
        work.owed = owed;
        work.owed.sort();
        work.owed.dedup();
        BODY_WORK.put(&vault.store, w, &Hex64(*id), &work.encode()?)?;
        Ok(())
    })
}

/// Cancels the delivery the confirmed receipt `id` still owes: its work, its
/// kept content and its stamps go. Returns whether any was owed.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn cancel_staged_import_body_work(vault: &Vault, id: &[u8; 32]) -> Result<bool> {
    vault.with_write_txn_grouped(|w| {
        if !BODY_WORK.contains(&vault.store, w, &Hex64(*id))? {
            return Ok(false);
        }
        drop_staged_import_body_work_in_txn(&vault.store, w, id)?;
        Ok(true)
    })
}

/// Drops the receipt `id`'s body work with the content and stamps it kept,
/// and forgets the receipt as a retained copy of the rows it carried; a
/// receipt with no work keeps whatever it holds. The retained-copy eraser
/// calls it for a receipt whose kept content carries an erased row.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn drop_staged_import_body_work_in_txn(
    store: &Store,
    w: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
) -> Result<()> {
    let key = Hex64(*id);
    let Some(raw) = BODY_WORK.get(store, w, &key)? else {
        return Ok(());
    };
    if let Ok(work) = StagedImportBodyWork::decode(&raw) {
        forget_in_txn(store, w, &work.carried_ids(), &CarriedBy::StagedImport(*id))?;
    }
    BODY_WORK.delete(store, w, &key)?;
    CONTENT.delete(store, w, &key)?;
    STAMPS.delete(store, w, &key)?;
    Ok(())
}
