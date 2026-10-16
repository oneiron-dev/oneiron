//! Where a fold's words go when a record they came from is withdrawn (Docs
//! Q23, Q24).
//!
//! A fold's accepted summary is host-stamped `Generated` and kept in its
//! run's node-local ledger with every record whose words could reach its
//! span. In base, the fold also stands as one dependent of each of those
//! records in the dependency index, under an id of its own that names no
//! row: erasing one of them walks to that dependent, and
//! [`scrub_withdrawn_fold_summary_in_txn`] takes the summary from the ledger
//! in the erasing transaction. A room's ledger lives in its overlay, which
//! base erasure cannot reach, and drops at close; until then, and for a
//! source withdrawn only through its own source, every read withholds the
//! words once any source is withdrawn ([`fence_withdrawn_folds_in`]). The
//! fold keeps its span and its references either way.

use super::{FoldLedger, FoldRecord};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::{ManifestDbs, Store};

/// One ledger per run, keyed by run id.
pub(crate) const FOLD_LEDGERS: SideTable<EntityId, FoldLedger, Raw> =
    SideTable::new(&side_table::CODE_RUN_FOLDS);

impl RawValue for FoldLedger {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex("code-run fold ledger").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("code-run fold ledger").into())
    }
}

/// The run and fold one fold-words dependent stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FoldOwner {
    run: EntityId,
    fold: u64,
}

const OWNERS: SideTable<EntityId, FoldOwner, Raw> =
    SideTable::new(&side_table::CODE_RUN_FOLD_WORDS);

impl RawValue for FoldOwner {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut raw = Vec::with_capacity(24);
        raw.extend_from_slice(self.run.as_bytes());
        raw.extend_from_slice(&self.fold.to_be_bytes());
        Ok(raw)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let corrupt = || Error::CorruptedIndex("code-run fold words owner");
        let (run, fold) = bytes
            .split_first_chunk::<16>()
            .filter(|(_, fold)| fold.len() == 8)
            .ok_or_else(corrupt)?;
        Ok(Self {
            run: EntityId::from_bytes(*run).map_err(|_| corrupt())?,
            fold: u64::from_be_bytes(fold.try_into().map_err(|_| corrupt())?),
        })
    }
}

/// The id run `run`'s fold `fold` depends on its sources under: stable per
/// (run, fold), and no row's.
fn fold_words_id(run: EntityId, fold: u64) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:code-run-fold-words:v1");
    hasher.update(run.as_bytes());
    hasher.update(&fold.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    loop {
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
        bytes[0] ^= 0x42;
    }
}

/// Whether `id` is gone or its words are withdrawn here: erased, stale, or
/// pending a source walk.
fn source_withdrawn(dbs: &impl ManifestDbs, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(dbs.port_entity_record(txn, id)?.is_none() || crate::ports::withdrawn_in_txn(dbs, txn, id)?)
}

/// Whether fold `record` of run `run` may not keep its words: a record they
/// came from is withdrawn, or the walk from one already reached the fold.
fn words_withdrawn(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    record: &FoldRecord,
) -> Result<bool> {
    if crate::ports::withdrawn_in_txn(dbs, txn, &fold_words_id(run, record.fold))? {
        return Ok(true);
    }
    for source in &record.sources {
        if source_withdrawn(dbs, txn, source)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Takes the summary from every fold of run `run`'s `ledger` whose words
/// are withdrawn, as read through `dbs`. Returns whether one was taken.
pub(crate) fn fence_withdrawn_folds_in(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    ledger: &mut FoldLedger,
) -> Result<bool> {
    let mut taken = false;
    for record in &mut ledger.folds {
        if record.summary.is_some() && words_withdrawn(dbs, txn, run, record)? {
            record.summary = None;
            taken = true;
        }
    }
    Ok(taken)
}

/// Lands `landed` on run `run`'s base `ledger` in this transaction. A fold
/// whose sources are no longer all here and live lands without its words,
/// as if the erasure had come after it. Each one that keeps them becomes a
/// dependent of every source, so erasing any of them reaches it.
pub(crate) fn land_folds_in_base(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    run: EntityId,
    ledger: &mut FoldLedger,
    landed: Vec<FoldRecord>,
    failed: &[(u64, String)],
) -> Result<()> {
    let mut records = Vec::with_capacity(landed.len());
    for mut record in landed {
        if ledger.fold(record.fold).is_some() {
            continue;
        }
        let mut withdrawn = false;
        for source in &record.sources {
            withdrawn |= source_withdrawn(store, txn, source)?;
        }
        if withdrawn {
            record.summary = None;
        } else if record.summary.is_some() {
            let dependent = fold_words_id(run, record.fold);
            for source in &record.sources {
                crate::ports::record_derived_edge_in_txn(store, txn, &dependent, source)?;
            }
            OWNERS.put(
                store,
                txn,
                &dependent,
                &FoldOwner {
                    run,
                    fold: record.fold,
                },
            )?;
        }
        records.push(record);
    }
    ledger.land(records, failed);
    Ok(())
}

/// [`land_folds_in_base`] for a ledger in a room's overlay: a fold whose
/// sources are not all live through `dbs` lands without its words. It takes
/// no dependency rows; its reads withhold its words instead.
pub(crate) fn land_folds_in_overlay(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    ledger: &mut FoldLedger,
    landed: Vec<FoldRecord>,
    failed: &[(u64, String)],
) -> Result<()> {
    let mut records = Vec::with_capacity(landed.len());
    for mut record in landed {
        if ledger.fold(record.fold).is_some() {
            continue;
        }
        for source in &record.sources {
            if source_withdrawn(dbs, txn, source)? {
                record.summary = None;
                break;
            }
        }
        records.push(record);
    }
    ledger.land(records, failed);
    Ok(())
}

/// Takes withdrawn fold-words dependent `id`'s summary from its run's base
/// ledger. The dependency walk calls this for every withdrawn dependent;
/// any other id, or a fold already without words, is left as it is.
pub(crate) fn scrub_withdrawn_fold_summary_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(owner) = OWNERS.get(store, txn, id)? else {
        return Ok(());
    };
    let Some(mut ledger) = FOLD_LEDGERS.get(store, txn, &owner.run)? else {
        return Ok(());
    };
    let Some(record) = ledger
        .folds
        .iter_mut()
        .find(|record| record.fold == owner.fold)
    else {
        return Ok(());
    };
    if record.summary.take().is_none() {
        return Ok(());
    }
    FOLD_LEDGERS.put(store, txn, &owner.run, &ledger)
}
