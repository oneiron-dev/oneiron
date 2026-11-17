//! Each external reader's lifetime read exposure (L8-65; Engine rulings 15 Nov 01:10, ADOPT,
//! UNIT, WHO and RESET all A): the distinct records the engine has ever served a key built
//! from a credential its caller presented, the vault owner's own excepted.
//!
//! A door names the records it hands its caller ([`ScopedRead::charge_served`]). No read opens
//! a writer, as no scan does ([`crate::scan_check`]): the records wait with the vault, in
//! memory, until its next write, whose door first keeps them in a write of their own, alone in
//! its group. A reader's exposure read folds in what still waits.
//!
//! Past the engine row `limits.actor_exposed_records` the installed limit port is asked
//! (OF-520). Every read is still served whole. Nothing resets a count: an erased record leaves
//! its rows but not the count, and a rotated key reads as the same reader.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use super::ScopedRead;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::{Callback, Rows, Store, active_write_txn_depth};

/// One reader's lifetime exposure. Key: id16 (the reader).
const EXPOSURE: SideTable<EntityId, ActorReadExposure, Named> =
    SideTable::new(&side_table::READ_EXPOSURE);

/// One record served to one reader, presence only. Key: id16 (the record) + id16 (the reader).
const EXPOSED_RECORD: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::READ_EXPOSURE_RECORD);

/// What the engine has served one external reader over its whole life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorReadExposure {
    /// Distinct records ever served to the reader. It never falls: an erased record still
    /// counts.
    pub distinct_records: u64,
    /// When the reader was served its first record, on the vault's recording clock.
    pub first_served_at: u64,
    /// When the reader was last served a record it had never been served.
    pub last_exposed_at: u64,
}

/// The records each reader was served since the vault's last write, each with when it was
/// first served then. The next write keeps them ([`Vault::keep_waiting_read_exposure`]).
#[derive(Debug, Default)]
pub(crate) struct PendingReadExposure(Mutex<Waiting>);

/// Reader, then record, then when the record was first served.
type Waiting = BTreeMap<EntityId, BTreeMap<EntityId, u64>>;

impl PendingReadExposure {
    fn lock(&self) -> MutexGuard<'_, Waiting> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn park(&self, reader: EntityId, records: impl IntoIterator<Item = EntityId>, at: u64) {
        let mut records = records.into_iter().peekable();
        if records.peek().is_none() {
            return;
        }
        let mut waiting = self.lock();
        let served = waiting.entry(reader).or_default();
        for record in records {
            served.entry(record).or_insert(at);
        }
    }

    fn waiting(&self) -> Waiting {
        self.lock().clone()
    }

    fn waiting_for(&self, reader: &EntityId) -> BTreeMap<EntityId, u64> {
        self.lock().get(reader).cloned().unwrap_or_default()
    }

    /// Drops what a committed write kept. A record served again since the copy stays only if
    /// it was not in the copy, so nothing kept is kept twice and nothing new is lost.
    fn clear(&self, kept: &Waiting) {
        let mut waiting = self.lock();
        for (reader, records) in kept {
            if let Some(served) = waiting.get_mut(reader) {
                for record in records.keys() {
                    served.remove(record);
                }
                if served.is_empty() {
                    waiting.remove(reader);
                }
            }
        }
    }

    fn forget_reader(&self, reader: &EntityId) {
        self.lock().remove(reader);
    }

    fn forget_record(&self, record: &EntityId) {
        let mut waiting = self.lock();
        waiting.retain(|_, served| {
            served.remove(record);
            !served.is_empty()
        });
    }
}

impl ScopedRead<'_> {
    /// Names the records this door hands its caller, for its reader's lifetime exposure
    /// (L8-65). It does nothing unless the read's key counts
    /// ([`super::ScopedReadActorKey::exposure_reader`]), and it opens no transaction: the
    /// records wait for the vault's next write.
    pub(crate) fn charge_served(&self, records: impl IntoIterator<Item = EntityId>) {
        let Some(reader) = self.actor_key.exposure_reader() else {
            return;
        };
        let at = self.vault.now_recorded_at();
        self.vault
            .store
            .pending_read_exposure
            .park(reader, records, at);
    }
}

impl Vault {
    /// The lifetime read exposure of `reader` (L8-65): the distinct records the engine has
    /// served it, those still waiting for the vault's next write included. `None` for a
    /// reader never served one, as every key the owner or the engine holds is.
    ///
    /// # Errors
    ///
    /// Storage errors, or a row that cannot be read.
    pub fn actor_read_exposure(&self, reader: &EntityId) -> Result<Option<ActorReadExposure>> {
        // Waiting first: a record that leaves the map after this copy was kept by a commit the
        // later snapshot sees.
        let waiting = self.store.pending_read_exposure.waiting_for(reader);
        let txn = self.store.env.read_txn()?;
        exposure_with_waiting_in(&self.store, &txn, reader, &waiting)
    }

    /// Every reader's lifetime read exposure (L8-65), in reader order, as
    /// [`Self::actor_read_exposure`] reads one: the owner's view of who crossed
    /// `limits.actor_exposed_records`.
    ///
    /// # Errors
    ///
    /// Storage errors, or a row that cannot be read.
    pub fn actor_read_exposures(&self) -> Result<Vec<(EntityId, ActorReadExposure)>> {
        let mut waiting = self.store.pending_read_exposure.waiting();
        let txn = self.store.env.read_txn()?;
        let mut readers: BTreeSet<EntityId> = EXPOSURE
            .scan_keys(&self.store, &txn, &[])?
            .into_iter()
            .collect();
        readers.extend(waiting.keys().copied());
        let mut exposures = Vec::with_capacity(readers.len());
        for reader in readers {
            let served = waiting.remove(&reader).unwrap_or_default();
            if let Some(exposure) = exposure_with_waiting_in(&self.store, &txn, &reader, &served)? {
                exposures.push((reader, exposure));
            }
        }
        Ok(exposures)
    }

    /// Keeps the records served since the vault's last write, in a write of their own, then
    /// measures each reader whose count grew against `limits.actor_exposed_records`. The write
    /// door calls it before a host write takes the writer, as it keeps scan checks, so the
    /// thread holds no writer yet. A record leaves the waiting map only once the write that
    /// keeps it commits; one that cannot be kept waits for the next write.
    pub(crate) fn keep_waiting_read_exposure(&self) {
        if active_write_txn_depth() > 0 {
            return;
        }
        let waiting = self.store.pending_read_exposure.waiting();
        if waiting.is_empty() {
            return;
        }
        match self.keep_read_exposure(&waiting) {
            Ok(grown) => {
                self.store.pending_read_exposure.clear(&waiting);
                for distinct_records in grown {
                    let _ = self.measure_limit(EngineLimit::ActorExposedRecords, distinct_records);
                }
            }
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "served records were not kept; they wait for the next write"
            ),
        }
    }

    /// Writes each waiting record its reader holds no row for. A record already kept costs a
    /// read, never a write. Returns each grown reader's new count.
    fn keep_read_exposure(&self, waiting: &Waiting) -> Result<Vec<u64>> {
        let fresh: Waiting = {
            let txn = self.store.env.read_txn()?;
            let mut fresh = Waiting::new();
            for (reader, served) in waiting {
                for (record, at) in served {
                    if !EXPOSED_RECORD.contains(&self.store, &txn, &(*record, *reader))? {
                        fresh.entry(*reader).or_default().insert(*record, *at);
                    }
                }
            }
            fresh
        };
        if fresh.is_empty() {
            return Ok(Vec::new());
        }
        // Alone in its group: no host's rows share its commit, so its failure fails no host's
        // write.
        self.store.group_write_as(Callback::Opaque, None, |wtxn| {
            match keep_waiting_in(&self.store, wtxn, &fresh) {
                Ok(grown) => Rows::Commit(grown),
                Err(error) => Rows::Discard(Err(error)),
            }
        })
    }
}

/// Writes each waiting record a reader was never served, and grows that reader's count by
/// them. Returns each grown reader's new count. `waiting` is a copy taken before the writer;
/// an entry no longer waiting once the writer is held is skipped. Another write kept it, or
/// an erasure of its reader or record forgot it inside its own write
/// ([`erase_read_exposure_reader_in_txn`], [`erase_read_exposure_records_in_txn`]), so a
/// stale copy never writes back a row an erasure removed.
fn keep_waiting_in(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    waiting: &Waiting,
) -> Result<Vec<u64>> {
    let still = store.pending_read_exposure.waiting();
    let mut grown = Vec::new();
    for (reader, served) in waiting {
        let Some(still_served) = still.get(reader) else {
            continue;
        };
        let mut fresh = Fresh::default();
        for (record, at) in served {
            let key = (*record, *reader);
            if !still_served.contains_key(record) || EXPOSED_RECORD.contains(store, wtxn, &key)? {
                continue;
            }
            EXPOSED_RECORD.put(store, wtxn, &key, &())?;
            fresh.add(*at);
        }
        if let Some(exposure) = fresh.onto(EXPOSURE.get(store, wtxn, reader)?) {
            EXPOSURE.put(store, wtxn, reader, &exposure)?;
            grown.push(exposure.distinct_records);
        }
    }
    Ok(grown)
}

/// `reader`'s kept exposure in `txn`, grown by each waiting record it holds no row for.
fn exposure_with_waiting_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    reader: &EntityId,
    waiting: &BTreeMap<EntityId, u64>,
) -> Result<Option<ActorReadExposure>> {
    let kept = EXPOSURE.get(store, txn, reader)?;
    let mut fresh = Fresh::default();
    for (record, at) in waiting {
        if !EXPOSED_RECORD.contains(store, txn, &(*record, *reader))? {
            fresh.add(*at);
        }
    }
    Ok(fresh.onto(kept).or(kept))
}

/// Records new to one reader: how many, and the first and last time one was served.
#[derive(Default)]
struct Fresh {
    records: u64,
    served: Option<(u64, u64)>,
}

impl Fresh {
    fn add(&mut self, at: u64) {
        self.records = self.records.saturating_add(1);
        self.served = Some(match self.served {
            Some((first, last)) => (first.min(at), last.max(at)),
            None => (at, at),
        });
    }

    /// `kept` grown by these records; `None` when there are none.
    fn onto(&self, kept: Option<ActorReadExposure>) -> Option<ActorReadExposure> {
        let (first, last) = self.served?;
        Some(match kept {
            Some(kept) => ActorReadExposure {
                distinct_records: kept.distinct_records.saturating_add(self.records),
                first_served_at: kept.first_served_at.min(first),
                last_exposed_at: kept.last_exposed_at.max(last),
            },
            None => ActorReadExposure {
                distinct_records: self.records,
                first_served_at: first,
                last_exposed_at: last,
            },
        })
    }
}

/// An erased reader's exposure count (FIX 3520 actor scrub): it goes with the reader, with
/// whatever still waits for it.
pub(crate) fn erase_read_exposure_reader_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    reader: &EntityId,
) -> Result<()> {
    vault.store.pending_read_exposure.forget_reader(reader);
    EXPOSURE.delete(&vault.store, wtxn, reader)?;
    Ok(())
}

/// An erased reader out of every record row that names it (FIX 3520 actor scrub). An id whose
/// entity is no actor scans nothing.
pub(crate) fn erase_read_exposure_record_reader_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    reader: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, reader)? {
        return Ok(());
    }
    let rows: Vec<(EntityId, EntityId)> = EXPOSED_RECORD
        .scan_keys(&vault.store, wtxn, &[])?
        .into_iter()
        .filter(|(_, served)| served == reader)
        .collect();
    for key in rows {
        EXPOSED_RECORD.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}

/// The records `reader`'s kept rows name, for `test_doors::read_exposure`.
#[cfg(oneiron_test_support)]
pub(crate) fn exposed_records_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    reader: &EntityId,
) -> Result<BTreeSet<EntityId>> {
    Ok(EXPOSED_RECORD
        .scan_keys(store, txn, &[])?
        .into_iter()
        .filter(|(_, served)| served == reader)
        .map(|(record, _)| record)
        .collect())
}

/// An erased record out of every reader's rows (`deletion::derived_rows`); each reader's count
/// stays. The erase's own write door kept what waited before it, so only a record served
/// while the erase runs is dropped from the waiting map uncounted.
pub(crate) fn erase_read_exposure_records_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    record: &EntityId,
) -> Result<()> {
    store.pending_read_exposure.forget_record(record);
    EXPOSED_RECORD.delete_from(store, wtxn, record.as_bytes())?;
    Ok(())
}
