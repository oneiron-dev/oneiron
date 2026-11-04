//! What the last advance of a machine history carried (FIX 4296).
//!
//! The own-receive advance runs on every landed control or target row, and
//! it read the target's whole index, chain and events again each time, so a
//! history that syncs n rows cost O(n^2) reads. The advance now carries what
//! it read: every control row the target's index named at the index's seal
//! (`history_seal`). The next advance reads the seal first. At the same seal
//! it reads none of those rows again; one put further, by the landed
//! control, it reads that row alone; at any other seal it reads the index
//! whole once more. A control's row is immutable under its content-addressed
//! id, and the seal moves with every put, delete and retire in the writer
//! that makes it, so a carried row answers as the store does in the same
//! transaction and every outcome stays today's. Handoff signature checks are
//! carried too, by packet content hash.
//!
//! The carry lives in this vault's memory only, bounded by
//! [`ADVANCE_CARRY_TARGETS`] targets and [`ADVANCE_CARRY_BYTES`] bytes. A
//! history past the bytes bound is read whole each time, as before.
//!
//! CALLS (L02, open): "FIX 4296 carry bounds".

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::EntityId;
use crate::authority::AuthorityFold;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::transition::ClaimTransitionProjection;
use crate::error::Result;
use crate::store::Store;

use super::ClaimHistoryHandoff;
use super::history_projection::{
    ControlRows, MachineHistoryRows, StoreRows, machine_history_rows_from,
    resolved_machine_history_from, verify_handoff_signature,
};
use super::history_seal::{IndexSeal, control_body_digest, read_index_seal};
use super::history_store::machine_history_ids_for_target;

/// The most targets whose reads this vault carries at once. CALLS: "FIX
/// 4296 carry bounds".
pub(crate) const ADVANCE_CARRY_TARGETS: usize = 64;
/// The most row bytes this vault carries at once. CALLS: "FIX 4296 carry
/// bounds".
pub(crate) const ADVANCE_CARRY_BYTES: usize = 64 * 1024 * 1024;
/// What one carried row costs beside its bytes: its id.
const ROW_OVERHEAD: usize = 16;

/// One target's controls as its index named them at `seal`.
pub(crate) struct CarriedHistory {
    target: EntityId,
    seal: IndexSeal,
    /// Every control id the index named, with its stored row (`None` where
    /// the index names a row that is not stored).
    rows: BTreeMap<EntityId, Option<Vec<u8>>>,
    bytes: usize,
    /// Handoff signature checks, by packet content hash.
    signed: Mutex<BTreeMap<[u8; 32], bool>>,
}

impl CarriedHistory {
    fn read_whole(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
        seal: IndexSeal,
    ) -> Result<Self> {
        let mut carried = Self {
            target,
            seal,
            rows: BTreeMap::new(),
            bytes: 0,
            signed: Mutex::new(BTreeMap::new()),
        };
        for id in machine_history_ids_for_target(store, txn, target)? {
            let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?;
            carried.put_row(id, raw);
        }
        Ok(carried)
    }

    fn put_row(&mut self, id: EntityId, raw: Option<Vec<u8>>) {
        self.bytes += raw.as_ref().map_or(0, Vec::len) + ROW_OVERHEAD;
        if let Some(old) = self.rows.insert(id, raw) {
            self.bytes -= old.as_ref().map_or(0, Vec::len) + ROW_OVERHEAD;
        }
    }
}

impl ControlRows for CarriedHistory {
    fn index_ids(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        target: EntityId,
    ) -> Result<Vec<EntityId>> {
        if target != self.target {
            return machine_history_ids_for_target(store, txn, target);
        }
        Ok(self.rows.keys().copied().collect())
    }

    fn row<'a>(
        &'a self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Cow<'a, [u8]>>> {
        match self.rows.get(id) {
            Some(row) => Ok(row.as_deref().map(Cow::Borrowed)),
            // A row the index does not name is read from the store, as ever.
            None => {
                Ok(crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?.map(Cow::Owned))
            }
        }
    }

    fn handoff_signed(&self, packet: &ClaimHistoryHandoff) -> bool {
        let Ok(hash) = packet.content_hash() else {
            return verify_handoff_signature(packet);
        };
        let mut signed = self.signed.lock().unwrap_or_else(PoisonError::into_inner);
        *signed
            .entry(hash)
            .or_insert_with(|| verify_handoff_signature(packet))
    }
}

/// The reads this vault carries, by target, each with the tick it was last
/// kept at.
#[derive(Default)]
pub(crate) struct AdvanceCarry {
    carried: BTreeMap<EntityId, (u64, Arc<CarriedHistory>)>,
    tick: u64,
    bytes: usize,
}

impl std::fmt::Debug for AdvanceCarry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdvanceCarry")
            .field("targets", &self.carried.len())
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl AdvanceCarry {
    fn take(&mut self, target: EntityId) -> Option<Arc<CarriedHistory>> {
        let (_, carried) = self.carried.remove(&target)?;
        self.bytes -= carried.bytes;
        Some(carried)
    }

    fn get(&self, target: EntityId, seal: IndexSeal) -> Option<Arc<CarriedHistory>> {
        self.carried
            .get(&target)
            .filter(|(_, carried)| carried.seal == seal)
            .map(|(_, carried)| Arc::clone(carried))
    }

    /// Keeps `carried`, dropping the least recently kept reads past the
    /// bounds. A read past the bytes bound alone is not kept.
    fn keep(&mut self, carried: Arc<CarriedHistory>) {
        if carried.bytes > ADVANCE_CARRY_BYTES {
            return;
        }
        self.tick = self.tick.saturating_add(1);
        self.bytes += carried.bytes;
        if let Some((_, old)) = self.carried.insert(carried.target, (self.tick, carried)) {
            self.bytes -= old.bytes;
        }
        while self.carried.len() > ADVANCE_CARRY_TARGETS || self.bytes > ADVANCE_CARRY_BYTES {
            let Some(oldest) = self
                .carried
                .iter()
                .min_by_key(|(_, (tick, _))| *tick)
                .map(|(target, _)| *target)
            else {
                break;
            };
            if let Some((_, evicted)) = self.carried.remove(&oldest) {
                self.bytes -= evicted.bytes;
            }
        }
    }
}

fn carry(store: &Store) -> MutexGuard<'_, AdvanceCarry> {
    store
        .machine_history_runtime
        .advance
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// The digest `raw`'s put chained into its target's seal, when `raw` is a
/// CLAIM row whose body decodes.
fn landed_body_digest(raw: &[u8]) -> Option<[u8; 32]> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return None;
    }
    let body = super::decode_claim_body(raw.get(ENTITY_METADATA_HEADER_LEN..)?, true).ok()?;
    control_body_digest(&body).ok()
}

/// `target`'s controls in `txn` for its advance, through what the last
/// advance carried: at the same seal no row is read again; one put further,
/// by `landed`, only `landed`'s row is; at any other seal the index is read
/// whole. The read is kept at once, for the readers of the same history in
/// this writer ([`carried_now`]) and for the next advance.
pub(crate) fn carried_history(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
    landed: Option<EntityId>,
) -> Result<Arc<CarriedHistory>> {
    let seal = read_index_seal(store, txn, target)?;
    let carried = match carry(store).take(target) {
        Some(carried) if carried.seal == seal => Some(carried),
        Some(mut carried) => match landed {
            Some(id) => {
                let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?;
                if raw
                    .as_deref()
                    .and_then(landed_body_digest)
                    .is_some_and(|digest| carried.seal.after(id, &digest) == seal)
                    && let Some(extended) = Arc::get_mut(&mut carried)
                {
                    extended.put_row(id, raw);
                    extended.seal = seal;
                    Some(carried)
                } else {
                    None
                }
            }
            None => None,
        },
        None => None,
    };
    let carried = match carried {
        Some(carried) => carried,
        None => Arc::new(CarriedHistory::read_whole(store, txn, target, seal)?),
    };
    carry(store).keep(Arc::clone(&carried));
    Ok(carried)
}

/// What the last advance of `target` carried, when it is still at `txn`'s
/// seal: a reader of the same history in the same writer reads through it.
pub(crate) fn carried_now(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Option<Arc<CarriedHistory>>> {
    let seal = read_index_seal(store, txn, target)?;
    Ok(carry(store).get(target, seal))
}

/// [`resolved_machine_history_from`] through what the last advance of
/// `target` carried while it stands at `txn`'s seal, else through the store.
pub(crate) fn resolved_machine_history_carried(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
) -> Result<ClaimTransitionProjection> {
    match carried_now(store, txn, target)? {
        Some(carried) => resolved_machine_history_from(&*carried, store, txn, fold, target),
        None => resolved_machine_history_from(&StoreRows, store, txn, fold, target),
    }
}

/// [`machine_history_rows_from`] through what the last advance of `target`
/// carried while it stands at `txn`'s seal, else through the store.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn machine_history_rows_carried(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<MachineHistoryRows> {
    match carried_now(store, txn, target)? {
        Some(carried) => machine_history_rows_from(&*carried, store, txn, target),
        None => machine_history_rows_from(&StoreRows, store, txn, target),
    }
}
