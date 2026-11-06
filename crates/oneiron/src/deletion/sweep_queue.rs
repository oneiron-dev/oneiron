//! Core half of `deletion::sweep_queue`: its store-layer items live in `oneiron_store::deletion::sweep_queue` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::deletion::sweep_queue::*;

use super::receipt::{CaptureFailure, RedactionScope};
use crate::error::{Error, Result};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) fn encode_hard_erase_sweep_job(
    scope: RedactionScope,
    extras: HardEraseSweepExtras,
    queued_at: u64,
    requested_at: u64,
) -> Result<Vec<u8>> {
    let mut revision_ids = scope.revision_ids;
    revision_ids.extend(extras.revision_ids);
    let job = HardEraseSweepJob {
        scope: HardEraseSweepScope {
            entity_ids: scope.entity_ids,
            revision_ids,
            body_snapshot_refs: extras.body_snapshot_refs,
            carrier_classes: arch0038_carrier_classes(),
            capture_failures: extras.capture_failures,
        },
        retry_state: HardEraseRetryState::fresh(queued_at, requested_at),
    };
    rmp_serde::to_vec_named(&job)
        .map_err(|_| Error::InvariantViolation("hard erase sweep job encode"))
}

/// Stages the historical sweep's obligation for withdrawn `generation` of
/// `artifact`, in the withdrawing transaction and on the store alone. A
/// repeat for the same generation keeps the row already queued.
pub(crate) fn enqueue_withdrawn_generation_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    artifact: &EntityId,
    generation: u64,
    replacement: WithdrawnReplacement,
    queued_at: u64,
) -> Result<()> {
    let key = encode_withdrawn_generation_key(artifact, generation);
    if store.sync_queue.get(&*wtxn, &key)?.is_some() {
        return Ok(());
    }
    let job = WithdrawnGenerationSweepJob {
        scope: WithdrawnGenerationScope {
            artifact_id: artifact.to_hex(),
            generation,
            replacement,
        },
        retry_state: HardEraseRetryState::fresh(queued_at, queued_at),
    };
    let value = rmp_serde::to_vec_named(&job)
        .map_err(|_| Error::InvariantViolation("withdrawn generation sweep job encode"))?;
    store.sync_queue.put(wtxn, &key, &value)?;
    Ok(())
}

/// The newest withdrawn generation of each artifact whose sweep finished and
/// what stands in for it (`wg:{hex32}`, an encoded [`WithdrawnCutoff`]). It
/// outlives the `hw:` row, so a late re-put of a withdrawn body is refused
/// after the obligation is gone.
const WITHDRAWN_GENERATION_FENCE: SideTable<HexId, [u8; WITHDRAWN_CUTOFF_LEN], Raw> =
    SideTable::new(&side_table::DELETION_WITHDRAWN_GENERATION_FENCE);

/// Raises `artifact`'s withdrawn-generation fence to `cutoff`, in the
/// transaction that deletes its `hw:` row. A fence already as high stays.
pub(crate) fn raise_withdrawn_generation_fence_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    artifact: &EntityId,
    cutoff: WithdrawnCutoff,
) -> Result<()> {
    let key = HexId(*artifact);
    if let Some(held) = WITHDRAWN_GENERATION_FENCE.get(store, wtxn, &key)?
        && fence_cutoff(&held)?.generation >= cutoff.generation
    {
        return Ok(());
    }
    WITHDRAWN_GENERATION_FENCE.put(store, wtxn, &key, &cutoff.encode())
}

/// The newest withdrawn generation of `artifact` and its replacement, from
/// its pending `hw:` rows and its fence; `None` when it has neither.
#[cfg(feature = "sync")]
pub(crate) fn withdrawn_generation_cutoff_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Option<WithdrawnCutoff>> {
    let mut cutoff = match WITHDRAWN_GENERATION_FENCE.get(store, txn, &HexId(*artifact))? {
        Some(bytes) => Some(fence_cutoff(&bytes)?),
        None => None,
    };
    let prefix = [WITHDRAWN_GENERATION_SWEEP_PREFIX, artifact.as_bytes()].concat();
    for row in store.sync_queue.prefix_iter(txn, &prefix)? {
        let (key, value) = row?;
        let pending = pending_cutoff(&key, &value);
        cutoff.get_or_insert(pending).raise(pending);
    }
    Ok(cutoff)
}

/// Every artifact's newest withdrawn generation and its replacement, from
/// the pending `hw:` rows and the fences. A `hw:` key that does not decode
/// names no artifact; the sweep inventory reports it.
pub(crate) fn withdrawn_generation_cutoffs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, WithdrawnCutoff>> {
    let mut cutoffs = BTreeMap::new();
    for row in WITHDRAWN_GENERATION_FENCE.iter_from(store, txn, &[])? {
        let (HexId(id), bytes) = row?;
        raise_cutoff(&mut cutoffs, id, fence_cutoff(&bytes)?);
    }
    for row in store
        .sync_queue
        .prefix_iter(txn, WITHDRAWN_GENERATION_SWEEP_PREFIX)?
    {
        let (key, value) = row?;
        if let Some((id, _)) = decode_withdrawn_generation_key(&key) {
            raise_cutoff(&mut cutoffs, id, pending_cutoff(&key, &value));
        }
    }
    Ok(cutoffs)
}

impl Vault {
    pub(super) fn enqueue_hard_erase_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        scope: RedactionScope,
        extras: HardEraseSweepExtras,
        queued_at: u64,
        requested_at: u64,
    ) -> Result<Vec<u8>> {
        let seq = self.allocate_next_hard_erase_sweep_seq(wtxn)?;
        let key = encode_hard_erase_sweep_key(seq);
        let value = encode_hard_erase_sweep_job(scope, extras, queued_at, requested_at)?;
        self.store.sync_queue.put(wtxn, &key, &value)?;
        Ok(key.to_vec())
    }

    fn allocate_next_hard_erase_sweep_seq(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
        let metadata_seq = match self
            .store
            .sync_queue
            .get(&*wtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY)?
        {
            Some(raw) if raw.len() == 8 => {
                Some(u64::from_le_bytes(raw.as_ref().try_into().map_err(
                    |_| Error::CorruptedIndex("hard erase sweep metadata"),
                )?))
            }
            Some(_) => return Err(Error::CorruptedIndex("hard erase sweep metadata")),
            None => None,
        };
        let current = match metadata_seq {
            Some(seq) => seq,
            None => self.max_hard_erase_sweep_seq(wtxn)?,
        };
        let next = current
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("hard erase sweep sequence"))?;
        if self
            .store
            .sync_queue
            .get(&*wtxn, &encode_hard_erase_sweep_key(next))?
            .is_some()
        {
            let repaired_current = self.max_hard_erase_sweep_seq(wtxn)?;
            let repaired_next = repaired_current
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("hard erase sweep sequence"))?;
            if self
                .store
                .sync_queue
                .get(&*wtxn, &encode_hard_erase_sweep_key(repaired_next))?
                .is_some()
            {
                return Err(Error::CorruptedIndex("hard erase sweep metadata"));
            }
            self.store.sync_queue.put(
                wtxn,
                LAST_HARD_ERASE_SWEEP_SEQ_KEY,
                &repaired_next.to_le_bytes(),
            )?;
            return Ok(repaired_next);
        }
        self.store
            .sync_queue
            .put(wtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY, &next.to_le_bytes())?;
        Ok(next)
    }

    fn max_hard_erase_sweep_seq(&self, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
        let mut max_seq = 0_u64;
        for row in self
            .store
            .sync_queue
            .prefix_iter(wtxn, HARD_ERASE_SWEEP_PREFIX)?
        {
            let (key, _) = row?;
            if let Some(seq) = decode_hard_erase_sweep_seq(&key) {
                max_seq = max_seq.max(seq);
            }
        }
        Ok(max_seq)
    }
}
