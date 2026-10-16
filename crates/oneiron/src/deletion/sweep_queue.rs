use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

use super::receipt::RedactionScope;

pub(crate) const HARD_ERASE_SWEEP_PREFIX: &[u8] = b"h:";
pub(crate) const LAST_HARD_ERASE_SWEEP_SEQ_KEY: &[u8] = b"m:last_hard_erase_sweep_seq";
pub(crate) const HARD_ERASE_SWEEP_SLA_SECS: u64 = 30 * 86_400;
/// Withdrawn-generation rows, `hw:{id16}{generation:8BE}`. Not `h:` rows: a
/// withdrawn generation is no erased id, and the `h:` executor must not
/// finalize one its compaction never rewrote.
pub(crate) const WITHDRAWN_GENERATION_SWEEP_PREFIX: &[u8] = b"hw:";

/// The ARCH-0038 carrier enumeration every queued hard-erase sweep row is
/// scoped to.
///
/// The redirect table joins the historical carriers on the ARCH-0055 §9 (r6)
/// ruling — "ARCH-0038's carrier enumeration gains the redirect table" —
/// because a shell row is erasable content, not just an index: it names the
/// head an erasure removed, and a shell left readable leaks exactly what the
/// erasure hid. The class handle is owned by the family that owns the
/// keyspace, so it is read from there rather than restated here.
const ARCH0038_CARRIER_CLASSES: &[&str] = &[
    "historical_loro_updates",
    "historical_loro_snapshots",
    "derived_carriers",
    crate::identity_redirect::REDIRECT_CARRIER_CLASS,
];

/// The ARCH-0038 carrier classes a hard erasure must account for — the
/// enumeration every queued `h:` sweep row carries as its audit scope.
///
/// A static read of the contract, not of any one vault: the enumeration is
/// what the deletion machinery is obliged to cover, and holds before the
/// first delete as much as after it.
#[must_use]
pub fn arch0038_carrier_classes() -> Vec<String> {
    ARCH0038_CARRIER_CLASSES
        .iter()
        .map(|class| (*class).to_owned())
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HardEraseSweepJob {
    pub(crate) scope: HardEraseSweepScope,
    pub(crate) retry_state: HardEraseRetryState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HardEraseSweepScope {
    pub(crate) entity_ids: Vec<String>,
    pub(crate) revision_ids: Vec<String>,
    /// ARCH-0038 delete-interplay seam: "body_snapshot_ref lets the queued
    /// historical-carrier sweep locate residual snapshot/update bytes"
    /// (contracts.ts retractionRules DELETE). Opaque lowercase-hex ids only;
    /// the consuming executor is ONE-1087/ONE-1091 phase 1 (whose window
    /// compaction is global, so the refs ride the job as audit context).
    pub(crate) body_snapshot_refs: Vec<String>,
    pub(crate) carrier_classes: Vec<String>,
}

/// Delete-interplay refs captured from an `edge.provenance` Claim BEFORE its
/// body is purged/SoftErased, riding the QUEUED sweep row's scope (ARCH-0038).
/// Opaque lowercase-hex identifiers only — never content, names, or predicate
/// strings. Empty for non-provenance deletes.
#[derive(Debug, Clone, Default)]
pub(crate) struct HardEraseSweepExtras {
    /// Captured `source_revision_ref`s — opaque revision UUIDs joining the
    /// scope's pinned `revision_ids` slot ("entity UUIDs / revision UUIDs").
    pub revision_ids: Vec<String>,
    /// Captured `body_snapshot_ref`s — pointers to the exact body bytes the
    /// actor saw, the sweep's residual-carrier locator.
    pub body_snapshot_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HardEraseRetryState {
    pub(crate) attempt_count: u32,
    pub(crate) next_attempt_at: u64,
    pub(crate) last_error_code: Option<String>,
    pub(crate) queued_at: u64,
    pub(crate) deadline_at: u64,
}

impl HardEraseRetryState {
    /// A job queued at `queued_at`: due now, under the 30-day SLA.
    fn fresh(queued_at: u64) -> Self {
        Self {
            attempt_count: 0,
            next_attempt_at: queued_at,
            last_error_code: None,
            queued_at,
            deadline_at: queued_at.saturating_add(HARD_ERASE_SWEEP_SLA_SECS),
        }
    }
}

/// What the historical sweep owes one withdrawn generation of a derived
/// artifact: its carriers of `generation` or older are rewritten to
/// `replacement`, and a newer generation stays. Ids and a generation only,
/// never words. Unlike [`HardEraseSweepScope::entity_ids`], this names no
/// erased id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WithdrawnGenerationScope {
    /// Lowercase hex of the artifact's id.
    pub(crate) artifact_id: String,
    /// The withdrawn body's `learned_at`, the generation its stale mark fences.
    pub(crate) generation: u64,
    pub(crate) replacement: WithdrawnReplacement,
}

/// What stands in history for a withdrawn generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WithdrawnReplacement {
    /// An epoch summary's content-free keyframe, as its row now keeps it.
    EpochKeyframe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WithdrawnGenerationSweepJob {
    pub(crate) scope: WithdrawnGenerationScope,
    pub(crate) retry_state: HardEraseRetryState,
}

pub(crate) fn encode_hard_erase_sweep_job(
    scope: RedactionScope,
    extras: HardEraseSweepExtras,
    queued_at: u64,
) -> Result<Vec<u8>> {
    let mut revision_ids = scope.revision_ids;
    revision_ids.extend(extras.revision_ids);
    let job = HardEraseSweepJob {
        scope: HardEraseSweepScope {
            entity_ids: scope.entity_ids,
            revision_ids,
            body_snapshot_refs: extras.body_snapshot_refs,
            carrier_classes: arch0038_carrier_classes(),
        },
        retry_state: HardEraseRetryState::fresh(queued_at),
    };
    rmp_serde::to_vec_named(&job)
        .map_err(|_| Error::InvariantViolation("hard erase sweep job encode"))
}

fn encode_withdrawn_generation_key(artifact: &EntityId, generation: u64) -> Vec<u8> {
    [
        WITHDRAWN_GENERATION_SWEEP_PREFIX,
        artifact.as_bytes(),
        &generation.to_be_bytes(),
    ]
    .concat()
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
        retry_state: HardEraseRetryState::fresh(queued_at),
    };
    let value = rmp_serde::to_vec_named(&job)
        .map_err(|_| Error::InvariantViolation("withdrawn generation sweep job encode"))?;
    store.sync_queue.put(wtxn, &key, &value)?;
    Ok(())
}

/// Decodes a persisted `h:{seq:8BE}` job value. An undecodable job row is a
/// deletion obligation the executor can neither execute nor safely discard —
/// callers must KEEP the row and report loudly, never delete it.
pub(crate) fn decode_hard_erase_sweep_job(value: &[u8]) -> Result<HardEraseSweepJob> {
    rmp_serde::from_slice(value).map_err(|_| Error::CorruptedIndex("hard erase sweep job"))
}

/// Re-encodes a job after an in-place `retry_state` update (ONE-1087: the
/// row is REWRITTEN on failure, never deleted). Same encoder as the
/// original write (`rmp_serde::to_vec_named`), so the wire shape is stable.
pub(crate) fn encode_hard_erase_sweep_job_value(job: &HardEraseSweepJob) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(job)
        .map_err(|_| Error::InvariantViolation("hard erase sweep job encode"))
}

pub(crate) fn encode_hard_erase_sweep_key(seq: u64) -> [u8; 10] {
    let mut key = [0_u8; 10];
    key[..2].copy_from_slice(HARD_ERASE_SWEEP_PREFIX);
    key[2..].copy_from_slice(&seq.to_be_bytes());
    key
}

pub(crate) fn decode_hard_erase_sweep_seq(key: &[u8]) -> Option<u64> {
    let seq = key.strip_prefix(HARD_ERASE_SWEEP_PREFIX)?;
    Some(u64::from_be_bytes(seq.try_into().ok()?))
}

/// The artifact and generation a `hw:{id16}{generation:8BE}` key names;
/// `None` for any other shape.
pub(crate) fn decode_withdrawn_generation_key(key: &[u8]) -> Option<(EntityId, u64)> {
    let rest = key.strip_prefix(WITHDRAWN_GENERATION_SWEEP_PREFIX)?;
    if rest.len() != 24 {
        return None;
    }
    let id = EntityId::from_bytes(rest[..16].try_into().ok()?).ok()?;
    Some((id, u64::from_be_bytes(rest[16..].try_into().ok()?)))
}

/// Strictly decodes one persisted `hw:` row: its key, then a value whose
/// scope names the same artifact and generation. A row that fails is an
/// obligation the sweep can neither execute nor discard; callers keep it and
/// report it, as they do an undecodable `h:` row.
pub(crate) fn decode_withdrawn_generation_row(
    key: &[u8],
    value: &[u8],
) -> Result<(EntityId, WithdrawnGenerationSweepJob)> {
    let (id, generation) = decode_withdrawn_generation_key(key)
        .ok_or(Error::CorruptedIndex("withdrawn generation sweep key"))?;
    let job: WithdrawnGenerationSweepJob = rmp_serde::from_slice(value)
        .map_err(|_| Error::CorruptedIndex("withdrawn generation sweep job"))?;
    if job.scope.artifact_id != id.to_hex() || job.scope.generation != generation {
        return Err(Error::CorruptedIndex("withdrawn generation sweep job"));
    }
    Ok((id, job))
}

/// Re-encodes a `hw:` job after an in-place `retry_state` update, with the
/// encoder of its first write.
pub(crate) fn encode_withdrawn_generation_job_value(
    job: &WithdrawnGenerationSweepJob,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(job)
        .map_err(|_| Error::InvariantViolation("withdrawn generation sweep job encode"))
}

/// The newest withdrawn generation of each artifact whose sweep finished
/// (`wg:{hex32}`, u64 BE). It outlives the `hw:` row, so a late re-put of a
/// withdrawn body is refused after the obligation is gone.
const WITHDRAWN_GENERATION_FENCE: SideTable<HexId, u64, Raw> =
    SideTable::new(&side_table::DELETION_WITHDRAWN_GENERATION_FENCE);

/// Raises `artifact`'s withdrawn-generation fence to `generation`, in the
/// transaction that deletes its `hw:` row. A fence already as high stays.
pub(crate) fn raise_withdrawn_generation_fence_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    artifact: &EntityId,
    generation: u64,
) -> Result<()> {
    let key = HexId(*artifact);
    if WITHDRAWN_GENERATION_FENCE
        .get(store, wtxn, &key)?
        .is_some_and(|held| held >= generation)
    {
        return Ok(());
    }
    WITHDRAWN_GENERATION_FENCE.put(store, wtxn, &key, &generation)
}

/// The newest withdrawn generation of `artifact`, from its pending `hw:`
/// rows and its fence; `None` when it has neither. A row under the
/// artifact's prefix whose key does not decode fences every generation, so
/// a reader fails closed.
#[cfg(feature = "sync")]
pub(crate) fn withdrawn_generation_cutoff_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Option<u64>> {
    let mut cutoff = WITHDRAWN_GENERATION_FENCE.get(store, txn, &HexId(*artifact))?;
    let prefix = [WITHDRAWN_GENERATION_SWEEP_PREFIX, artifact.as_bytes()].concat();
    for row in store.sync_queue.prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        let generation = decode_withdrawn_generation_key(&key).map_or(u64::MAX, |(_, at)| at);
        cutoff = Some(cutoff.map_or(generation, |held| held.max(generation)));
    }
    Ok(cutoff)
}

/// Every artifact's newest withdrawn generation, from the pending `hw:` rows
/// and the fences. A `hw:` key that does not decode names no artifact; the
/// sweep inventory reports it.
pub(crate) fn withdrawn_generation_cutoffs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, u64>> {
    let mut cutoffs = BTreeMap::new();
    let mut raise = |id: EntityId, generation: u64| {
        let held = cutoffs.entry(id).or_insert(generation);
        *held = (*held).max(generation);
    };
    for row in WITHDRAWN_GENERATION_FENCE.iter_from(store, txn, &[])? {
        let (HexId(id), generation) = row?;
        raise(id, generation);
    }
    for row in store
        .sync_queue
        .prefix_iter(txn, WITHDRAWN_GENERATION_SWEEP_PREFIX)?
    {
        let (key, _) = row?;
        if let Some((id, generation)) = decode_withdrawn_generation_key(&key) {
            raise(id, generation);
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
    ) -> Result<Vec<u8>> {
        let seq = self.allocate_next_hard_erase_sweep_seq(wtxn)?;
        let key = encode_hard_erase_sweep_key(seq);
        let value = encode_hard_erase_sweep_job(scope, extras, queued_at)?;
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
