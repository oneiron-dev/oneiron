//! Retrieval-run, outcome, and trace-fork persistence: `Store` and `SessionStoreView` methods, staging bodies, key formats, and codecs.

use std::collections::HashSet;
use std::str;

use heed::{RoTxn, RwTxn};

use crate::batch::secret_scan;
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
#[cfg(test)]
use crate::store::test_hooks;
use crate::store::{ManifestDbs, SessionStoreView, Store, active_write_txn_depth};

use super::types::{
    RETRIEVAL_TELEMETRY_VERSION, RetrievalOutcome, RetrievalOutcomeRecord, RetrievalRunFinalize,
    RetrievalRunId, RetrievalRunRecord, RetrievalTrace, RetrievalTraceForkHash,
};

/// Crate-visible so the off-record close census can count the session's own
/// retrieval-run receipt rows in the overlay `VaultMeta` keyspace immediately
/// before they evaporate (ONE-1728 K8). The key FORMAT is owned here; the
/// census only tests the prefix.
pub(crate) const RETRIEVAL_RUN_KEY_PREFIX: &[u8] = b"retr_run:v0:";

const RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX: &[u8] = b"retr_run_prov:v0:";

const RETRIEVAL_TRACE_FORK_KEY_PREFIX: &[u8] = b"retr_trace_fork:v0:";

const RETRIEVAL_OUTCOME_KEY_PREFIX: &[u8] = b"retr_out:v0:";

const RETRIEVAL_OUTCOME_KEY_MAX_LEN: usize = 128;

pub(in crate::store) const RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT: usize = 1024;

/// The session-side retrieval-telemetry surface (ONE-1728 §7 / K10).
///
/// Each method is the session sibling of the identically-named `Store`
/// method and rides the SAME extracted staging body, so the two targets
/// cannot drift in key format or side-write footprint. The difference is
/// purely which accessor bundle the body reaches: a session run's rows land
/// in the overlay `VaultMeta` keyspace and evaporate at close, so the base
/// telemetry ledger gains zero rows from an OffRecord session.
///
/// These take the caller's `wtxn` rather than opening their own, because a
/// session write must commit in the same transaction its overlay segment is
/// staged into — the segment guard applies staged rows only after the base
/// commit returns.
#[allow(
    dead_code,
    reason = "P4a lands the session telemetry seam whole; `record_retrieval_run_in_txn` has its \
              lib-target caller in ONE-1728's session `search_text`, and the finalize/delete/read \
              siblings get theirs from ONE-1729's session context-pack runs and ONE-1730's promote"
)]
impl SessionStoreView<'_> {
    /// Session sibling of `Store::record_retrieval_run`.
    pub(crate) fn record_retrieval_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &RetrievalRunRecord,
    ) -> Result<()> {
        stage_retrieval_run_with_visibility(self, wtxn, record, true)
    }

    /// Session sibling of `Store::record_context_pack_provisional_retrieval_run`.
    pub(crate) fn record_context_pack_provisional_retrieval_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &RetrievalRunRecord,
    ) -> Result<()> {
        stage_retrieval_run_with_visibility(self, wtxn, record, false)
    }

    /// Session sibling of `Store::finalize_context_pack_retrieval_run`.
    ///
    /// Finalizes the same overlay row the session registration created; the
    /// base finalizer never sees that row and this one never reaches a base
    /// row.
    pub(crate) fn finalize_context_pack_retrieval_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        finalize: RetrievalRunFinalize<'_>,
    ) -> Result<()> {
        stage_context_pack_retrieval_run_finalize(self, wtxn, finalize)
    }

    /// Session sibling of `Store::delete_retrieval_run`, used to discard a
    /// failed session context-pack run's provisional overlay row.
    pub(crate) fn delete_retrieval_run_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        run_id: RetrievalRunId,
    ) -> Result<()> {
        stage_retrieval_run_delete(self, wtxn, run_id)
    }

    /// Composed read of the newest published retrieval-run rows: overlay ∪
    /// base, so an in-room caller sees its own runs and its ancestors'.
    pub(crate) fn retrieval_runs_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        limit: usize,
    ) -> Result<Vec<RetrievalRunRecord>> {
        read_retrieval_runs_in_txn(self, rtxn, limit)
    }
}

impl Store {
    pub(crate) fn record_retrieval_run(&self, record: &RetrievalRunRecord) -> Result<()> {
        self.record_retrieval_run_with_visibility(record, true)
    }

    pub(crate) fn record_context_pack_provisional_retrieval_run(
        &self,
        record: &RetrievalRunRecord,
    ) -> Result<()> {
        self.record_retrieval_run_with_visibility(record, false)
    }

    fn record_retrieval_run_with_visibility(
        &self,
        record: &RetrievalRunRecord,
        published: bool,
    ) -> Result<()> {
        #[cfg(test)]
        if test_hooks::take_fail_next_retrieval_run_write(&self.owner._registered_path.path) {
            return Err(Error::InvariantViolation(
                "forced retrieval telemetry write failure",
            ));
        }
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval telemetry skipped inside active write transaction",
            ));
        }

        let mut wtxn = self.env.write_txn()?;
        stage_retrieval_run_with_visibility(self, &mut wtxn, record, published)?;
        wtxn.commit()?;
        Ok(())
    }

    pub(crate) fn delete_retrieval_run(&self, run_id: RetrievalRunId) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval telemetry delete skipped inside active write transaction",
            ));
        }

        let mut wtxn = self.env.write_txn()?;
        stage_retrieval_run_delete(self, &mut wtxn, run_id)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Publishes the caller's scope count and surfaced ids atomically.
    /// Ordinary callers retain the pipeline count; post-filter callers supply
    /// the count from their filtered pack instead.
    pub(crate) fn finalize_context_pack_retrieval_run(
        &self,
        finalize: RetrievalRunFinalize<'_>,
    ) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "context-pack retrieval telemetry skipped inside active write transaction",
            ));
        }

        let mut wtxn = self.env.write_txn()?;
        stage_context_pack_retrieval_run_finalize(self, &mut wtxn, finalize)?;
        wtxn.commit()?;
        Ok(())
    }

    pub(crate) fn record_retrieval_outcome(&self, outcome: RetrievalOutcome) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval outcome telemetry skipped inside active write transaction",
            ));
        }

        vet_retrieval_outcome(&outcome)?;
        secret_scan::scan_metadata_field(&outcome.key)?;
        for (key, value) in &outcome.metadata {
            secret_scan::scan_metadata_field(key)?;
            secret_scan::scan_metadata_field(value)?;
        }
        let record = RetrievalOutcomeRecord {
            version: RETRIEVAL_TELEMETRY_VERSION,
            run_id: outcome.run_id,
            key: outcome.key,
            reward: outcome.reward,
            accepted: outcome.accepted,
            metadata: outcome.metadata,
            updated_at: crate::unix_seconds_now(),
        };
        let key = retrieval_outcome_key(record.run_id, &record.key);
        let value = encode_retrieval_outcome(&record)?;
        let mut wtxn = self.env.write_txn()?;
        let run_key = retrieval_run_key(record.run_id);
        if self.vault_meta.get(&wtxn, &run_key)?.is_none() {
            return Err(Error::InvalidConfig(
                "retrieval outcome references unknown run id".to_owned(),
            ));
        }
        let provisional_key = retrieval_run_provisional_key(record.run_id);
        if self.vault_meta.get(&wtxn, &provisional_key)?.is_some() {
            return Err(Error::InvalidConfig(
                "retrieval outcome references unpublished context-pack run id".to_owned(),
            ));
        }
        self.vault_meta.put(&mut wtxn, &key, &value)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn retrieval_runs(&self, limit: usize) -> Result<Vec<RetrievalRunRecord>> {
        let rtxn = self.env.read_txn()?;
        read_retrieval_runs_in_txn(self, &rtxn, limit)
    }

    pub(crate) fn retrieval_run(
        &self,
        run_id: RetrievalRunId,
    ) -> Result<Option<RetrievalRunRecord>> {
        let rtxn = self.env.read_txn()?;
        if self
            .vault_meta
            .get(&rtxn, &retrieval_run_provisional_key(run_id))?
            .is_some()
        {
            return Ok(None);
        }
        let Some(value) = self.vault_meta.get(&rtxn, &retrieval_run_key(run_id))? else {
            return Ok(None);
        };
        let record = decode_retrieval_run(&value)?;
        if record.run_id != run_id {
            return Err(Error::CorruptedIndex("retrieval run telemetry"));
        }
        Ok(Some(record))
    }

    pub(crate) fn retrieval_trace_by_fork_hash(
        &self,
        fork_hash: RetrievalTraceForkHash,
    ) -> Result<Option<RetrievalTrace>> {
        if is_unknown_retrieval_trace_fork_hash(&fork_hash) {
            return Ok(None);
        }
        let rtxn = self.env.read_txn()?;
        let prefix = retrieval_trace_fork_prefix(&fork_hash);
        let mut latest = None::<RetrievalRunRecord>;
        for row in self.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = row?;
            let run_id = retrieval_run_id_from_fork_key(&key)?;
            if self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
            {
                continue;
            }
            let Some(value) = self.vault_meta.get(&rtxn, &retrieval_run_key(run_id))? else {
                return Err(Error::CorruptedIndex("retrieval trace fork index"));
            };
            let record = decode_retrieval_run(&value)?;
            let Some(trace) = &record.trace else {
                return Err(Error::CorruptedIndex("retrieval trace fork index"));
            };
            if record.run_id != run_id || trace.fork_hash != fork_hash {
                return Err(Error::CorruptedIndex("retrieval trace fork index"));
            }
            let replace = latest.as_ref().is_none_or(|current| {
                (record.started_at, record.run_id.as_bytes())
                    > (current.started_at, current.run_id.as_bytes())
            });
            if replace {
                latest = Some(record);
            }
        }
        Ok(latest.and_then(|record| record.trace))
    }

    pub fn retrieval_outcomes(
        &self,
        run_id: RetrievalRunId,
    ) -> Result<Vec<RetrievalOutcomeRecord>> {
        let rtxn = self.env.read_txn()?;
        if self
            .vault_meta
            .get(&rtxn, &retrieval_run_key(run_id))?
            .is_none()
            || self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
        {
            return Ok(Vec::new());
        }
        retrieval_outcomes_for_run_in_txn(&self.vault_meta, &rtxn, run_id)
    }
}

/// Reads the newest published retrieval-run rows from `target`, newest first.
///
/// `Store` reads base rows; a `SessionStoreView` reads overlay ∪ base, so an
/// in-room caller sees its own run rows and a base caller never does.
fn read_retrieval_runs_in_txn(
    target: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    limit: usize,
) -> Result<Vec<RetrievalRunRecord>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut records = Vec::with_capacity(limit.min(RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT));
    let upper = retrieval_run_upper_bound();
    for row in target.vault_meta().rev_range(
        rtxn,
        &(
            std::ops::Bound::Included(RETRIEVAL_RUN_KEY_PREFIX),
            std::ops::Bound::Excluded(upper.as_slice()),
        ),
    )? {
        let (key, value) = row?;
        if !key.starts_with(RETRIEVAL_RUN_KEY_PREFIX) {
            break;
        }
        let run_id = retrieval_run_id_from_key(&key)?;
        if target
            .vault_meta()
            .get(rtxn, &retrieval_run_provisional_key(run_id))?
            .is_some()
        {
            continue;
        }
        let record = decode_retrieval_run(&value)?;
        if record.run_id != run_id {
            return Err(Error::CorruptedIndex("retrieval run telemetry"));
        }
        records.push(record);
        if records.len() == limit {
            break;
        }
    }
    Ok(records)
}

/// Stages one retrieval-run row and its provisional/fork-index side writes
/// into `target`'s `vault_meta` (ONE-1728 K11).
///
/// The base path is byte-identical because it IS this body: `Store`'s
/// `record_retrieval_run_with_visibility` opens the txn and calls here. A
/// session target passes its `SessionStoreView`, so an OffRecord run's row
/// stages into the overlay keyspace and evaporates at close — the base
/// telemetry ledger gains nothing (ARCH-0052 §7 / K10).
fn stage_retrieval_run_with_visibility(
    target: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    record: &RetrievalRunRecord,
    published: bool,
) -> Result<()> {
    let key = retrieval_run_key(record.run_id);
    let value = encode_retrieval_run(record)?;
    let provisional_key = retrieval_run_provisional_key(record.run_id);
    target.vault_meta().put(wtxn, &key, &value)?;
    if published {
        target.vault_meta().delete(wtxn, &provisional_key)?;
        if let Some(trace) = &record.trace {
            put_retrieval_trace_fork_index(
                target.vault_meta(),
                wtxn,
                &trace.fork_hash,
                record.run_id,
            )?;
        }
    } else {
        target.vault_meta().put(wtxn, &provisional_key, b"1")?;
    }
    Ok(())
}

/// Stages the deletion of one retrieval-run row, its provisional marker, its
/// outcome rows, and its trace fork indexes into `target`'s `vault_meta`.
fn stage_retrieval_run_delete(
    target: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    run_id: RetrievalRunId,
) -> Result<()> {
    let key = retrieval_run_key(run_id);
    let provisional_key = retrieval_run_provisional_key(run_id);
    let outcome_prefix = retrieval_outcome_run_prefix(run_id);
    delete_retrieval_trace_fork_indexes_for_run(target.vault_meta(), wtxn, &key, run_id)?;
    let mut outcome_keys = Vec::new();
    for row in target.vault_meta().prefix_iter(wtxn, &outcome_prefix)? {
        let (key, _) = row?;
        outcome_keys.push(key.to_vec());
    }
    for key in outcome_keys {
        target.vault_meta().delete(wtxn, &key)?;
    }
    target.vault_meta().delete(wtxn, &provisional_key)?;
    target.vault_meta().delete(wtxn, &key)?;
    Ok(())
}

/// Stages the finalize of one provisional context-pack retrieval-run row —
/// clearing the provisional marker — into `target`'s `vault_meta`.
///
/// A session run finalizes the SAME overlay row its registration created:
/// the row is looked up through the composed accessor, so the base finalizer
/// never sees it and this one never reaches a base row (ARCH-0052 §7).
fn stage_context_pack_retrieval_run_finalize(
    target: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    finalize: RetrievalRunFinalize<'_>,
) -> Result<()> {
    let RetrievalRunFinalize {
        run_id,
        elapsed_us,
        total_in_scope,
        claims_suppressed,
        surfaced_result_ids,
        empty_reason,
    } = finalize;
    let key = retrieval_run_key(run_id);
    let provisional_key = retrieval_run_provisional_key(run_id);
    let Some(raw) = target.vault_meta().get(wtxn, &key)? else {
        target.vault_meta().delete(wtxn, &provisional_key)?;
        return Ok(());
    };
    let mut record = decode_retrieval_run(&raw)?;
    record.elapsed_us = elapsed_us;
    record.total_in_scope = total_in_scope;
    record.claims_suppressed = claims_suppressed;
    record.result_ids = surfaced_result_ids.to_vec();
    let mut surfaced_breakdown = Vec::with_capacity(surfaced_result_ids.len());
    for (index, result_id) in surfaced_result_ids.iter().enumerate() {
        if let Some(entry) = record
            .score_breakdown
            .iter()
            .find(|entry| entry.result_id == *result_id)
        {
            let mut entry = entry.clone();
            entry.final_rank = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
            surfaced_breakdown.push(entry);
        }
    }
    record.score_breakdown = surfaced_breakdown;
    if let Some(trace) = record.trace.as_mut() {
        // Finalization publishes only the caller's post-filter result set.
        // Earlier stages also reach the durable row and its fork index, so
        // retain their scoring detail only for ids that actually surfaced.
        let allowed: HashSet<[u8; 16]> = surfaced_result_ids.iter().copied().collect();
        for channel in &mut trace.per_channel {
            channel
                .candidates
                .retain(|entry| allowed.contains(&entry.result_id));
        }
        for stage in [&mut trace.fused, &mut trace.blended, &mut trace.reranked] {
            stage
                .candidates
                .retain(|entry| allowed.contains(&entry.result_id));
        }
        trace.final_stage.candidates = record.score_breakdown.clone();
    }
    record.empty_reason = empty_reason;
    let value = encode_retrieval_run(&record)?;
    target.vault_meta().put(wtxn, &key, &value)?;
    if let Some(trace) = &record.trace {
        put_retrieval_trace_fork_index(target.vault_meta(), wtxn, &trace.fork_hash, record.run_id)?;
    }
    target.vault_meta().delete(wtxn, &provisional_key)?;
    Ok(())
}

pub(in crate::store) fn retrieval_run_key(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_RUN_KEY_PREFIX.len() + 16);
    key.extend_from_slice(RETRIEVAL_RUN_KEY_PREFIX);
    key.extend_from_slice(&run_id.as_bytes());
    key
}

pub(super) fn retrieval_run_id_from_key(key: &[u8]) -> Result<RetrievalRunId> {
    let bytes = key
        .strip_prefix(RETRIEVAL_RUN_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("retrieval run telemetry"))?;
    retrieval_run_id_from_value(bytes)
}

fn retrieval_run_id_from_value(bytes: &[u8]) -> Result<RetrievalRunId> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("retrieval run telemetry"))?;
    Ok(RetrievalRunId { bytes })
}

fn retrieval_trace_fork_prefix(fork_hash: &RetrievalTraceForkHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_TRACE_FORK_KEY_PREFIX.len() + 32);
    key.extend_from_slice(RETRIEVAL_TRACE_FORK_KEY_PREFIX);
    key.extend_from_slice(fork_hash);
    key
}

pub(in crate::store) fn retrieval_trace_fork_key(
    fork_hash: &RetrievalTraceForkHash,
    run_id: RetrievalRunId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_TRACE_FORK_KEY_PREFIX.len() + 32 + 16);
    key.extend_from_slice(&retrieval_trace_fork_prefix(fork_hash));
    key.extend_from_slice(&run_id.as_bytes());
    key
}

fn is_unknown_retrieval_trace_fork_hash(fork_hash: &RetrievalTraceForkHash) -> bool {
    fork_hash.iter().all(|byte| *byte == 0)
}

fn put_retrieval_trace_fork_index(
    vault_meta: &OverlayDb,
    wtxn: &mut RwTxn<'_>,
    fork_hash: &RetrievalTraceForkHash,
    run_id: RetrievalRunId,
) -> Result<()> {
    if !is_unknown_retrieval_trace_fork_hash(fork_hash) {
        vault_meta.put(wtxn, &retrieval_trace_fork_key(fork_hash, run_id), b"1")?;
    }
    Ok(())
}

fn delete_retrieval_trace_fork_indexes_for_run(
    vault_meta: &OverlayDb,
    wtxn: &mut RwTxn<'_>,
    run_key: &[u8],
    run_id: RetrievalRunId,
) -> Result<()> {
    if let Some(raw) = vault_meta.get(wtxn, run_key)?
        && let Ok(record) = decode_retrieval_run(&raw)
        && record.run_id == run_id
        && let Some(trace) = record.trace
        && !is_unknown_retrieval_trace_fork_hash(&trace.fork_hash)
    {
        vault_meta.delete(wtxn, &retrieval_trace_fork_key(&trace.fork_hash, run_id))?;
        return Ok(());
    }

    let run_id_bytes = run_id.as_bytes();
    let expected_len = RETRIEVAL_TRACE_FORK_KEY_PREFIX.len() + 32 + 16;
    let mut keys = Vec::new();
    for row in vault_meta.prefix_iter(wtxn, RETRIEVAL_TRACE_FORK_KEY_PREFIX)? {
        let (key, _) = row?;
        if key.len() == expected_len && key.ends_with(&run_id_bytes) {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        vault_meta.delete(wtxn, &key)?;
    }
    Ok(())
}

fn retrieval_run_id_from_fork_key(key: &[u8]) -> Result<RetrievalRunId> {
    let suffix = key
        .strip_prefix(RETRIEVAL_TRACE_FORK_KEY_PREFIX)
        .and_then(|bytes| bytes.get(32..))
        .ok_or(Error::CorruptedIndex("retrieval trace fork index"))?;
    retrieval_run_id_from_value(suffix)
}

pub(super) fn retrieval_run_provisional_key(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX.len() + 16);
    key.extend_from_slice(RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX);
    key.extend_from_slice(&run_id.as_bytes());
    key
}

pub(super) fn retrieval_run_upper_bound() -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_RUN_KEY_PREFIX.len());
    key.extend_from_slice(RETRIEVAL_RUN_KEY_PREFIX);
    *key.last_mut()
        .expect("retrieval run key prefix must be non-empty") += 1;
    key
}

fn retrieval_outcome_run_prefix(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_OUTCOME_KEY_PREFIX.len() + 17);
    key.extend_from_slice(RETRIEVAL_OUTCOME_KEY_PREFIX);
    key.extend_from_slice(&run_id.as_bytes());
    key.push(b':');
    key
}

pub(in crate::store) fn retrieval_outcome_key(
    run_id: RetrievalRunId,
    outcome_key: &str,
) -> Vec<u8> {
    let mut key = retrieval_outcome_run_prefix(run_id);
    key.extend_from_slice(outcome_key.as_bytes());
    key
}

fn retrieval_outcome_parts_from_key(key: &[u8]) -> Result<(RetrievalRunId, String)> {
    let suffix = key
        .strip_prefix(RETRIEVAL_OUTCOME_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("retrieval outcome telemetry"))?;
    if suffix.len() < 17 || suffix[16] != b':' {
        return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
    }
    let run_id_bytes: [u8; 16] = suffix[..16]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("retrieval outcome telemetry"))?;
    let outcome_key_bytes = &suffix[17..];
    let outcome_key = std::str::from_utf8(outcome_key_bytes)
        .map_err(|_| Error::CorruptedIndex("retrieval outcome telemetry"))?;
    if outcome_key.is_empty()
        || outcome_key.len() > RETRIEVAL_OUTCOME_KEY_MAX_LEN
        || !outcome_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
    }
    Ok((
        RetrievalRunId {
            bytes: run_id_bytes,
        },
        outcome_key.to_owned(),
    ))
}

pub(in crate::store) fn encode_retrieval_run(record: &RetrievalRunRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("retrieval run telemetry encode failed"))
}

pub(in crate::store) fn decode_retrieval_run(raw: &[u8]) -> Result<RetrievalRunRecord> {
    let record: RetrievalRunRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("retrieval run telemetry"))?;
    if record.version != RETRIEVAL_TELEMETRY_VERSION {
        return Err(Error::CorruptedIndex("retrieval run telemetry"));
    }
    Ok(record)
}

fn encode_retrieval_outcome(record: &RetrievalOutcomeRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("retrieval outcome telemetry encode failed"))
}

fn decode_retrieval_outcome(raw: &[u8]) -> Result<RetrievalOutcomeRecord> {
    let record: RetrievalOutcomeRecord = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("retrieval outcome telemetry"))?;
    if record.version != RETRIEVAL_TELEMETRY_VERSION {
        return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
    }
    Ok(record)
}

pub(super) fn retrieval_outcomes_for_run_in_txn(
    vault_meta: &OverlayDb,
    rtxn: &RoTxn<'_>,
    run_id: RetrievalRunId,
) -> Result<Vec<RetrievalOutcomeRecord>> {
    let prefix = retrieval_outcome_run_prefix(run_id);
    let mut records = Vec::new();
    for row in vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, value) = row?;
        let (key_run_id, key_outcome_key) = retrieval_outcome_parts_from_key(&key)?;
        if key_run_id != run_id {
            return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
        }
        let record = decode_retrieval_outcome(&value)?;
        if record.run_id != key_run_id || record.key != key_outcome_key {
            return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
        }
        records.push(record);
    }
    records.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(records)
}

fn vet_retrieval_outcome(outcome: &RetrievalOutcome) -> Result<()> {
    if outcome.key.is_empty()
        || outcome.key.len() > RETRIEVAL_OUTCOME_KEY_MAX_LEN
        || !outcome
            .key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(Error::InvalidConfig(
            "retrieval outcome key must be 1-128 chars of ASCII alnum, '.', '_', '-', or ':'"
                .to_owned(),
        ));
    }
    if let Some(reward) = outcome.reward
        && !reward.is_finite()
    {
        return Err(Error::InvalidConfig(
            "retrieval outcome reward must be finite".to_owned(),
        ));
    }
    Ok(())
}
