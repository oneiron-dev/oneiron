//! Retrieval-run, outcome, and trace-fork persistence: `Store` and `SessionStoreView` methods, staging bodies, key formats, and codecs.

use std::collections::HashSet;

use heed::{RoTxn, RwTxn};

use crate::batch::secret_scan;
use crate::error::{Error, Result, SideTableRowProblem, StoreError};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
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

const RETRIEVAL_OUTCOME_KEY_MAX_LEN: usize = 128;

pub(in crate::store) const RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT: usize = 1024;

impl SideKey for RetrievalRunId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(Self::from_bytes(bytes.try_into().ok()?))
    }
}

/// Retrieval-run telemetry record, keyed by run id. Codec fixed `Raw` (see
/// the decls.rs note): decode also enforces the version byte and
/// `RetrievalState::validate`, so [`RawValue`] delegates to
/// [`encode_retrieval_run`]/[`decode_retrieval_run`] — kept as free functions
/// because `retrieval_telemetry::state_tests` calls them directly.
pub(super) const RETRIEVAL_RUN: SideTable<RetrievalRunId, RetrievalRunRecord, Raw> =
    SideTable::new(&side_table::RETRIEVAL_RUN);

impl RawValue for RetrievalRunRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_retrieval_run(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_retrieval_run(bytes)?)
    }
}

/// Unpublished context-pack run marker: presence-only, but the byte already
/// on disk is the literal `b"1"` this module always wrote, so the value type
/// spells that exact byte rather than reusing the empty-marker `()` codec.
pub(super) struct PresentMarker;

impl RawValue for PresentMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(b"1".to_vec())
    }

    fn from_raw(_bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self)
    }
}

pub(super) const RETRIEVAL_RUN_PROVISIONAL: SideTable<RetrievalRunId, PresentMarker, Raw> =
    SideTable::new(&side_table::RETRIEVAL_RUN_PROVISIONAL);

/// Trace fork hash to runs. Key: bytes32 + id16 (the run id trails, so the
/// door's built-in fixed-width tuple key applies directly).
const RETRIEVAL_TRACE_FORK_INDEX: SideTable<([u8; 32], RetrievalRunId), PresentMarker, Raw> =
    SideTable::new(&side_table::RETRIEVAL_TRACE_FORK_INDEX);

/// Reported retrieval run outcome. Key: id16 ":" string — a literal `:`
/// separator, not the door's plain fixed-then-rest tuple, so it gets a
/// hand-spelled key type.
struct OutcomeKey(RetrievalRunId, String);

impl SideKey for OutcomeKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.as_bytes());
        out.push(b':');
        out.extend_from_slice(self.1.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 17 || bytes[16] != b':' {
            return None;
        }
        let run_id = RetrievalRunId::from_bytes(bytes[..16].try_into().ok()?);
        let outcome_key = std::str::from_utf8(&bytes[17..]).ok()?.to_owned();
        if outcome_key.is_empty()
            || outcome_key.len() > RETRIEVAL_OUTCOME_KEY_MAX_LEN
            || !outcome_key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
        {
            return None;
        }
        Some(Self(run_id, outcome_key))
    }
}

/// Codec fixed `Raw` (see the decls.rs note): decode also enforces the
/// version byte, so [`RawValue`] delegates to the module's own
/// `encode_retrieval_outcome`/`decode_retrieval_outcome`.
const RETRIEVAL_OUTCOME: SideTable<OutcomeKey, RetrievalOutcomeRecord, Raw> =
    SideTable::new(&side_table::RETRIEVAL_OUTCOME);

impl RawValue for RetrievalOutcomeRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_retrieval_outcome(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_retrieval_outcome(bytes)?)
    }
}

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
        crate::ports::recorded_at_in_txn(self, wtxn)?;
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
    pub fn retrieval_telemetry_writes_enabled(&self) -> bool {
        !self
            .retrieval_writes_disabled
            .load(std::sync::atomic::Ordering::Acquire)
    }

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
        if !self.retrieval_telemetry_writes_enabled() {
            return Err(Error::InvariantViolation(
                "retrieval telemetry writes disabled",
            ));
        }
        // Invalid caller state is not a storage failure. Session staging also
        // validates in-transaction because it does not enter this outer door.
        record.state.validate()?;
        #[cfg(test)]
        if test_hooks::take_fail_next_retrieval_run_write(&self.owner._registered_path.path) {
            self.retrieval_writes_disabled
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(Error::InvariantViolation(
                "forced retrieval telemetry write failure",
            ));
        }
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval telemetry skipped inside active write transaction",
            ));
        }

        let result = (|| {
            let mut wtxn = self.env.write_txn()?;
            stage_retrieval_run_with_visibility(self, &mut wtxn, record, published)?;
            wtxn.commit()?;
            Ok(())
        })();
        if result.is_err() {
            self.retrieval_writes_disabled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
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
            updated_at: self.clock.now_recorded_at(),
        };
        let mut wtxn = self.env.write_txn()?;
        if !RETRIEVAL_RUN.contains(self, &wtxn, &record.run_id)? {
            return Err(Error::InvalidConfig(
                "retrieval outcome references unknown run id".to_owned(),
            ));
        }
        if RETRIEVAL_RUN_PROVISIONAL.contains(self, &wtxn, &record.run_id)? {
            return Err(Error::InvalidConfig(
                "retrieval outcome references unpublished context-pack run id".to_owned(),
            ));
        }
        let key = OutcomeKey(record.run_id, record.key.clone());
        RETRIEVAL_OUTCOME.put(self, &mut wtxn, &key, &record)?;
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
        if RETRIEVAL_RUN_PROVISIONAL.contains(self, &rtxn, &run_id)? {
            return Ok(None);
        }
        let Some(record) = RETRIEVAL_RUN.get(self, &rtxn, &run_id)? else {
            return Ok(None);
        };
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
        let mut latest = None::<RetrievalRunRecord>;
        for row in RETRIEVAL_TRACE_FORK_INDEX.scan_from(self, &rtxn, &fork_hash)? {
            let ((_fork_hash, run_id), _marker) = row;
            if RETRIEVAL_RUN_PROVISIONAL.contains(self, &rtxn, &run_id)? {
                continue;
            }
            let Some(record) = RETRIEVAL_RUN.get(self, &rtxn, &run_id)? else {
                return Err(Error::CorruptedIndex("retrieval trace fork index"));
            };
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
        if !RETRIEVAL_RUN.contains(self, &rtxn, &run_id)?
            || RETRIEVAL_RUN_PROVISIONAL.contains(self, &rtxn, &run_id)?
        {
            return Ok(Vec::new());
        }
        retrieval_outcomes_for_run_in_txn(self, &rtxn, run_id)
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
    for row in RETRIEVAL_RUN.iter_rev_from(target, rtxn, &[])? {
        let (run_id, record) = row.map_err(|error| match error {
            Error::Store(StoreError::SideTableRow {
                problem: SideTableRowProblem::KeyShape,
                ..
            }) => Error::CorruptedIndex("retrieval run telemetry"),
            other => other,
        })?;
        if RETRIEVAL_RUN_PROVISIONAL.contains(target, rtxn, &run_id)? {
            continue;
        }
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
    record.state.validate()?;
    if let Some(existing) = RETRIEVAL_RUN.get(target, &*wtxn, &record.run_id)? {
        super::turn_index::delete(target, wtxn, &existing)?;
    }
    RETRIEVAL_RUN.put(target, wtxn, &record.run_id, record)?;
    if published {
        super::turn_index::put(target, wtxn, record)?;
        RETRIEVAL_RUN_PROVISIONAL.delete(target, wtxn, &record.run_id)?;
        if let Some(trace) = &record.trace {
            put_retrieval_trace_fork_index(target, wtxn, &trace.fork_hash, record.run_id)?;
        }
    } else {
        RETRIEVAL_RUN_PROVISIONAL.put(target, wtxn, &record.run_id, &PresentMarker)?;
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
    super::turn_index::delete_for_run(target, wtxn, run_id)?;
    delete_retrieval_trace_fork_indexes_for_run(target, wtxn, run_id)?;
    RETRIEVAL_OUTCOME.delete_from(target, wtxn, &retrieval_outcome_run_prefix(run_id))?;
    RETRIEVAL_RUN_PROVISIONAL.delete(target, wtxn, &run_id)?;
    RETRIEVAL_RUN.delete(target, wtxn, &run_id)?;
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
    let Some(mut record) = RETRIEVAL_RUN.get(target, &*wtxn, &run_id)? else {
        RETRIEVAL_RUN_PROVISIONAL.delete(target, wtxn, &run_id)?;
        return Ok(());
    };
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
    super::turn_index::put(target, wtxn, &record)?;
    RETRIEVAL_RUN.put(target, wtxn, &run_id, &record)?;
    if let Some(trace) = &record.trace {
        put_retrieval_trace_fork_index(target, wtxn, &trace.fork_hash, record.run_id)?;
    }
    RETRIEVAL_RUN_PROVISIONAL.delete(target, wtxn, &run_id)?;
    Ok(())
}

/// Only `store::tests`/`state_tests` name this directly now, to compute a raw
/// full key for corrupt/legacy-row fixtures; production readers go through
/// [`RETRIEVAL_RUN`]'s typed door.
#[cfg(test)]
pub(in crate::store) fn retrieval_run_key(run_id: RetrievalRunId) -> Vec<u8> {
    RETRIEVAL_RUN.key_bytes(&run_id)
}

/// Test-only, see [`retrieval_run_key`].
#[cfg(test)]
pub(in crate::store) fn retrieval_trace_fork_key(
    fork_hash: &RetrievalTraceForkHash,
    run_id: RetrievalRunId,
) -> Vec<u8> {
    RETRIEVAL_TRACE_FORK_INDEX.key_bytes(&(*fork_hash, run_id))
}

fn is_unknown_retrieval_trace_fork_hash(fork_hash: &RetrievalTraceForkHash) -> bool {
    fork_hash.iter().all(|byte| *byte == 0)
}

fn put_retrieval_trace_fork_index(
    target: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    fork_hash: &RetrievalTraceForkHash,
    run_id: RetrievalRunId,
) -> Result<()> {
    if !is_unknown_retrieval_trace_fork_hash(fork_hash) {
        RETRIEVAL_TRACE_FORK_INDEX.put(target, wtxn, &(*fork_hash, run_id), &PresentMarker)?;
    }
    Ok(())
}

/// Cleanup must work even if the primary row was corrupted before
/// publication: a decode failure (or a missing row) on the direct lookup
/// falls back to the full-family scan below rather than propagating.
fn delete_retrieval_trace_fork_indexes_for_run(
    target: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    run_id: RetrievalRunId,
) -> Result<()> {
    if let Ok(Some(record)) = RETRIEVAL_RUN.get(target, &*wtxn, &run_id)
        && record.run_id == run_id
        && let Some(trace) = record.trace
        && !is_unknown_retrieval_trace_fork_hash(&trace.fork_hash)
    {
        RETRIEVAL_TRACE_FORK_INDEX.delete(target, wtxn, &(trace.fork_hash, run_id))?;
        return Ok(());
    }

    let mut keys = Vec::new();
    for row in RETRIEVAL_TRACE_FORK_INDEX
        .iter_from(target, &*wtxn, &[])?
        .collect::<Result<Vec<_>>>()?
    {
        let ((fork_hash, key_run_id), _marker) = row;
        if key_run_id == run_id {
            keys.push((fork_hash, key_run_id));
        }
    }
    for key in keys {
        RETRIEVAL_TRACE_FORK_INDEX.delete(target, wtxn, &key)?;
    }
    Ok(())
}

fn retrieval_outcome_run_prefix(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = run_id.as_bytes().to_vec();
    key.push(b':');
    key
}

/// Test-only, see [`retrieval_run_key`].
#[cfg(test)]
pub(in crate::store) fn retrieval_outcome_key(
    run_id: RetrievalRunId,
    outcome_key: &str,
) -> Vec<u8> {
    RETRIEVAL_OUTCOME.key_bytes(&OutcomeKey(run_id, outcome_key.to_owned()))
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
    record
        .state
        .validate()
        .map_err(|_| Error::CorruptedIndex("retrieval run state"))?;
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
    target: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    run_id: RetrievalRunId,
) -> Result<Vec<RetrievalOutcomeRecord>> {
    let mut records = Vec::new();
    for (OutcomeKey(key_run_id, key_outcome_key), record) in
        RETRIEVAL_OUTCOME.scan_from(target, rtxn, &retrieval_outcome_run_prefix(run_id))?
    {
        if key_run_id != run_id {
            return Err(Error::CorruptedIndex("retrieval outcome telemetry"));
        }
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
