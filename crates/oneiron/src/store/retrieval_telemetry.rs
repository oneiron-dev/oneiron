//! Retrieval telemetry: run records, trace fork index, outcome rows, and
//! reward-weighted blend-weight tuning. This file also carries the
//! session-side [`SessionStoreView`] retrieval siblings.

use std::collections::BTreeMap;
use std::str;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::batch::secret_scan;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
use crate::pipeline::Signal;

use super::*;

const RETRIEVAL_TELEMETRY_VERSION: u8 = 0;

/// Crate-visible so the off-record close census can count the session's own
/// retrieval-run receipt rows in the overlay `VaultMeta` keyspace immediately
/// before they evaporate (ONE-1728 K8). The key FORMAT is owned here; the
/// census only tests the prefix.
pub(crate) const RETRIEVAL_RUN_KEY_PREFIX: &[u8] = b"retr_run:v0:";

const RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX: &[u8] = b"retr_run_prov:v0:";

const RETRIEVAL_TRACE_FORK_KEY_PREFIX: &[u8] = b"retr_trace_fork:v0:";

const RETRIEVAL_OUTCOME_KEY_PREFIX: &[u8] = b"retr_out:v0:";

pub(super) const RETRIEVAL_BLEND_WEIGHT_TABLE_KEY: &[u8] = b"retr_blend_weights:v0:active";

pub(super) const RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT: usize = 1024;

const RETRIEVAL_OUTCOME_KEY_MAX_LEN: usize = 128;

pub(super) const RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION: u8 = 1;

pub(super) const RETRIEVAL_BLEND_TUNER_ALGORITHM: &str = "ret010d.reward_weighted_bandit.v1";

const RETRIEVAL_BLEND_BOOTSTRAP_SOURCE: &str = "ret010b.bootstrap";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RetrievalRunId {
    bytes: [u8; 16],
}

impl RetrievalRunId {
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.bytes
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "no P4a path reconstructs a run id from raw bytes; on the ONE-1728 seg-4 \
                  post-merge delete-list unless ONE-1730's promote replay claims it"
    )]
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalAction {
    Pipeline,
    ContextPack,
    VaultSearch,
    GraphFsCoreutils,
    /// EMB-5 speculative fire over an ASR partial. Only speculative fires
    /// carry this tag (the end-of-utterance full-quality pass logs as
    /// `Pipeline`) — that is what makes wasted-retrieval budget measurable.
    Speculative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalSignal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
    Recency,
    Salience,
    Confidence,
    Gravity,
    /// RET-010 host-injected reranker component. Never a channel and never
    /// a blend signal: the blend weight table must not train on reranker
    /// output.
    Rerank,
    Hyde,
    /// HyDE retry subquery channel, retained only in retrieval traces.
    HydeRetry,
}

impl RetrievalSignal {
    #[must_use]
    pub fn as_blend_signal(self) -> Option<RetrievalBlendSignal> {
        match self {
            Self::Recency => Some(RetrievalBlendSignal::Recency),
            Self::Salience => Some(RetrievalBlendSignal::Salience),
            Self::Confidence => Some(RetrievalBlendSignal::Confidence),
            Self::Gravity => Some(RetrievalBlendSignal::Gravity),
            Self::Vector
            | Self::Text
            | Self::Phonetic
            | Self::Temporal
            | Self::Ppr
            | Self::Rerank
            | Self::Hyde
            | Self::HydeRetry => None,
        }
    }
}

impl From<Signal> for RetrievalSignal {
    fn from(signal: Signal) -> Self {
        match signal {
            Signal::Vector => Self::Vector,
            Signal::Text => Self::Text,
            Signal::Phonetic => Self::Phonetic,
            Signal::Temporal => Self::Temporal,
            Signal::Ppr => Self::Ppr,
            Signal::Hyde => Self::Hyde,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalBlendSignal {
    Recency,
    Salience,
    Confidence,
    Gravity,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RetrievalBlendWeights {
    pub recency: f32,
    pub salience: f32,
    pub confidence: f32,
    pub gravity: f32,
}

impl RetrievalBlendWeights {
    #[must_use]
    pub const fn bootstrap() -> Self {
        Self {
            recency: 0.35,
            salience: 0.30,
            confidence: 0.20,
            gravity: 0.15,
        }
    }

    #[must_use]
    pub const fn new(recency: f32, salience: f32, confidence: f32, gravity: f32) -> Self {
        Self {
            recency,
            salience,
            confidence,
            gravity,
        }
    }

    #[must_use]
    pub fn weight(self, signal: RetrievalBlendSignal) -> f32 {
        match signal {
            RetrievalBlendSignal::Recency => self.recency,
            RetrievalBlendSignal::Salience => self.salience,
            RetrievalBlendSignal::Confidence => self.confidence,
            RetrievalBlendSignal::Gravity => self.gravity,
        }
    }

    pub(crate) fn normalized(self) -> Result<Self> {
        validate_retrieval_blend_weights(self).map_err(Error::InvalidConfig)?;
        let sum = self.sum();
        Ok(Self {
            recency: self.recency / sum,
            salience: self.salience / sum,
            confidence: self.confidence / sum,
            gravity: self.gravity / sum,
        })
    }

    fn sum(self) -> f32 {
        self.recency + self.salience + self.confidence + self.gravity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RetrievalBlendWeightDataWindow {
    pub run_count: u32,
    pub outcome_count: u32,
    pub candidate_count: u32,
    pub started_at_min: Option<u64>,
    pub started_at_max: Option<u64>,
    pub outcome_updated_at_min: Option<u64>,
    pub outcome_updated_at_max: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalBlendWeightTableEntry {
    pub version: u8,
    pub weights: RetrievalBlendWeights,
    pub tuned_at: u64,
    pub provenance: BTreeMap<String, String>,
    pub data_window: RetrievalBlendWeightDataWindow,
}

impl RetrievalBlendWeightTableEntry {
    #[must_use]
    pub fn bootstrap() -> Self {
        let mut provenance = BTreeMap::new();
        provenance.insert(
            "source".to_owned(),
            RETRIEVAL_BLEND_BOOTSTRAP_SOURCE.to_owned(),
        );
        provenance.insert("algorithm".to_owned(), "ret010b.bootstrap.v1".to_owned());
        Self {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights: RetrievalBlendWeights::bootstrap(),
            tuned_at: 0,
            provenance,
            data_window: RetrievalBlendWeightDataWindow::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetrievalBlendTuningConfig {
    pub max_runs: usize,
    pub learning_rate: f32,
    pub min_reward_count: usize,
}

impl Default for RetrievalBlendTuningConfig {
    fn default() -> Self {
        Self {
            max_runs: RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT,
            learning_rate: 0.05,
            min_reward_count: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalScoreComponent {
    pub signal: RetrievalSignal,
    pub rank: u32,
    pub score: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalScoreBreakdown {
    pub result_id: [u8; 16],
    pub final_rank: u32,
    pub final_score: f32,
    pub components: Vec<RetrievalScoreComponent>,
    /// ONE-1402 read-side decay attribution: the exact access multiplier
    /// the run applied to this entity's fused score (post-override,
    /// post-floor; `1.0` for non-claims and gate-skipped candidates), so a
    /// consumer can reconstruct the pre-decay scale as `final_score / f`
    /// when `Some(f)` and `f > 0`.
    ///
    /// `None` means NOT APPLICABLE — a per-channel or fused-stage row and
    /// direct vault-search breakdowns, where no multiplication happened —
    /// or a row written by a binary that predates the field. It is
    /// deliberately distinct from `Some(1.0)`, which means decay ran and
    /// resolved to neutral.
    ///
    /// Wire-compatible in both directions: `None` skips the key, so a row
    /// encodes to the exact legacy four-key shape and legacy bytes decode
    /// back to `None`. Decay is still not a [`RetrievalSignal`]: this is
    /// an observation of the multiplier, never a blend component and never
    /// a rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_factor: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalTraceStage {
    PerChannel,
    Fused,
    Blended,
    Reranked,
    Final,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTraceChannelRecord {
    pub stage: RetrievalTraceStage,
    pub signal: RetrievalSignal,
    pub candidates: Vec<RetrievalScoreBreakdown>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTraceStageRecord {
    pub stage: RetrievalTraceStage,
    pub candidates: Vec<RetrievalScoreBreakdown>,
}

/// SHA-256 replay key for a content-addressed [`RetrievalTrace`].
///
/// The hash is stored as the raw 32-byte digest, not hex. It is computed by
/// the retrieval pipeline with the same domain-separated SHA-256 style as the
/// gate policy frontier hash: length-prefixed UTF-8 strings/bytes, little-endian
/// integers, one-byte booleans, and IEEE-754 `to_bits()` bytes for floats.
pub type RetrievalTraceForkHash = [u8; 32];

/// Opt-in per-stage retrieval trace.
///
/// `fork_hash` is the content-addressed replay key for fork-and-diff eval. Its
/// canonical input snapshot is: query inputs for all enabled retrieval channels,
/// normalized retrieval config and flags, the BM25 rank-profile snapshot, the
/// pinned recency half-life table, the active retrieval-blend weight table,
/// an explicitly supplied replay clock whenever present — read-side decay
/// scores from the run's resolved clock on EVERY retrieval, so an explicit
/// clock is time-dependent scoring input unconditionally, not only for
/// recency/temporal runs — the caller-supplied read-side access-factor
/// override map canonicalized as a presence flag plus entries sorted by
/// `EntityId`, and the candidate set canonicalized as sorted, deduplicated
/// `EntityId` bytes. Implicit wall-clock seconds are not hashed. Legacy traces
/// missing the field decode to the all-zero sentinel, which is treated as
/// unknown and is not indexed. The trace remains typed msgpack-native;
/// JSONL/parquet export belongs outside the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTrace {
    #[serde(default)]
    pub fork_hash: RetrievalTraceForkHash,
    pub per_channel: Vec<RetrievalTraceChannelRecord>,
    pub fused: RetrievalTraceStageRecord,
    pub blended: RetrievalTraceStageRecord,
    pub reranked: RetrievalTraceStageRecord,
    #[serde(rename = "final")]
    pub final_stage: RetrievalTraceStageRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalRunRecord {
    pub version: u8,
    pub run_id: RetrievalRunId,
    pub action: RetrievalAction,
    pub started_at: u64,
    pub elapsed_us: u64,
    pub signals: Vec<RetrievalSignal>,
    pub result_ids: Vec<[u8; 16]>,
    pub score_breakdown: Vec<RetrievalScoreBreakdown>,
    pub total_in_scope: usize,
    pub claims_suppressed: usize,
    pub empty_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<RetrievalTrace>,
}

impl RetrievalRunRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        run_id: RetrievalRunId,
        action: RetrievalAction,
        started_at: u64,
        elapsed_us: u64,
        signals: Vec<RetrievalSignal>,
        score_breakdown: Vec<RetrievalScoreBreakdown>,
        total_in_scope: usize,
        claims_suppressed: usize,
        empty_reason: Option<String>,
    ) -> Self {
        let result_ids = score_breakdown
            .iter()
            .map(|entry| entry.result_id)
            .collect();
        Self {
            version: RETRIEVAL_TELEMETRY_VERSION,
            run_id,
            action,
            started_at,
            elapsed_us,
            signals,
            result_ids,
            score_breakdown,
            total_in_scope,
            claims_suppressed,
            empty_reason,
            trace: None,
        }
    }

    pub(crate) fn with_trace(mut self, trace: Option<RetrievalTrace>) -> Self {
        self.trace = trace;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalOutcome {
    pub run_id: RetrievalRunId,
    pub key: String,
    pub reward: Option<f32>,
    pub accepted: Option<bool>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalOutcomeRecord {
    pub version: u8,
    pub run_id: RetrievalRunId,
    pub key: String,
    pub reward: Option<f32>,
    pub accepted: Option<bool>,
    pub metadata: BTreeMap<String, String>,
    pub updated_at: u64,
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
        run_id: RetrievalRunId,
        elapsed_us: u64,
        claims_suppressed: usize,
        surfaced_result_ids: &[[u8; 16]],
        empty_reason: Option<String>,
    ) -> Result<()> {
        stage_context_pack_retrieval_run_finalize(
            self,
            wtxn,
            run_id,
            elapsed_us,
            claims_suppressed,
            surfaced_result_ids,
            empty_reason,
        )
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

    pub(crate) fn finalize_context_pack_retrieval_run(
        &self,
        run_id: RetrievalRunId,
        elapsed_us: u64,
        claims_suppressed: usize,
        surfaced_result_ids: &[[u8; 16]],
        empty_reason: Option<String>,
    ) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "context-pack retrieval telemetry skipped inside active write transaction",
            ));
        }

        let mut wtxn = self.env.write_txn()?;
        stage_context_pack_retrieval_run_finalize(
            self,
            &mut wtxn,
            run_id,
            elapsed_us,
            claims_suppressed,
            surfaced_result_ids,
            empty_reason,
        )?;
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

    pub(crate) fn retrieval_blend_weight_table_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        let Some(value) = self
            .vault_meta
            .get(rtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY)?
        else {
            return Ok(RetrievalBlendWeightTableEntry::bootstrap());
        };
        decode_retrieval_blend_weight_table(&value)
    }

    pub fn retrieval_blend_weight_table(&self) -> Result<RetrievalBlendWeightTableEntry> {
        let rtxn = self.env.read_txn()?;
        self.retrieval_blend_weight_table_in_txn(&rtxn)
    }

    pub fn tune_retrieval_blend_weights(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        validate_retrieval_blend_tuning_config(config)?;
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval blend weight tuning skipped inside active write transaction",
            ));
        }
        let _tuning_guard = self
            .retrieval_blend_tuning_lock
            .lock()
            .map_err(|_| Error::InvariantViolation("retrieval blend tuning mutex poisoned"))?;

        let rtxn = self.env.read_txn()?;
        let previous = self.retrieval_blend_weight_table_in_txn(&rtxn)?;
        let upper = retrieval_run_upper_bound();
        let mut gradient = [0.0_f64; 4];
        let mut reward_count = 0_usize;
        let mut component_count = 0_usize;
        let mut data_window = RetrievalBlendWeightDataWindow::default();

        let mut accepted_runs = 0_usize;
        for row in self.vault_meta.rev_range(
            &rtxn,
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
            if self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
            {
                continue;
            }
            let record = decode_retrieval_run(&value)?;
            if record.run_id != run_id {
                return Err(Error::CorruptedIndex("retrieval run telemetry"));
            }
            if accepted_runs == config.max_runs {
                break;
            }
            accepted_runs += 1;

            let outcomes = retrieval_outcomes_for_run_in_txn(&self.vault_meta, &rtxn, run_id)?;
            let run_reward_count_before = reward_count;
            let run_candidate_count_before = data_window.candidate_count;
            for outcome in outcomes.iter().filter(|outcome| outcome.reward.is_some()) {
                let reward = f64::from(outcome.reward.expect("filtered reward"));
                let mut outcome_gradient = [0.0_f64; 4];
                let mut outcome_component_count = 0_usize;
                let mut outcome_candidate_count = 0_u32;
                for candidate in &record.score_breakdown {
                    let rank_credit = 1.0 / f64::from(candidate.final_rank.max(1));
                    let mut candidate_has_blend_component = false;
                    for component in &candidate.components {
                        let Some(index) = retrieval_blend_component_index(component.signal) else {
                            continue;
                        };
                        if !component.score.is_finite() {
                            return Err(Error::CorruptedIndex("retrieval blend tuning"));
                        }
                        outcome_gradient[index] +=
                            reward * rank_credit * f64::from(component.score);
                        outcome_component_count += 1;
                        candidate_has_blend_component = true;
                    }
                    if candidate_has_blend_component {
                        outcome_candidate_count = outcome_candidate_count.saturating_add(1);
                    }
                }
                if outcome_component_count == 0 {
                    continue;
                }
                for (total, outcome) in gradient.iter_mut().zip(outcome_gradient) {
                    *total += outcome;
                }
                component_count += outcome_component_count;
                reward_count += 1;
                observe_retrieval_blend_outcome(&mut data_window, outcome);
                data_window.candidate_count = data_window
                    .candidate_count
                    .saturating_add(outcome_candidate_count);
            }
            if reward_count > run_reward_count_before
                && data_window.candidate_count > run_candidate_count_before
            {
                observe_retrieval_blend_run(&mut data_window, &record);
            }
        }
        drop(rtxn);

        if reward_count < config.min_reward_count {
            return Err(Error::InvalidConfig(format!(
                "retrieval blend tuning requires at least {} reward outcome(s), found {reward_count}",
                config.min_reward_count
            )));
        }
        if component_count == 0 {
            return Err(Error::InvalidConfig(
                "retrieval blend tuning requires blend-signal score components".to_owned(),
            ));
        }

        let weights = apply_retrieval_blend_weight_update(
            previous.weights,
            gradient,
            config.learning_rate,
            reward_count,
        )?;
        let mut provenance = BTreeMap::new();
        provenance.insert("source".to_owned(), "RetrievalOutcomeRecord".to_owned());
        provenance.insert(
            "algorithm".to_owned(),
            RETRIEVAL_BLEND_TUNER_ALGORITHM.to_owned(),
        );
        provenance.insert("max_runs".to_owned(), config.max_runs.to_string());
        provenance.insert("learning_rate".to_owned(), config.learning_rate.to_string());
        provenance.insert(
            "previous_tuned_at".to_owned(),
            previous.tuned_at.to_string(),
        );
        let entry = RetrievalBlendWeightTableEntry {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights,
            tuned_at: crate::unix_seconds_now(),
            provenance,
            data_window,
        };
        self.put_retrieval_blend_weight_table_entry(&entry)?;
        Ok(entry)
    }

    fn put_retrieval_blend_weight_table_entry(
        &self,
        entry: &RetrievalBlendWeightTableEntry,
    ) -> Result<()> {
        vet_retrieval_blend_weight_table_entry(entry)
            .map_err(|_| Error::InvalidConfig("invalid retrieval blend weight table".to_owned()))?;
        let value = encode_retrieval_blend_weight_table(entry)?;
        let mut wtxn = self.env.write_txn()?;
        self.vault_meta
            .put(&mut wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, &value)?;
        wtxn.commit()?;
        Ok(())
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
    run_id: RetrievalRunId,
    elapsed_us: u64,
    claims_suppressed: usize,
    surfaced_result_ids: &[[u8; 16]],
    empty_reason: Option<String>,
) -> Result<()> {
    let key = retrieval_run_key(run_id);
    let provisional_key = retrieval_run_provisional_key(run_id);
    let Some(raw) = target.vault_meta().get(wtxn, &key)? else {
        target.vault_meta().delete(wtxn, &provisional_key)?;
        return Ok(());
    };
    let mut record = decode_retrieval_run(&raw)?;
    record.elapsed_us = elapsed_us;
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

pub(super) fn retrieval_run_key(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_RUN_KEY_PREFIX.len() + 16);
    key.extend_from_slice(RETRIEVAL_RUN_KEY_PREFIX);
    key.extend_from_slice(&run_id.as_bytes());
    key
}

fn retrieval_run_id_from_key(key: &[u8]) -> Result<RetrievalRunId> {
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

pub(super) fn retrieval_trace_fork_key(
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

fn retrieval_run_provisional_key(run_id: RetrievalRunId) -> Vec<u8> {
    let mut key = Vec::with_capacity(RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX.len() + 16);
    key.extend_from_slice(RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX);
    key.extend_from_slice(&run_id.as_bytes());
    key
}

fn retrieval_run_upper_bound() -> Vec<u8> {
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

pub(super) fn retrieval_outcome_key(run_id: RetrievalRunId, outcome_key: &str) -> Vec<u8> {
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

pub(super) fn encode_retrieval_run(record: &RetrievalRunRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("retrieval run telemetry encode failed"))
}

pub(super) fn decode_retrieval_run(raw: &[u8]) -> Result<RetrievalRunRecord> {
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

fn retrieval_outcomes_for_run_in_txn(
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

fn encode_retrieval_blend_weight_table(entry: &RetrievalBlendWeightTableEntry) -> Result<Vec<u8>> {
    vet_retrieval_blend_weight_table_entry(entry)?;
    rmp_serde::to_vec_named(entry)
        .map_err(|_| Error::InvariantViolation("retrieval blend weight table encode failed"))
}

fn decode_retrieval_blend_weight_table(raw: &[u8]) -> Result<RetrievalBlendWeightTableEntry> {
    let mut entry: RetrievalBlendWeightTableEntry = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    vet_retrieval_blend_weight_table_entry(&entry)?;
    entry.weights = entry
        .weights
        .normalized()
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    Ok(entry)
}

fn vet_retrieval_blend_weight_table_entry(entry: &RetrievalBlendWeightTableEntry) -> Result<()> {
    if entry.version != RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION
        || entry.provenance.is_empty()
        || !entry.provenance.contains_key("source")
        || !entry.provenance.contains_key("algorithm")
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    validate_retrieval_blend_weights(entry.weights)
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    if entry.data_window.outcome_count > 0
        && (entry.data_window.outcome_updated_at_min.is_none()
            || entry.data_window.outcome_updated_at_max.is_none())
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    if entry.data_window.run_count > 0
        && (entry.data_window.started_at_min.is_none()
            || entry.data_window.started_at_max.is_none())
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    Ok(())
}

fn validate_retrieval_blend_weights(
    weights: RetrievalBlendWeights,
) -> std::result::Result<(), String> {
    let values = [
        ("recency", weights.recency),
        ("salience", weights.salience),
        ("confidence", weights.confidence),
        ("gravity", weights.gravity),
    ];
    for (name, value) in values {
        if !value.is_finite() || value < 0.0 {
            return Err(format!(
                "retrieval blend {name} weight must be finite and non-negative"
            ));
        }
    }
    if weights.sum() <= 0.0 {
        return Err("retrieval blend weights must have positive total mass".to_owned());
    }
    Ok(())
}

fn validate_retrieval_blend_tuning_config(config: RetrievalBlendTuningConfig) -> Result<()> {
    if config.max_runs == 0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning max_runs must be positive".to_owned(),
        ));
    }
    if config.min_reward_count == 0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning min_reward_count must be positive".to_owned(),
        ));
    }
    if !config.learning_rate.is_finite() || config.learning_rate <= 0.0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning learning_rate must be finite and positive".to_owned(),
        ));
    }
    Ok(())
}

fn retrieval_blend_component_index(signal: RetrievalSignal) -> Option<usize> {
    match signal.as_blend_signal()? {
        RetrievalBlendSignal::Recency => Some(0),
        RetrievalBlendSignal::Salience => Some(1),
        RetrievalBlendSignal::Confidence => Some(2),
        RetrievalBlendSignal::Gravity => Some(3),
    }
}

fn observe_retrieval_blend_run(
    data_window: &mut RetrievalBlendWeightDataWindow,
    record: &RetrievalRunRecord,
) {
    data_window.run_count = data_window.run_count.saturating_add(1);
    data_window.started_at_min = Some(
        data_window
            .started_at_min
            .map_or(record.started_at, |current| current.min(record.started_at)),
    );
    data_window.started_at_max = Some(
        data_window
            .started_at_max
            .map_or(record.started_at, |current| current.max(record.started_at)),
    );
}

fn observe_retrieval_blend_outcome(
    data_window: &mut RetrievalBlendWeightDataWindow,
    record: &RetrievalOutcomeRecord,
) {
    data_window.outcome_count = data_window.outcome_count.saturating_add(1);
    data_window.outcome_updated_at_min = Some(
        data_window
            .outcome_updated_at_min
            .map_or(record.updated_at, |current| current.min(record.updated_at)),
    );
    data_window.outcome_updated_at_max = Some(
        data_window
            .outcome_updated_at_max
            .map_or(record.updated_at, |current| current.max(record.updated_at)),
    );
}

pub(super) fn apply_retrieval_blend_weight_update(
    previous: RetrievalBlendWeights,
    gradient: [f64; 4],
    learning_rate: f32,
    reward_count: usize,
) -> Result<RetrievalBlendWeights> {
    let reward_scale = reward_count.max(1) as f64;
    let learning_rate = f64::from(learning_rate);
    let mut next = [
        f64::from(previous.recency) + learning_rate * gradient[0] / reward_scale,
        f64::from(previous.salience) + learning_rate * gradient[1] / reward_scale,
        f64::from(previous.confidence) + learning_rate * gradient[2] / reward_scale,
        f64::from(previous.gravity) + learning_rate * gradient[3] / reward_scale,
    ];
    for value in &mut next {
        if !value.is_finite() {
            return Err(Error::InvalidConfig(
                "retrieval blend tuning produced non-finite weight".to_owned(),
            ));
        }
        *value = value.max(0.0);
    }
    let sum = next.iter().sum::<f64>();
    if sum <= f64::EPSILON {
        return previous.normalized();
    }
    RetrievalBlendWeights::new(
        (next[0] / sum) as f32,
        (next[1] / sum) as f32,
        (next[2] / sum) as f32,
        (next[3] / sum) as f32,
    )
    .normalized()
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
