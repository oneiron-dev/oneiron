//! Vault text and vector search, batch and query builders, and retrieval telemetry.

use super::Vault;
use super::doctor_manifest::{TextIndexStatus, read_text_schema_version};
use crate::batch::TxnBatchBuilder;
use crate::error::{Error, Result};
use crate::pipeline::{RetrievalWithTelemetry, ScoredEntity};
use crate::store::{
    GateDecisionRecord, PendingGateConsentGroup, PendingGateConsentRecord, RetrievalAction,
    RetrievalBlendTuningConfig, RetrievalBlendWeightTableEntry, RetrievalOutcome,
    RetrievalOutcomeRecord, RetrievalRunId, RetrievalRunRecord, RetrievalScoreBreakdown,
    RetrievalScoreComponent, RetrievalSignal, RetrievalTrace, RetrievalTraceForkHash,
};
use crate::{BatchBuilder, ContextPackBuilder, PipelineBuilder, bm25, unix_seconds_now};
use std::time::Instant;

/// One scored search plus the timing its telemetry row is built from.
pub(crate) struct TimedSearch {
    pub(crate) scores: Vec<ScoredEntity>,
    pub(crate) started_at: u64,
    pub(crate) started: Instant,
}

fn vault_search_score_breakdown(
    signal: RetrievalSignal,
    results: &[ScoredEntity],
) -> Vec<RetrievalScoreBreakdown> {
    results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            let rank = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
            RetrievalScoreBreakdown {
                result_id: *result.id.as_bytes(),
                final_rank: rank,
                final_score: result.score,
                components: vec![RetrievalScoreComponent {
                    signal,
                    rank,
                    score: result.score,
                }],
                // Direct single-signal search: no blend ran, so no
                // read-side multiplier was ever applied to this score.
                access_factor: None,
            }
        })
        .collect()
}

impl Vault {
    // NOTE (ONE-1133): the bare non-txn `purge_entity_active_store` wrapper
    // was removed — both sync replay surfaces now route through the
    // reason-aware `apply_replayed_tombstone`, and a bare purge entry point
    // would be an invitation to bypass the ARCH-0038 reason semantics.

    // -----------------------------------------------------------------
    // ARCH-0050 R6 L2 code-memory doors (ONE-1608).
    //
    // Every wrapper here opens ONE transaction, delegates to the internal
    // `crate::code_memory` implementation, and commits exactly once on
    // success. None exposes `Store`, `RoTxn`, or `RwTxn`; the public
    // contract suite reaches only these methods.
    // -----------------------------------------------------------------

    // Read/write/list helpers intentionally remain behind `feature = "sync"`
    // instead of `cfg(test)` because the sync bridge regression suite is an
    // integration test crate. Production bridge code still uses direct
    // transactional `sync_state` access when multiple keys must update
    // atomically.

    // ─── Tree Query API ───────────────────────────────────────

    /// Internal guard: read paths over the text index must refuse to score
    /// when the analyzer-manifest handshake was bypassed on a populated
    /// index. See the docstring on `Vault::text_index_trusted`.
    pub(crate) fn ensure_text_index_trusted(&self) -> Result<()> {
        if self
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Ok(())
        } else {
            Err(Error::CorruptedIndex(
                "text index handshake bypassed on populated index",
            ))
        }
    }

    /// Current text-index status. `analyzer_manifest` reflects the analyzer
    /// this vault was opened with; `schema_version` and `total_docs` reflect
    /// what was persisted by prior writes.
    pub fn text_index_status(&self) -> Result<TextIndexStatus> {
        let rtxn = self.store.env.read_txn()?;
        let total_docs = bm25::read_total_docs(&self.store, &rtxn)?;
        let schema_version = read_text_schema_version(&self.store, &rtxn)?;
        Ok(TextIndexStatus {
            total_docs,
            schema_version,
            analyzer_manifest: self.analyzer.manifest(),
        })
    }

    /// Returns BM25 text matches for a query under the contract-default
    /// rank profile.
    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        Ok(self.search_text_with_telemetry(query, limit)?.value)
    }

    /// Returns BM25 text matches and the retrieval telemetry run id when the
    /// best-effort telemetry row was persisted.
    pub fn search_text_with_telemetry(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        self.search_text_with_profile_and_telemetry(
            query,
            limit,
            &crate::config::Bm25RankProfile::default(),
        )
    }

    /// Returns BM25 text matches for a query under a caller-supplied
    /// scoring-only rank profile (ARCH-0031: Okapi vs `Plus { delta }`,
    /// per-channel weight / `b`). The profile never touches the on-disk
    /// index or the open-time manifest handshake — changing it does not
    /// require a reindex. Invalid profiles fail closed with
    /// [`crate::Error::InvalidRankProfile`].
    pub fn search_text_with_profile(
        &self,
        query: &str,
        limit: usize,
        profile: &crate::config::Bm25RankProfile,
    ) -> Result<Vec<ScoredEntity>> {
        Ok(self
            .search_text_with_profile_and_telemetry(query, limit, profile)?
            .value)
    }

    /// Returns BM25 text matches for a caller-supplied profile and the
    /// retrieval telemetry run id when the best-effort telemetry row was
    /// persisted.
    pub fn search_text_with_profile_and_telemetry(
        &self,
        query: &str,
        limit: usize,
        profile: &crate::config::Bm25RankProfile,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        let results = self.search_text_scored(&self.store, query, limit, profile)?;
        let run_id = self.record_vault_search_retrieval_run(
            RetrievalSignal::Text,
            results.started_at,
            results.started,
            &results.scores,
            limit,
        );
        Ok(RetrievalWithTelemetry {
            retrieval_quality: crate::retrieval_quality::classify_retrieval_quality(
                &crate::retrieval_quality::RetrievalDiagnostics {
                    attempted: vec![RetrievalSignal::Text],
                    succeeded: vec![RetrievalSignal::Text],
                    ..Default::default()
                },
            ),
            value: results.scores,
            run_id,
        })
    }

    /// Scores one BM25 search against `target` and returns the scores plus the
    /// timing the telemetry row needs.
    ///
    /// `target` is `&Store` on the canonical path and a `SessionStoreView` on
    /// the session path (ONE-1728 §7), so an in-room search scores over
    /// overlay ∪ base through the SAME body — the two cannot drift in
    /// scoring, and canonical output stays byte-identical.
    pub(crate) fn search_text_scored(
        &self,
        target: &impl crate::store::ManifestDbs,
        query: &str,
        limit: usize,
        profile: &crate::config::Bm25RankProfile,
    ) -> Result<TimedSearch> {
        let config = profile.to_bm25_config()?;
        self.ensure_text_index_trusted()?;
        let started_at = unix_seconds_now();
        let started = Instant::now();
        let scores = {
            let rtxn = self.store.env.read_txn()?;
            bm25::search_text(target, &rtxn, &self.analyzer, &config, query, limit)?
        };
        Ok(TimedSearch {
            scores,
            started_at,
            started,
        })
    }

    /// Builds the `VaultSearch` telemetry row for one search.
    ///
    /// Shared with the session path so an in-room search's row carries the
    /// identical shape; only where it LANDS differs (K10).
    pub(crate) fn vault_search_retrieval_run_record(
        signal: RetrievalSignal,
        started_at: u64,
        started: Instant,
        results: &[ScoredEntity],
        limit: usize,
    ) -> RetrievalRunRecord {
        RetrievalRunRecord::new(
            RetrievalRunId::now(),
            RetrievalAction::VaultSearch,
            started_at,
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            vec![signal],
            vault_search_score_breakdown(signal, results),
            results.len(),
            0,
            (limit > 0 && results.is_empty()).then(|| "NoData".to_owned()),
        )
    }

    pub(super) fn record_vault_search_retrieval_run(
        &self,
        signal: RetrievalSignal,
        started_at: u64,
        started: Instant,
        results: &[ScoredEntity],
        limit: usize,
    ) -> Option<RetrievalRunId> {
        let record =
            Self::vault_search_retrieval_run_record(signal, started_at, started, results, limit);
        let run_id = record.run_id;
        if let Err(error) = self.store.record_retrieval_run(&record) {
            tracing::warn!(
                ?error,
                "vault search retrieval telemetry write failed; continuing retrieval"
            );
            None
        } else {
            Some(run_id)
        }
    }

    /// Creates a new write batch builder bound to this vault.
    pub fn batch(&self) -> BatchBuilder<'_> {
        BatchBuilder::new(self)
    }

    /// Creates a batch builder that writes into an externally-owned transaction.
    ///
    /// Call `.apply(wtxn)` to execute writes without committing.
    /// Use with `with_write_txn()` for atomic multi-operation writes (e.g. entity + pm marker).
    pub fn batch_in(&self) -> TxnBatchBuilder<'_> {
        TxnBatchBuilder::new(self)
    }

    /// Creates a query pipeline builder for multi-signal retrieval.
    ///
    /// This unbound builder carries no executing principal. ActiveSet reads
    /// require [`Vault::query_for_execution`] and otherwise fail closed.
    pub fn query(&self) -> PipelineBuilder<'_> {
        PipelineBuilder::new(self)
    }

    /// Creates a pipeline bound to an existing host-owned execution capability.
    ///
    /// The host passes its dispatcher, not an actor id supplied by a guest.
    /// ActiveSet selections must name that dispatcher's actor. A foreign-vault
    /// or session-bound dispatcher is refused: this door reads the canonical
    /// vault only, not a session's composed view.
    pub fn query_for_execution(
        &self,
        execution: &crate::code_run::HostSelfDispatcher<'_>,
    ) -> Result<PipelineBuilder<'_>> {
        PipelineBuilder::for_execution(self, execution)
    }

    /// Creates a context pack builder for retrieval + hydration + serialization.
    pub fn context_pack(&self) -> ContextPackBuilder<'_> {
        ContextPackBuilder::new(self)
    }

    /// Returns the newest retrieval telemetry run rows, newest first.
    pub fn retrieval_runs(&self, limit: usize) -> Result<Vec<RetrievalRunRecord>> {
        self.store.retrieval_runs(limit)
    }

    /// Returns one published retrieval telemetry row by id.
    pub fn retrieval_run(&self, run_id: RetrievalRunId) -> Result<Option<RetrievalRunRecord>> {
        self.store.retrieval_run(run_id)
    }

    /// Returns the published trace keyed by a content-addressed fork hash.
    pub fn retrieval_trace_by_fork_hash(
        &self,
        fork_hash: RetrievalTraceForkHash,
    ) -> Result<Option<RetrievalTrace>> {
        self.store.retrieval_trace_by_fork_hash(fork_hash)
    }

    /// Returns the active RET-010 retrieval-blend weight table entry.
    pub fn retrieval_blend_weight_table(&self) -> Result<RetrievalBlendWeightTableEntry> {
        self.store.retrieval_blend_weight_table()
    }

    /// Tunes and persists the active RET-010 retrieval-blend weight table
    /// from persisted retrieval rewards.
    pub fn tune_retrieval_blend_weights(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        self.store.tune_retrieval_blend_weights(config)
    }

    /// Idempotently writes or replaces a retrieval outcome row for one run.
    pub fn record_retrieval_outcome(&self, outcome: RetrievalOutcome) -> Result<()> {
        self.store.record_retrieval_outcome(outcome)
    }

    /// Returns outcome rows recorded for `run_id`, sorted by outcome key.
    pub fn retrieval_outcomes(
        &self,
        run_id: RetrievalRunId,
    ) -> Result<Vec<RetrievalOutcomeRecord>> {
        self.store.retrieval_outcomes(run_id)
    }

    /// Returns pending Gate consent proposals ordered by their write decision.
    pub fn pending_gate_consents(&self, limit: usize) -> Result<Vec<PendingGateConsentRecord>> {
        self.store.pending_gate_consents(limit)
    }

    /// Returns recent Gate decisions ordered from newest to oldest.
    pub fn gate_decisions(&self, limit: usize) -> Result<Vec<GateDecisionRecord>> {
        self.store.gate_decisions(limit)
    }

    /// Checks whether the active Gate policy has an actor-ceiling row for an actor.
    pub fn gate_actor_ceiling_exists(&self, actor_class: &str, actor_ref: &str) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &rtxn)?;
        Ok(policy.has_matching_actor_ceiling(actor_class, Some(actor_ref)))
    }

    /// Returns pending Gate consent proposals grouped by Dreamer run id.
    ///
    /// Proposals without a Dreamer run id are returned in the default lane,
    /// represented by a group with `dreamer_run_id == None`.
    pub fn pending_gate_consent_groups(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentGroup>> {
        self.store.pending_gate_consent_groups(limit)
    }
}
