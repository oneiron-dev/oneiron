//! Outer context-pack driver: the HyDE assess/retry loop, telemetry write, and validation helpers.

use super::super::budget::context_pack_evidence_abstains;
use super::super::builder::PipelineBuilder;
use super::super::support::normalize_range;
use super::super::trace::{merge_retrieval_diagnostics, telemetry_score_breakdown};
use super::super::types::{FacetMode, PipelineOutput, ScoredEntity};
use super::types::HydeAttemptOverrides;
use crate::claim::ClaimBody;
use crate::context_pack::EmptyReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::query_expansion::{
    CompletionCandidate, CompletionRequest, EvidenceVerdict, HydeRequest, ground_query,
    normalized_subqueries,
};
use crate::retrieval_quality::{RetrievalDiagnostics, classify_retrieval_quality};
use crate::store::{RetrievalAction, RetrievalRunId, RetrievalRunRecord, RetrievalSignal};
use crate::temporal::{TemporalExpressionParseError, temporal_expression_from_query};
use std::collections::HashMap;
use std::time::Instant;

impl PipelineBuilder<'_> {
    /// Executes the pipeline and returns the detailed [`PipelineOutput`]
    /// the context-pack path consumes (gated scores + the claim bodies the
    /// D19 gate already decoded + the suppression count).
    pub(crate) fn run_for_pack(self) -> Result<PipelineOutput> {
        // Scoped search already denies before counting candidates. Also stop
        // resolved-deny builders before index trust checks, host expansion,
        // or telemetry work; the gate has already validated their request.
        if self
            .authority_filter
            .as_ref()
            .is_some_and(|filter| filter.deny_all)
        {
            return Ok(PipelineOutput {
                // No channel ran: an authority refusal is not a cache failure.
                retrieval_quality: Default::default(),
                scores: Vec::new(),
                claim_bodies: HashMap::new(),
                pending_vectors: Vec::new(),
                claims_suppressed: 0,
                cosine_ghosts_dampened: 0,
                total_in_scope: 0,
                empty_reason: Some(EmptyReason::FilterMatchedNone),
                telemetry_run_id: None,
                signals: Vec::new(),
            });
        }
        if self.ppr_search.is_some() || self.ppr_expand.is_some() {
            crate::config::validate_ppr_vad_alpha(self.vault.config.ppr_vad_alpha)?;
        }
        if self.ppr_expand.is_some() && self.vault.config.ppr_community.beta != 0.0 {
            crate::config::validate_ppr_community(&self.vault.config.ppr_community)?;
        }
        let started = Instant::now();
        let started_at = crate::unix_seconds_now();
        let temporal_now = self.temporal_now.unwrap_or(started_at);
        let occurred_range = self.resolved_occurred_range(temporal_now)?;
        let telemetry_action = self.telemetry_action;
        let mut telemetry_signals = self.telemetry_signals();
        if occurred_range.is_some() && !telemetry_signals.contains(&RetrievalSignal::Temporal) {
            telemetry_signals.push(RetrievalSignal::Temporal);
        }

        // Resolve the rank profile before anything else: an invalid
        // profile is a caller bug and fails closed even when no text
        // search would consume it on this run.
        let bm25_config = match self.rank_profile.as_ref() {
            Some(profile) => profile.to_bm25_config()?,
            None => crate::bm25::Bm25Config::default(),
        };

        // ARCH-0039 facet `prefer` boost is a caller-supplied multiplier
        // (ONE-1117): reject a non-finite or non-positive boost fail-closed
        // here, before any work, in the same spirit as the rank profile above.
        if let Some((_, FacetMode::Prefer { boost })) = self.facet_filter
            && (!boost.is_finite() || boost <= 0.0)
        {
            return Err(Error::InvalidConfig(format!(
                "facet prefer boost must be finite and positive, got {boost}"
            )));
        }

        // Read-side decay overrides are a caller-supplied input seam
        // (ONE-1402): an out-of-range factor is a caller bug and fails
        // closed here, before any channel work, like the boost above.
        validate_access_factor_overrides(self.access_factor_overrides)?;

        // RET-010 rerank knobs fail closed before any channel work, in the
        // same spirit as the rank profile above: an invalid `top_n` or a
        // missing query is a caller bug even when the block would be empty
        // on this run.
        let rerank_query = match self.rerank.as_ref() {
            None => None,
            Some((_, options)) => {
                if options.top_n == 0 {
                    return Err(Error::InvalidConfig(
                        "rerank top_n must be greater than zero".to_owned(),
                    ));
                }
                let query = options
                    .query
                    .as_deref()
                    .or_else(|| self.text_search.as_ref().map(|(query, _)| query.as_str()));
                let Some(query) = query else {
                    return Err(Error::InvalidConfig(
                        "rerank requires a query: set RerankOptions::query or search_text"
                            .to_owned(),
                    ));
                };
                Some(query.to_owned())
            }
        };

        let hyde_expansion = match self.hyde.as_ref() {
            None => None,
            Some((expander, grounding, options)) => {
                if options.channel_limit == 0 {
                    return Err(Error::InvalidConfig(
                        "hyde channel_limit must be greater than zero".to_owned(),
                    ));
                }
                let Some((template, _)) = self.text_search.as_ref() else {
                    return Err(Error::InvalidConfig(
                        "hyde requires search_text query".to_owned(),
                    ));
                };
                let query = ground_query(template, grounding)?;
                let expansion = expander.expand(&HydeRequest {
                    query,
                    max_subqueries: crate::query_expansion::HYDE_MAX_SUBQUERIES,
                })?;
                if expansion.embedding.is_empty() {
                    return Err(Error::InvalidConfig(
                        "hyde embedding must not be empty".to_owned(),
                    ));
                }
                if expansion.embedding.len() != self.vault.config.dimensions
                    && self.vault.config.fast_dims.map(usize::from)
                        != Some(expansion.embedding.len())
                {
                    return Err(Error::DimensionMismatch {
                        expected: self.vault.config.dimensions,
                        got: expansion.embedding.len(),
                    });
                }
                if let Some(error) = Error::invalid_vector_component(&expansion.embedding) {
                    return Err(error);
                }
                Some(expansion)
            }
        };

        if self.text_search.is_some() {
            self.vault.ensure_text_index_trusted()?;
        }

        let recency = if self.temporal_search.is_none() && self.recency_blend_enabled {
            Some(temporal_now)
        } else {
            None
        };
        // ONE-1402: read-side decay ages every claim against the run's
        // resolved clock, so EVERY run is time-dependent scoring now — not
        // only the ones that blend recency or search temporally. An
        // explicitly supplied `temporal_now` is therefore always part of
        // the fork's canonical input snapshot; two replays that differ
        // only in that clock score differently and must not collide on one
        // fork hash. An implicit wall clock stays unhashed, as pinned.
        let explicit_time_dependent_now = self.temporal_now;

        let attempt = self.run_retrieval_txn_attempt(
            occurred_range,
            &bm25_config,
            rerank_query.as_deref(),
            hyde_expansion.as_ref(),
            temporal_now,
            recency,
            explicit_time_dependent_now,
            HydeAttemptOverrides {
                widen_channel_limits: false,
                extra_text_queries: &[],
                skip_ret01_abstain: self.hyde.is_some(),
            },
        )?;
        // Preserve the pre-HyDE no-channel fast path: it returns no run row.
        if self.hyde.is_none() && attempt.early_empty_no_telemetry {
            return Ok(PipelineOutput {
                retrieval_quality: classify_retrieval_quality(&attempt.diagnostics),
                scores: Vec::new(),
                claim_bodies: HashMap::new(),
                pending_vectors: Vec::new(),
                claims_suppressed: 0,
                cosine_ghosts_dampened: 0,
                total_in_scope: 0,
                empty_reason: None,
                telemetry_run_id: None,
                signals: telemetry_signals,
            });
        }
        let mut diagnostics = attempt.diagnostics;
        let mut ppr_expand_executed = attempt.ppr_expand_executed;
        let mut scores = attempt.scores;
        let mut pending_vectors = attempt.pending_vectors;
        let mut claim_gate = attempt.claim_gate;
        let deferred_ppr_cache_writes = attempt.deferred_ppr_cache_writes;
        let mut cosine_ghosts_dampened = attempt.cosine_ghosts_dampened;
        let mut total_in_scope = attempt.total_in_scope;
        let mut empty_reason = attempt.empty_reason;
        let mut signal_components = attempt.signal_components;
        let mut blend_components = attempt.blend_components;
        let mut access_factors = attempt.access_factors;
        let mut rerank_merged_components = attempt.rerank_merged_components;
        let mut retrieval_trace = attempt.retrieval_trace;

        crate::ppr::flush_deferred_ppr_cache_writes(&self.vault.store, &deferred_ppr_cache_writes)?;

        let mut claim_bodies = HashMap::new();
        let mut claims_suppressed = 0_usize;
        for (id, decision) in claim_gate.decisions {
            match decision {
                Some(body) => {
                    claim_bodies.insert(id, body);
                }
                None => claims_suppressed += 1,
            }
        }

        // Host assessment runs only after each read transaction has closed.
        if let (Some((expander, _, options)), Some(expansion)) =
            (self.hyde.as_ref(), hyde_expansion.as_ref())
        {
            let request = |scores: &[ScoredEntity], claims: &HashMap<EntityId, ClaimBody>| {
                CompletionRequest {
                    query: expansion.grounded_query.clone(),
                    candidates: scores
                        .iter()
                        .take(self.result_limit)
                        .map(|scored| CompletionCandidate {
                            id: scored.id,
                            score: scored.score,
                            claim: claims.get(&scored.id).cloned(),
                        })
                        .collect(),
                }
            };
            let verdict = expander.assess_evidence(&request(&scores, &claim_bodies))?;
            let mut second_insufficient = false;
            if matches!(verdict, EvidenceVerdict::Insufficient { .. }) && options.retry_once {
                // Replace every retrieval artifact with the widened fresh transaction.
                let subqueries = normalized_subqueries(&expansion.subqueries);
                let retry = self.run_retrieval_txn_attempt(
                    occurred_range,
                    &bm25_config,
                    rerank_query.as_deref(),
                    hyde_expansion.as_ref(),
                    temporal_now,
                    recency,
                    explicit_time_dependent_now,
                    HydeAttemptOverrides {
                        widen_channel_limits: true,
                        extra_text_queries: &subqueries,
                        skip_ret01_abstain: true,
                    },
                )?;
                crate::ppr::flush_deferred_ppr_cache_writes(
                    &self.vault.store,
                    &retry.deferred_ppr_cache_writes,
                )?;
                // A retry cache hit must not erase an earlier miss in this run.
                merge_retrieval_diagnostics(&mut diagnostics, retry.diagnostics);
                scores = retry.scores;
                pending_vectors = retry.pending_vectors;
                claim_gate = retry.claim_gate;
                cosine_ghosts_dampened = retry.cosine_ghosts_dampened;
                total_in_scope = retry.total_in_scope;
                empty_reason = retry.empty_reason;
                signal_components = retry.signal_components;
                blend_components = retry.blend_components;
                access_factors = retry.access_factors;
                rerank_merged_components = retry.rerank_merged_components;
                retrieval_trace = retry.retrieval_trace;
                ppr_expand_executed = retry.ppr_expand_executed;
                claim_bodies.clear();
                claims_suppressed = 0;
                for (id, decision) in &claim_gate.decisions {
                    match decision {
                        Some(body) => {
                            claim_bodies.insert(*id, body.clone());
                        }
                        None => claims_suppressed += 1,
                    }
                }
                second_insufficient = matches!(
                    expander.assess_evidence(&request(&scores, &claim_bodies))?,
                    EvidenceVerdict::Insufficient { .. }
                );
            }
            let abstain = second_insufficient
                || (matches!(verdict, EvidenceVerdict::Insufficient { .. }) && !options.retry_once)
                || (self.context_pack_budget.is_some()
                    && context_pack_evidence_abstains(
                        &scores,
                        &signal_components,
                        self.text_search.as_ref().map(|(query, _)| query.as_str()),
                        self.vector_search.is_some() || hyde_expansion.is_some(),
                    ));
            if abstain {
                scores.clear();
                pending_vectors.clear();
                retrieval_trace = None;
                empty_reason = Some(EmptyReason::BelowThreshold);
            }
        }

        let score_breakdown = telemetry_score_breakdown(
            &scores,
            &signal_components,
            rerank_merged_components
                .as_ref()
                .unwrap_or(&blend_components),
            &access_factors,
        );
        let ppr_search_executed = self
            .ppr_search
            .as_ref()
            .is_some_and(|(seeds, _)| !seeds.is_empty());
        if !ppr_search_executed && self.ppr_expand.is_some() && !ppr_expand_executed {
            telemetry_signals.retain(|signal| *signal != RetrievalSignal::Ppr);
        }
        let retrieval_quality = classify_retrieval_quality(&diagnostics);
        let run_id = RetrievalRunId::now();
        let run_record = RetrievalRunRecord::new(
            run_id,
            telemetry_action,
            started_at,
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            telemetry_signals.clone(),
            score_breakdown,
            total_in_scope,
            claims_suppressed,
            empty_reason.map(|reason| format!("{reason:?}")),
        )
        .with_trace(retrieval_trace)
        .with_quality(&retrieval_quality);
        // ONE-1728 K10: a retrieval issued inside a room registers through the
        // room's door, which writes under the route the run captured — into
        // the room's overlay `VaultMeta` while it is off record (so the base
        // telemetry ledger gains ZERO rows from an OffRecord session, and the
        // row evaporates at close), and under that route's refusal once the
        // room has flipped. Canonical entries carry `None` and take the
        // unchanged base path.
        let provisional = telemetry_action == RetrievalAction::ContextPack;
        let write_result = match self.session {
            Some(session) => session.register_run(&run_record, provisional),
            None if provisional => self
                .vault
                .store
                .record_context_pack_provisional_retrieval_run(&run_record),
            None => self.vault.store.record_retrieval_run(&run_record),
        };
        let telemetry_run_id = match write_result {
            Ok(()) => Some(run_id),
            // A retrieval the caller declared to be INSIDE a room owns its
            // registration. Off record the run row is what close consumes, so
            // swallowing the failure would return a successful retrieval whose
            // durable run is absent from the session-local close set — the one
            // outcome the settle contract forbids outright. On record the room
            // is also the half that can refuse for a STALE ROUTE, and a K10
            // refusal warned past is the same log-and-continue wearing a
            // different hat. Only a CANONICAL entry — no room at all — keeps
            // the best-effort posture: an ordinary retrieval that loses its
            // telemetry row loses nothing its caller depends on.
            Err(error) if self.session.is_some() => return Err(error),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "retrieval telemetry run write failed; continuing retrieval"
                );
                None
            }
        };

        Ok(PipelineOutput {
            retrieval_quality,
            scores,
            claim_bodies,
            pending_vectors,
            claims_suppressed,
            cosine_ghosts_dampened,
            total_in_scope,
            empty_reason,
            telemetry_run_id,
            signals: telemetry_signals,
        })
    }

    // Requested operations, not the legacy signal list: time filters and
    // recency blending do not constitute a Temporal search. Empty inputs still
    // reach their channel operation and may complete with zero candidates.
    pub(super) fn retrieval_diagnostics(&self) -> RetrievalDiagnostics {
        let mut diagnostics = RetrievalDiagnostics::default();
        for (requested, signal) in [
            (self.vector_search.is_some(), RetrievalSignal::Vector),
            (self.text_search.is_some(), RetrievalSignal::Text),
            (self.phonetic_search.is_some(), RetrievalSignal::Phonetic),
            (self.temporal_search.is_some(), RetrievalSignal::Temporal),
            (
                self.ppr_search.is_some() || self.ppr_expand.is_some(),
                RetrievalSignal::Ppr,
            ),
        ] {
            if requested {
                diagnostics.attempted.push(signal);
            }
        }
        diagnostics
    }

    pub(super) fn telemetry_signals(&self) -> Vec<RetrievalSignal> {
        let mut signals = Vec::new();
        if self.vector_search.is_some() {
            signals.push(RetrievalSignal::Vector);
        }
        if self.text_search.is_some() {
            signals.push(RetrievalSignal::Text);
        }
        if self.hyde.is_some() {
            signals.push(RetrievalSignal::Hyde);
        }
        if self
            .phonetic_search
            .as_ref()
            .is_some_and(|codes| !codes.is_empty())
        {
            signals.push(RetrievalSignal::Phonetic);
        }
        if self.temporal_search.is_some() {
            signals.push(RetrievalSignal::Temporal);
        }
        if self
            .ppr_search
            .as_ref()
            .is_some_and(|(seeds, _)| !seeds.is_empty())
            || self.ppr_expand.is_some()
        {
            signals.push(RetrievalSignal::Ppr);
        }
        signals
    }

    pub(super) fn no_data_fallback_eligible(&self) -> bool {
        self.vector_search
            .as_ref()
            .is_some_and(|(_, limit)| *limit > 0)
            || self
                .text_search
                .as_ref()
                .is_some_and(|(_, limit)| *limit > 0)
            || self
                .phonetic_search
                .as_ref()
                .is_some_and(|codes| !codes.is_empty())
            || self
                .temporal_search
                .as_ref()
                .is_some_and(|config| config.limit > 0)
            || self
                .ppr_search
                .as_ref()
                .is_some_and(|(seeds, _)| !seeds.is_empty())
            || self
                .ppr_expand
                .as_ref()
                .is_some_and(|(seeds, _)| !seeds.is_empty())
    }

    fn resolved_occurred_range(&self, now: u64) -> Result<Option<(u64, u64)>> {
        if self.occurred_range.is_some() || self.temporal_search.is_some() {
            return Ok(self.occurred_range);
        }

        let Some((query, _)) = self.text_search.as_ref() else {
            return Ok(None);
        };

        temporal_expression_from_query(query)
            .map(|expression| expression.map(|expression| expression.resolve(now)))
            .map(|range| range.map(|range| normalize_range(range.start, range.end)))
            .map_err(invalid_temporal_expression)
    }
}

fn invalid_temporal_expression(error: TemporalExpressionParseError) -> Error {
    Error::InvalidTemporalExpression(error)
}

/// Fail-closed admission of the caller's per-entity read-side decay
/// overrides. The offending entry is chosen by id order so the rejection
/// message does not depend on map iteration order.
fn validate_access_factor_overrides(overrides: Option<&HashMap<EntityId, f32>>) -> Result<()> {
    let Some(overrides) = overrides else {
        return Ok(());
    };

    let invalid = overrides
        .iter()
        .filter(|(_, factor)| !crate::claim::access_factor_override_valid(**factor))
        .min_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    if let Some((_, factor)) = invalid {
        return Err(Error::InvalidConfig(format!(
            "access factor override must be finite and within [0, 1], got {factor}"
        )));
    }

    Ok(())
}
