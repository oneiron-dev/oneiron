//! Policy-guided attempts; every attempt keeps the pipeline's existing gates.

use super::types::{HydeAttemptOverrides, RetrievalTxnOutput};
use crate::bm25::Bm25Config;
use crate::context_pack::EmptyReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::PipelineBuilder;
use crate::pipeline::retrieval_policy::{
    RetrievalIntent, RetrievalPolicyAction, RetrievalPolicyChoices, RetrievalPolicyDecision,
    RetrievalPolicyEnvelope, RetrievalPolicyTier, RetrievalPolicyTrace, choose_action,
};
use crate::pipeline::support::{read_entity_metadata, resolve_sigma_secs};
use crate::pipeline::trace::{merge_retrieval_diagnostics, telemetry_score_breakdown};
use crate::store::RetrievalState;
use std::collections::HashSet;

impl PipelineBuilder<'_> {
    #[expect(clippy::too_many_arguments)]
    pub(super) fn run_retrieval_policy_attempts(
        &mut self,
        occurred_range: Option<(u64, u64)>,
        bm25_config: &Bm25Config,
        rerank_query: Option<&str>,
        hyde_expansion: Option<&crate::query_expansion::HydeExpansion>,
        temporal_now: u64,
        recency: Option<u64>,
        explicit_time_dependent_now: Option<u64>,
        overrides: HydeAttemptOverrides<'_>,
    ) -> Result<(RetrievalTxnOutput, Option<RetrievalPolicyTrace>)> {
        let Some(mut options) = self.retrieval_policy else {
            return self
                .run_retrieval_txn_attempt(
                    occurred_range,
                    bm25_config,
                    rerank_query,
                    hyde_expansion,
                    temporal_now,
                    recency,
                    explicit_time_dependent_now,
                    overrides,
                )
                .map(|attempt| (attempt, None));
        };
        if options.intent == RetrievalIntent::Unknown
            && let Some((query, _)) = &self.text_search
        {
            options.intent = RetrievalIntent::classify(query);
        }
        let envelope = RetrievalPolicyEnvelope::for_effort(options.effort);
        let posterior = if options.bandit_enabled {
            self.vault.store.retrieval_policy_posterior()?
        } else {
            Default::default()
        };
        let mut explicit_seeds = Vec::new();
        for (seeds, _) in self
            .ppr_search
            .take()
            .into_iter()
            .chain(self.ppr_expand.take())
        {
            explicit_seeds.extend(seeds);
        }
        explicit_seeds.sort_unstable();
        explicit_seeds.dedup();
        explicit_seeds.truncate(crate::ppr::MAX_PPR_SEEDS);
        // Disable the channel's internal adaptive loop: each widening is now
        // one policy decision. Hard occurred/learned/since filters never change.
        let temporal_allowed = self.temporal_search.as_mut().is_some_and(|config| {
            let allowed = config.adaptive;
            config.adaptive = false;
            allowed
        });
        let mut state = self.retrieval_state.clone().unwrap_or_default();
        state.iteration = 0;
        state.hops = 0;
        state.last_action = 0;
        state.intent_class = options.intent as u8;
        state.budget_remaining = envelope.max_steps;
        let mut trace = RetrievalPolicyTrace {
            identity: options.identity,
            envelope,
            bandit_enabled: options.bandit_enabled,
            decisions: vec![RetrievalPolicyDecision {
                state,
                action: RetrievalPolicyAction::Search,
                tier: RetrievalPolicyTier::Seed,
            }],
        };
        let mut seen = HashSet::new();
        let mut iteration = 0_u8;
        let mut hops = 0_u8;
        let mut temporal_round = 1_u8;
        let mut last_action = RetrievalPolicyAction::Search;
        let mut previous_diagnostics = None;
        let mut expanded = false;
        let mut cache_writes = Vec::new();
        let mut rng = rand::thread_rng();
        loop {
            let mut attempt = self.run_retrieval_txn_attempt(
                occurred_range,
                bm25_config,
                rerank_query,
                hyde_expansion,
                temporal_now,
                recency,
                explicit_time_dependent_now,
                overrides,
            )?;
            if let Some(mut previous) = previous_diagnostics.take() {
                merge_retrieval_diagnostics(&mut previous, attempt.diagnostics);
                attempt.diagnostics = previous;
            }
            expanded |= attempt.ppr_expand_executed;
            cache_writes.append(&mut attempt.deferred_ppr_cache_writes);
            let breakdown = telemetry_score_breakdown(
                &attempt.scores,
                &attempt.signal_components,
                attempt
                    .rerank_merged_components
                    .as_ref()
                    .unwrap_or(&attempt.blend_components),
                &attempt.access_factors,
            );
            let mut state = RetrievalState::one_shot(&breakdown);
            state.iteration = iteration;
            state.hops = hops;
            state.last_action = last_action as u8;
            state.intent_class = options.intent as u8;
            state.budget_remaining = if self.deadline_reached() {
                0
            } else {
                envelope.max_steps.saturating_sub(iteration)
            };
            state.novelty_vs_prior = if attempt.scores.is_empty() {
                0.0
            } else {
                attempt
                    .scores
                    .iter()
                    .filter(|score| !seen.contains(&score.id))
                    .count() as f32
                    / attempt.scores.len() as f32
            };
            if !explicit_seeds.is_empty() {
                state.entity_coverage = explicit_seeds
                    .iter()
                    .filter(|id| attempt.scores.iter().any(|score| score.id == **id))
                    .count() as f32
                    / explicit_seeds.len() as f32;
            }
            // Only already-admitted result metadata contributes temporal features.
            let txn = self.vault.store.env.read_txn()?;
            let mut start = u64::MAX;
            let mut end = 0;
            for scored in &attempt.scores {
                if let Some(meta) = read_entity_metadata(&self.read, &txn, &scored.id)? {
                    start = start.min(meta.occurred_start);
                    end = end.max(meta.occurred_end);
                }
            }
            drop(txn);
            state.temporal_spread = end.saturating_sub(start) as f32;
            let choices = RetrievalPolicyChoices {
                expand: state.budget_remaining > 0
                    && hops < envelope.max_hops
                    && (!attempt.scores.is_empty() || !explicit_seeds.is_empty())
                    && (last_action != RetrievalPolicyAction::Expand
                        || state.novelty_vs_prior > 0.0),
                widen_temporal: state.budget_remaining > 0
                    && hops == 0
                    && temporal_allowed
                    && temporal_round < envelope.temporal_rounds,
            };
            let decision = choose_action(&posterior, options, &state, choices, &mut rng)?;
            let action = decision.action;
            trace.decisions.push(decision);
            match action {
                RetrievalPolicyAction::Stop | RetrievalPolicyAction::Abstain => {
                    if action == RetrievalPolicyAction::Abstain {
                        attempt.scores.clear();
                        attempt.cited_messages.clear();
                        attempt.capabilities.clear();
                        attempt.pending_vectors.clear();
                        attempt.retrieval_trace = None;
                        attempt.empty_reason = Some(EmptyReason::BelowThreshold);
                    }
                    attempt.early_empty_no_telemetry = false;
                    attempt.deferred_ppr_cache_writes = cache_writes;
                    attempt.ppr_expand_executed = expanded;
                    self.retrieval_state = Some(state);
                    trace.validate()?;
                    if let Some(inputs) = attempt.replay_inputs.as_mut() {
                        inputs.config["retrieval_policy"] =
                            serde_json::to_value(&trace).map_err(|_| {
                                Error::InvariantViolation("retrieval policy replay encode")
                            })?;
                    }
                    return Ok((attempt, Some(trace)));
                }
                RetrievalPolicyAction::Expand => {
                    // One graph step from the admitted working set, not an
                    // ever-deeper rerun from an unfiltered raw candidate set.
                    crate::config::validate_ppr_vad_alpha(self.vault.config.ppr_vad_alpha)?;
                    if self.vault.config.ppr_community.beta != 0.0 {
                        crate::config::validate_ppr_community(&self.vault.config.ppr_community)?;
                    }
                    let mut seeds: Vec<EntityId> =
                        attempt.scores.iter().map(|score| score.id).collect();
                    seeds.extend_from_slice(&explicit_seeds);
                    seeds.sort_unstable();
                    seeds.dedup();
                    seeds.truncate(crate::ppr::MAX_PPR_SEEDS);
                    self.ppr_expand = Some((seeds, 1));
                    hops += 1;
                }
                RetrievalPolicyAction::WidenTemporal => {
                    if let Some(config) = self.temporal_search.as_mut() {
                        config.sigma_secs = resolve_sigma_secs(config.sigma_secs)
                            .saturating_mul(2)
                            .max(1);
                    }
                    temporal_round += 1;
                }
                RetrievalPolicyAction::Search => {
                    unreachable!("Search is the initial policy action")
                }
            }
            seen.extend(attempt.scores.iter().map(|score| score.id));
            previous_diagnostics = Some(attempt.diagnostics);
            iteration += 1;
            last_action = action;
            // Do not repeat an expansion during a later temporal-only step.
            if action != RetrievalPolicyAction::Expand {
                self.ppr_expand = None;
            }
        }
    }
}
