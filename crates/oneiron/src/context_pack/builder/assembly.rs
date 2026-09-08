//! Executing a configured builder: the retrieval run, hydration, validation, and every run_* terminal.

use std::collections::HashSet;
use std::time::Instant;

use crate::disclosure::DisclosureMode;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::{RetrievalWithTelemetry, WorldScope};
use crate::serialize::{SerializeConfig, serialize_pack_with_telemetry};

use super::super::edge_walk::{EdgeWalkOptions, EdgeWalkResult, load_entity_edges, walk_edges};
use super::super::empty_pack::{
    context_pack_empty_reason, dedupe_signals, empty_context, pack_signal_from_retrieval,
    serialized_context_pack_empty_reason,
};
use super::super::hydration::hydrate_entity;
use super::super::psych_mirror::{PsychProfilePackSection, psych_profile_pack_section};
use super::super::quarantine::load_pack_quarantine_index;
use super::super::telemetry::{
    discard_failed_context_pack_telemetry, finalize_context_pack_telemetry,
};
use super::super::types::{ContextPack, ContextPackRetrievalBudget, PackStats};
use super::super::validation::{
    disclosure_admits_candidate, validate_hydrated_pack_entities, validate_pack_disclosure,
    validate_pack_edge_references, validate_pack_entity_reference, validate_scored_candidates,
};
use super::super::world_partition::{
    annotate_stale_federated_worlds, partition_results_by_world, resolve_edge_short_ids,
};
use super::{
    ContextPackBuilder, ContextPackRun, ContextPackTelemetry, HydrateOptions,
    SerializedContextPack, UnfinalizedContextPack,
};

impl<'a> ContextPackBuilder<'a> {
    /// Runs retrieval and returns the opt-in stored-profile companion section.
    pub fn run_with_psych_profile(self) -> Result<(ContextPack, Option<PsychProfilePackSection>)> {
        let key = self.psych_profile_key;
        let vault = self.vault;
        let pack = self.run()?;
        let section = key
            .map(|key| psych_profile_pack_section(vault, &key))
            .transpose()?;
        Ok((pack, section))
    }

    pub fn run(self) -> Result<ContextPack> {
        Ok(self.run_with_telemetry()?.value)
    }

    pub fn run_with_telemetry(self) -> Result<RetrievalWithTelemetry<ContextPack>> {
        let run = self.run_unfinalized()?;
        let surfaced_result_ids: Vec<[u8; 16]> = run
            .pack
            .results
            .iter()
            .map(|entity| *entity.id.as_bytes())
            .collect();
        let telemetry_run_id = finalize_context_pack_telemetry(
            run.telemetry,
            run.telemetry_run_id,
            run.pack.stats.query_time_us,
            run.total_in_scope,
            run.pack.stats.claims_suppressed,
            &surfaced_result_ids,
            context_pack_empty_reason(&run.pack, &surfaced_result_ids),
        )?;
        Ok(RetrievalWithTelemetry {
            retrieval_quality: run.pack.retrieval_quality.clone(),
            value: run.pack,
            run_id: telemetry_run_id,
        })
    }

    pub fn run_projected_json_with_telemetry(
        self,
        config: &SerializeConfig,
    ) -> Result<RetrievalWithTelemetry<ContextPack>> {
        Ok(self
            .run_unfinalized_with_telemetry()?
            .finish_projected_json(config))
    }

    /// # Errors
    ///
    /// Refuses an assembly issued INSIDE a room (ONE-1570 Arm B). The deferred
    /// door hands the caller an [`UnfinalizedContextPack`] whose finalize runs
    /// in [`UnfinalizedContextPack::finish_projected_json`], which returns no
    /// `Result` — so a room's failed registration would have nowhere to go but
    /// a warning, and a warning past it is the log-and-continue the settle
    /// contract forbids. A room's assembly takes the finalizing doors, which
    /// can fail.
    pub fn run_unfinalized_with_telemetry(self) -> Result<UnfinalizedContextPack<'a>> {
        if self.session.is_some() {
            return Err(Error::InvalidConfig(
                "a context pack assembled inside an off-record session cannot defer \
                 finalization: the deferred door has no channel for a failed registration"
                    .to_owned(),
            ));
        }
        let run = self.run_unfinalized()?;
        Ok(UnfinalizedContextPack {
            value: run.pack,
            telemetry_run_id: run.telemetry_run_id,
            telemetry: run.telemetry,
            total_in_scope: run.total_in_scope,
            clamped_out: run.clamped_out,
        })
    }

    pub(in crate::context_pack) fn run_unfinalized(self) -> Result<ContextPackRun<'a>> {
        let started = Instant::now();
        let retrieval_budget = self.retrieval_budget.unwrap_or_else(|| {
            ContextPackRetrievalBudget::from_limit(
                self.pipeline.result_limit(),
                self.token_allocation,
                self.selected_edge_budget,
            )
        });
        let selected_edge_budget = retrieval_budget.selected_edges;
        // OF-365: a clamped assembly persists NO retrieval stage trace. The
        // pipeline records per_channel/fused/blended/reranked stages BEFORE
        // the clamp's candidate sweep runs, so a captured trace would retain
        // exactly the ids the clamp removes — absence is the boundary, and
        // suppressing capture is the fail-closed form of scrubbing every
        // stage. OwnerAlone (and no-context) assemblies keep the caller's
        // trace setting unchanged.
        let mut pipeline = self.pipeline;
        if self
            .disclosure
            .as_ref()
            .is_some_and(|ctx| ctx.mode() != DisclosureMode::OwnerAlone)
        {
            pipeline = pipeline.capture_retrieval_trace(false);
        }
        // Captured BEFORE the run, from the same door the pipeline registers
        // the provisional row through, and carried on every outcome — so the
        // finalize and the failure discard both reach the row that was
        // actually written (ONE-1570 Arm B).
        let telemetry = match self.session {
            Some(session) => ContextPackTelemetry::Session(session),
            None => ContextPackTelemetry::Base(&self.vault.store),
        };
        let pipeline_output = pipeline
            .context_pack_budget(retrieval_budget)
            .run_for_pack()?;
        let telemetry_run_id = pipeline_output.telemetry_run_id;
        let result = (|| {
            let total_in_scope = pipeline_output.total_in_scope;
            let pipeline_empty_reason = pipeline_output.empty_reason;
            let retrieval_quality = pipeline_output.retrieval_quality;
            let pipeline_signals = pipeline_output.signals;
            let scored = pipeline_output.scores;
            validate_scored_candidates(&scored)?;
            let claim_bodies = pipeline_output.claim_bodies;
            let mut claims_suppressed = pipeline_output.claims_suppressed;
            let cosine_ghosts_dampened = pipeline_output.cosine_ghosts_dampened;

            let rtxn = self.vault.store.env.read_txn()?;
            let hydrate_result_edges = self.include_edges && self.edge_hop == 0;
            let mut claim_bodies = claim_bodies;
            let quarantine_index = load_pack_quarantine_index(&self.vault.store, &rtxn)?;

            // OF-365 disclosure clamp, enforcement point 1 (candidate sweep,
            // the only point that counts): drop non-admitted scored ids
            // before hydration. Absence is the boundary — a clamped id never
            // reaches hydration, results, or stats.
            let clamp = self.disclosure.as_ref();
            let mut scored = scored;
            let mut clamped_out: u64 = 0;
            if let Some(ctx) = clamp
                && ctx.mode() != DisclosureMode::OwnerAlone
            {
                let mut kept = Vec::with_capacity(scored.len());
                for entry in scored {
                    if disclosure_admits_candidate(
                        &self.vault.store,
                        &rtxn,
                        ctx,
                        &entry.id,
                        &claim_bodies,
                    )? {
                        kept.push(entry);
                    } else {
                        clamped_out = clamped_out.saturating_add(1);
                    }
                }
                scored = kept;
            }
            let surfaced_candidate_count = scored.len();

            let result_options = HydrateOptions {
                hydrate_fields: self.hydrate,
                include_edges: hydrate_result_edges,
                include_vectors: self.include_vectors,
                edge_cache: None,
                claim_bodies: Some(&claim_bodies),
                clamp,
            };
            let mut results = Vec::with_capacity(scored.len());
            for entry in scored.iter().copied() {
                let Some(entity) = hydrate_entity(
                    self.vault,
                    &rtxn,
                    entry.id,
                    entry.score,
                    result_options,
                    &mut claims_suppressed,
                )?
                else {
                    continue;
                };
                results.push(entity);
            }

            // ARCH-0004 / ARCH-0022 world partitioning (ONE-1117): under the
            // default `All` scope, group surviving claims by world — base section
            // first, then one section per non-base world — and cap how much of the
            // claim budget fiction may take. Flat (unchanged) for Base / World(id).
            if matches!(self.world_scope, WorldScope::All) {
                partition_results_by_world(
                    &self.vault.store,
                    &rtxn,
                    &mut results,
                    self.non_base_world_fraction,
                    &claim_bodies,
                )?;
            }

            // ONE-1411: read ONCE per pack run and reused by every stage below
            // — the result marker pass, the neighbor exclusion, and the
            // neighbor marker pass.
            let stale_worlds = crate::federation::stale_stamped_worlds(&self.vault.store, &rtxn)?;

            // Mark whatever world rows survived. Scope-independent by design —
            // the pipeline already dropped stale worlds from `All` and `Base`,
            // so in practice this fires for the explicit scopes that
            // deliberately KEEP a dead world, which are exactly the ones owed
            // the warning.
            annotate_stale_federated_worlds(
                &self.vault.store,
                &rtxn,
                &stale_worlds,
                &mut results,
                &claim_bodies,
            )?;

            for entity in &results {
                validate_pack_entity_reference(
                    &self.vault.store,
                    &rtxn,
                    &entity.id,
                    &mut claim_bodies,
                    &quarantine_index,
                )?;
            }

            let seed_ids: Vec<EntityId> = results.iter().map(|entity| entity.id).collect();
            let result_ids: HashSet<EntityId> = seed_ids.iter().copied().collect();
            // ONE-1411: edge expansion is the SECOND door onto the same
            // content. The scopes that dropped stale federated claims from the
            // candidate set must not readmit one as a neighbor; the explicit
            // scopes that keep them pass `None` and get the marker instead.
            let stale_neighbor_exclusion = (!stale_worlds.is_empty()
                && matches!(self.world_scope, WorldScope::All | WorldScope::Base))
            .then_some(&stale_worlds);
            let edge_walk = if self.edge_hop > 0 && selected_edge_budget > 0 {
                walk_edges(
                    &self.vault.store,
                    &rtxn,
                    &seed_ids,
                    EdgeWalkOptions {
                        hops: self.edge_hop,
                        budget: selected_edge_budget,
                        exclude: &result_ids,
                        clamp,
                        stale_worlds: stale_neighbor_exclusion,
                    },
                )?
            } else {
                EdgeWalkResult::default()
            };
            let edge_cache = self.include_edges.then_some(&edge_walk.scanned_edges);
            for id in &edge_walk.neighbor_ids {
                validate_pack_entity_reference(
                    &self.vault.store,
                    &rtxn,
                    id,
                    &mut claim_bodies,
                    &quarantine_index,
                )?;
            }
            let neighbor_options = HydrateOptions {
                hydrate_fields: self.hydrate,
                include_edges: self.include_edges,
                include_vectors: self.include_vectors,
                edge_cache,
                claim_bodies: Some(&claim_bodies),
                clamp,
            };

            if self.include_edges && self.edge_hop > 0 {
                for entity in &mut results {
                    entity.edges = Some(load_entity_edges(
                        &self.vault.store,
                        &rtxn,
                        &entity.id,
                        edge_cache,
                        clamp,
                    )?);
                }
            }

            let mut neighbors = Vec::with_capacity(edge_walk.neighbor_ids.len());
            for id in edge_walk.neighbor_ids {
                let Some(entity) = hydrate_entity(
                    self.vault,
                    &rtxn,
                    id,
                    0.0,
                    neighbor_options,
                    &mut claims_suppressed,
                )?
                else {
                    continue;
                };
                neighbors.push(entity);
            }

            // ONE-1411: a stale world that survived the walk did so because the
            // scope named it. Mark it on exactly the rule the results follow.
            annotate_stale_federated_worlds(
                &self.vault.store,
                &rtxn,
                &stale_worlds,
                &mut neighbors,
                &claim_bodies,
            )?;

            validate_hydrated_pack_entities(&results, &neighbors)?;
            validate_pack_edge_references(
                &self.vault.store,
                &rtxn,
                &results,
                &mut claim_bodies,
                &quarantine_index,
            )?;
            validate_pack_edge_references(
                &self.vault.store,
                &rtxn,
                &neighbors,
                &mut claim_bodies,
                &quarantine_index,
            )?;
            // OF-365 enforcement point 4 — final fail-closed sweep: the pack
            // build FAILS rather than leaks a non-admitted id.
            if let Some(ctx) = clamp {
                validate_pack_disclosure(&self.vault.store, &rtxn, ctx, &results, &neighbors)?;
            }
            resolve_edge_short_ids(&mut results, &mut neighbors);

            let pack_is_empty = results.is_empty() && neighbors.is_empty();
            let candidates_considered = if pack_is_empty {
                total_in_scope
            } else {
                surfaced_candidate_count
            };
            let mut signals_used = self.signals_used;
            signals_used.extend(pipeline_signals.into_iter().map(pack_signal_from_retrieval));
            let stats = PackStats {
                candidates_considered,
                signals_used: dedupe_signals(signals_used),
                query_time_us: started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                entities_hydrated: results.len(),
                neighbors_hydrated: neighbors.len(),
                cosine_ghosts_dampened,
                claims_suppressed,
                tokens: crate::context_pack::PackTokenStats::default(),
                items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
                items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
            };
            let empty = empty_context(
                pack_is_empty,
                &stats,
                pipeline_empty_reason,
                &retrieval_quality,
            );

            Ok(ContextPackRun {
                pack: ContextPack {
                    retrieval_quality,
                    results,
                    neighbors,
                    stats,
                    empty,
                },
                telemetry_run_id,
                telemetry,
                total_in_scope,
                clamped_out,
            })
        })();

        if result.is_err() {
            discard_failed_context_pack_telemetry(telemetry, telemetry_run_id);
        }
        result
    }

    pub fn run_serialized(self) -> Result<Vec<u8>> {
        Ok(self.run_serialized_with_telemetry()?.value)
    }

    pub fn run_serialized_with_telemetry(self) -> Result<RetrievalWithTelemetry<Vec<u8>>> {
        let serialized = self.run_serialized_with_stats()?;
        Ok(RetrievalWithTelemetry {
            retrieval_quality: serialized.retrieval_quality,
            value: serialized.value.bytes,
            run_id: serialized.run_id,
        })
    }

    pub fn run_serialized_with_stats(
        self,
    ) -> Result<RetrievalWithTelemetry<SerializedContextPack>> {
        let config = SerializeConfig {
            format: self.format,
            profile: self.field_profile,
            budget: self.token_budget,
            allocation: self.token_allocation,
            include_stats: self.include_stats,
            merge_neighbors: self.merge_neighbors,
            max_field_chars: self.max_field_chars,
            max_item_tokens: self.max_item_tokens,
        };
        let run = self.run_unfinalized()?;
        let (bytes, telemetry) = serialize_pack_with_telemetry(&run.pack, &config);
        let telemetry_run_id = finalize_context_pack_telemetry(
            run.telemetry,
            run.telemetry_run_id,
            telemetry.stats.query_time_us,
            run.total_in_scope,
            telemetry.stats.claims_suppressed,
            &telemetry.result_ids,
            serialized_context_pack_empty_reason(&run.pack, &telemetry),
        )?;
        Ok(RetrievalWithTelemetry {
            retrieval_quality: run.pack.retrieval_quality,
            value: SerializedContextPack {
                bytes,
                stats: telemetry.stats,
            },
            run_id: telemetry_run_id,
        })
    }
}
