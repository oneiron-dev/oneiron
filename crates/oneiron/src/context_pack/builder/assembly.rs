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
use super::super::psych_mirror::{
    PsychProfilePackSection, missing_psych_profile_pack_section, psych_profile_pack_section_in,
};
use super::super::quarantine::load_pack_quarantine_index;
use super::super::telemetry::{
    discard_failed_context_pack_telemetry, finalize_context_pack_telemetry,
};
use super::super::types::{ContextPack, ContextPackRetrievalBudget, PackStats};
use super::super::validation::{
    disclosure_admits_candidate, disclosure_admits_target, validate_hydrated_pack_entities,
    validate_pack_disclosure, validate_pack_edge_references, validate_pack_entity_reference,
    validate_scored_candidates,
};
use super::super::world_partition::{
    annotate_stale_federated_worlds, partition_results_by_world, resolve_edge_short_ids,
};
use super::{
    ContextPackBuilder, ContextPackRun, ContextPackTelemetry, HydrateOptions,
    SerializedContextPack, UnfinalizedContextPack,
};

/// What a scoped pack run reports beside its pack.
pub(crate) struct PackRunStatus {
    /// Only the handle returned by successful post-filter finalization.
    pub(crate) run_id: Option<crate::store::RetrievalRunId>,
    /// Whether the vector channel completed.
    pub(crate) vector_completed: bool,
    /// The query's temporal phrases and what the run did with each.
    pub(crate) temporal_hints: Vec<crate::temporal::TemporalHintReport>,
    /// Per TURN in the pack, the MESSAGE rows it took the place of, best
    /// first ([`ContextPackBuilder::fold_messages_into_turns`]).
    pub(crate) cited_messages: std::collections::HashMap<EntityId, Vec<EntityId>>,
}

impl<'a> ContextPackBuilder<'a> {
    /// Runs retrieval and returns the opt-in stored-profile companion section.
    /// The profile is one more row of the pack: the pack's disclosure clamp
    /// and reader admit it as they admit any row, and a profile either
    /// refuses reads as a missing one.
    pub fn run_with_psych_profile(self) -> Result<(ContextPack, Option<PsychProfilePackSection>)> {
        let section = self
            .psych_profile_key
            .map(|key| self.psych_profile_section(&key))
            .transpose()?;
        let pack = self.run()?;
        Ok((pack, section))
    }

    /// The profile section, admitted and read in one snapshot.
    fn psych_profile_section(
        &self,
        key: &crate::psych_profile::PsychProfileKey,
    ) -> Result<PsychProfilePackSection> {
        let id = crate::psych_profile::psych_profile_entity_id(key);
        if let Some(reader) = self.l2_summary_reader {
            reader.persist_grant_clock()?;
        }
        let rtxn = self.vault.store.env.read_txn()?;
        if let Some(reader) = self.l2_summary_reader {
            let policy = reader.live_policy_manifest_in(&rtxn)?;
            if !reader.is_entity_readable_with_policy_in(&rtxn, &policy, &id)? {
                return Ok(missing_psych_profile_pack_section(*key));
            }
        }
        if !disclosure_admits_target(&self.read, &rtxn, self.disclosure.as_ref(), &id)? {
            return Ok(missing_psych_profile_pack_section(*key));
        }
        psych_profile_pack_section_in(self.vault, &rtxn, key)
    }

    pub fn run(self) -> Result<ContextPack> {
        Ok(self.run_with_telemetry()?.value)
    }

    pub fn run_with_telemetry(self) -> Result<RetrievalWithTelemetry<ContextPack>> {
        Ok(self.run_with_vector_status()?.0)
    }

    pub(crate) fn run_with_vector_status(
        self,
    ) -> Result<(RetrievalWithTelemetry<ContextPack>, bool)> {
        let run = self.run_unfinalized()?;
        let surfaced_result_ids: Vec<[u8; 16]> = run
            .pack
            .results
            .iter()
            .map(|entity| *entity.id.as_bytes())
            .collect();
        let mut replay_config = run.replay_config;
        if let Some(config) = replay_config.as_mut() {
            config["terminal_kind"] = "structured".into();
        }
        let telemetry_run_id = finalize_context_pack_telemetry(
            run.telemetry,
            run.telemetry_run_id,
            run.pack.stats.query_time_us,
            run.total_in_scope,
            run.pack.stats.claims_suppressed,
            &surfaced_result_ids,
            context_pack_empty_reason(&run.pack, &surfaced_result_ids),
            replay_config,
        )?;
        Ok((
            RetrievalWithTelemetry {
                retrieval_quality: run.pack.retrieval_quality.clone(),
                value: run.pack,
                run_id: telemetry_run_id,
            },
            run.vector_completed,
        ))
    }

    /// Filter the actor's pack before rendering or finalizing telemetry, including rooms.
    /// Also returns how the run went ([`PackRunStatus`]).
    pub(crate) fn run_scoped_with_run_status(
        self,
        lane: &crate::claim::ScopedRead<'_>,
    ) -> Result<(crate::claim::ScopedReadResult<ContextPack>, PackRunStatus)> {
        let disclosure = self.disclosure.clone();
        let run = self
            .caller_off_device(lane.off_device())
            .run_unfinalized()?;
        let mut status = PackRunStatus {
            run_id: None,
            vector_completed: run.vector_completed,
            temporal_hints: run.temporal_hints,
            cited_messages: run.cited_messages,
        };
        let mut pending = UnfinalizedContextPack {
            value: run.pack,
            telemetry_run_id: run.telemetry_run_id,
            telemetry: run.telemetry,
            total_in_scope: run.total_in_scope,
            clamped: run.clamped,
            replay_config: run.replay_config,
        };
        lane.end_recall_plan()?;
        let receipt = match lane.filter_context_pack_under(&mut pending.value, disclosure.as_ref())
        {
            Ok(receipt) => receipt,
            Err(error) => {
                pending.discard_telemetry();
                return Err(error);
            }
        };
        // Counts exposed by recall refer only to rows admitted by this read.
        pending.value.stats.candidates_considered = pending.value.results.len();
        let finalized = pending.finish_post_filter()?;
        status.run_id = finalized.run_id;
        let pack = finalized.value;
        Ok((
            crate::claim::ScopedReadResult {
                value: pack,
                receipt,
            },
            status,
        ))
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
            clamped: run.clamped,
            replay_config: run.replay_config,
        })
    }

    pub(in crate::context_pack) fn run_unfinalized(self) -> Result<ContextPackRun<'a>> {
        if self.skip_optional_recall {
            return Ok(ContextPackRun {
                vector_completed: false,
                temporal_hints: Vec::new(),
                cited_messages: std::collections::HashMap::new(),
                pack: super::super::empty_pack::skipped_by_profile_pack(),
                telemetry_run_id: None,
                telemetry: match self.session {
                    Some(session) => ContextPackTelemetry::Session(session),
                    None => ContextPackTelemetry::Base(&self.vault.store),
                },
                total_in_scope: 0,
                clamped: Vec::new(),
                replay_config: None,
            });
        }
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
        let replay_config = (self.pipeline.captures_replay()
            && self
                .disclosure
                .as_ref()
                .is_none_or(|ctx| ctx.mode() == DisclosureMode::OwnerAlone))
        .then(|| self.pack_replay_config());
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
        let implicit_l2 = self.l2_summary_subjects.is_empty();
        let l2_subjects = if implicit_l2 {
            super::super::l2_base::default_l2_subjects(self.vault, self.l2_summary_reader)?
        } else {
            self.l2_summary_subjects.clone()
        };
        let mut l2_base = match super::super::l2_base::produce_l2_base(
            self.vault,
            &pipeline,
            &l2_subjects,
            self.disclosure.as_ref(),
            self.l2_summary_reader,
            // The cache is the vault's and outlives any room: a summary
            // over a room's rows is computed, never kept.
            self.session.is_none() && !self.read.is_union(),
        ) {
            // Only bounded-summary limits may omit an implicit optional
            // prefix. Corruption, disclosure and explicit-request errors stay
            // fail-closed; the normal retrieval still runs its own gates.
            Err(Error::IndexOverflow(
                "L2 subject adjacency" | "L2 evidence bytes" | "L2 evidence claims",
            )) if implicit_l2 => None,
            other => other?,
        };
        let l2_pipeline = l2_base.as_ref().map(|_| pipeline.clone());
        let neighbor_pipeline =
            (self.edge_hop > 0 && selected_edge_budget > 0).then(|| pipeline.clone());
        let mut pipeline = pipeline.context_pack_budget(retrieval_budget);
        // The world share and the disclosure clamp hold while the rows are
        // selected, so neither leaves the pack short of rows it could carry.
        if matches!(self.world_scope, WorldScope::All) {
            pipeline = pipeline.context_pack_world_share(self.non_base_world_fraction);
        }
        if let Some(ctx) = self
            .disclosure
            .as_ref()
            .filter(|ctx| ctx.mode() != DisclosureMode::OwnerAlone)
        {
            pipeline = pipeline.disclosure_preselect(ctx.clone());
        }
        let pipeline_output = pipeline.run_for_pack()?;
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

            if let Some(reader) = self.l2_summary_reader {
                reader.persist_grant_clock()?;
            }
            let rtxn = self.vault.store.env.read_txn()?;
            let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &rtxn)?;
            let hydrate_result_edges = self.include_edges && self.edge_hop == 0;
            let mut claim_bodies = claim_bodies;
            let quarantine_index = load_pack_quarantine_index(&self.vault.store, &rtxn)?;

            // OF-365 disclosure clamp, enforcement point 1 (candidate sweep,
            // the only point that counts): drop non-admitted scored ids
            // before hydration. Absence is the boundary — a clamped id never
            // reaches hydration, results, or stats.
            let clamp = self.disclosure.as_ref();
            let mut scored = scored;
            let mut clamped = pipeline_output.disclosure_clamped;
            if let Some(ctx) = clamp
                && ctx.mode() != DisclosureMode::OwnerAlone
            {
                let mut kept = Vec::with_capacity(scored.len());
                for entry in scored {
                    if disclosure_admits_candidate(
                        &self.read,
                        &rtxn,
                        ctx,
                        &entry.id,
                        &claim_bodies,
                    )? {
                        kept.push(entry);
                    } else {
                        clamped.push(entry.id);
                    }
                }
                scored = kept;
            }
            let mut capabilities = Vec::new();
            for entry in pipeline_output.capabilities {
                if clamp.is_some_and(|ctx| ctx.mode() != DisclosureMode::OwnerAlone)
                    && !disclosure_admits_candidate(
                        &self.read,
                        &rtxn,
                        clamp.expect("checked"),
                        &entry.id,
                        &claim_bodies,
                    )?
                {
                    continue;
                }
                if self
                    .vault
                    .archive_tombstone_in_txn(&rtxn, &entry.id)?
                    .is_some()
                {
                    continue;
                }
                if let Some(hit) = crate::pipeline::capability_hit(&self.read, &rtxn, entry.id)? {
                    capabilities.push(hit);
                }
            }
            let surfaced_candidate_count = scored.len();

            let result_options = HydrateOptions {
                read_mode: self.read_mode,
                words_pinned: false,
                policy: &policy,
                criticality: self.criticality,
                hydrate_fields: self.hydrate,
                include_edges: hydrate_result_edges,
                include_vectors: self.include_vectors,
                edge_cache: None,
                claim_bodies: Some(&claim_bodies),
                clamp,
            };
            let mut results = Vec::with_capacity(scored.len());
            for entry in scored.iter().copied() {
                let mut options = result_options;
                options.words_pinned = pipeline_output.words_bound.contains(&entry.id);
                // A hit a reranker scored at its words is served at them,
                // whatever mode the builder reads its other hits in.
                if options.words_pinned || options.read_mode == crate::vault::ReadMode::Indexed {
                    let Some(revision) = pipeline_output.revisions.get(&entry.id) else {
                        continue;
                    };
                    options.read_mode = crate::vault::ReadMode::Pinned(*revision);
                }
                let Some(entity) = hydrate_entity(
                    self.vault,
                    &self.read,
                    &rtxn,
                    entry.id,
                    entry.score,
                    options,
                    &mut claims_suppressed,
                )?
                else {
                    continue;
                };
                results.push(entity);
            }

            // ARCH-0004 / ARCH-0022 world partitioning (ONE-1117): under the
            // default `All` scope, group surviving claims by world — base section
            // first, then one section per non-base world. The pipeline already
            // selected under the world share; the cap here only bites when
            // hydration dropped a base claim. Flat (unchanged) for Base / World(id).
            if matches!(self.world_scope, WorldScope::All) {
                partition_results_by_world(
                    &self.read,
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
                &self.read,
                &rtxn,
                &stale_worlds,
                &mut results,
                &claim_bodies,
            )?;

            for entity in &results {
                validate_pack_entity_reference(
                    &self.read,
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
            let device_local = if self.off_device {
                Some(crate::settings::device_local_worlds_at(
                    self.vault,
                    &rtxn,
                    crate::claim::CallerLocality::OffDevice,
                )?)
            } else {
                None
            };
            let edge_walk = if let Some(neighbor_pipeline) = neighbor_pipeline.as_ref() {
                let (neighbor_filter, named_types) =
                    neighbor_pipeline.neighbor_type_policy(&rtxn)?;
                walk_edges(
                    &self.read,
                    &rtxn,
                    &seed_ids,
                    EdgeWalkOptions {
                        hops: self.edge_hop,
                        budget: selected_edge_budget,
                        exclude: &result_ids,
                        clamp,
                        stale_worlds: stale_neighbor_exclusion,
                        device_local: device_local.as_ref(),
                        type_filter: &neighbor_filter,
                        named_types,
                    },
                )?
            } else {
                EdgeWalkResult::default()
            };
            let edge_cache = self.include_edges.then_some(&edge_walk.scanned_edges);
            for id in &edge_walk.neighbor_ids {
                validate_pack_entity_reference(
                    &self.read,
                    &rtxn,
                    id,
                    &mut claim_bodies,
                    &quarantine_index,
                )?;
            }
            let neighbor_options = HydrateOptions {
                read_mode: self.read_mode,
                words_pinned: false,
                policy: &policy,
                criticality: self.criticality,
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
                        &self.read, &rtxn, &entity.id, edge_cache, clamp,
                    )?);
                }
            }

            let mut neighbors = Vec::with_capacity(edge_walk.neighbor_ids.len());
            for id in edge_walk.neighbor_ids {
                let Some(entity) = hydrate_entity(
                    self.vault,
                    &self.read,
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
                &self.read,
                &rtxn,
                &stale_worlds,
                &mut neighbors,
                &claim_bodies,
            )?;

            validate_hydrated_pack_entities(&results, &neighbors)?;
            validate_pack_edge_references(
                &self.read,
                &rtxn,
                &results,
                &mut claim_bodies,
                &quarantine_index,
            )?;
            validate_pack_edge_references(
                &self.read,
                &rtxn,
                &neighbors,
                &mut claim_bodies,
                &quarantine_index,
            )?;
            // OF-365 enforcement point 4 — final fail-closed sweep: the pack
            // build FAILS rather than leaks a non-admitted id.
            if let Some(ctx) = clamp {
                validate_pack_disclosure(&self.read, &rtxn, ctx, &results, &neighbors)?;
            }
            if let (Some(summary), Some(pipeline)) = (&l2_base, &l2_pipeline) {
                let valid = match super::super::l2_base::revalidate_l2_base(
                    self.vault,
                    pipeline,
                    &rtxn,
                    summary,
                    clamp,
                    self.l2_summary_reader,
                ) {
                    Ok(valid) => valid,
                    Err(Error::IndexOverflow(
                        "L2 subject adjacency" | "L2 evidence bytes" | "L2 evidence claims",
                    )) if implicit_l2 => false,
                    Err(error) => return Err(error),
                };
                if !valid {
                    l2_base = None;
                }
            }
            super::super::source_ranking::apply(
                &mut results,
                &mut neighbors,
                &claim_bodies,
                &self.source_ranking,
            )?;
            resolve_edge_short_ids(&mut results, &mut neighbors);

            let memory_is_empty = results.is_empty() && neighbors.is_empty() && l2_base.is_none();
            let pack_is_empty = memory_is_empty && capabilities.is_empty();
            // Discoveries keep the whole pack nonempty, but never decide the
            // memory channel's accounting. Non-owner disclosure still reports
            // only admitted candidates, not pre-clamp population information.
            let candidates_considered = if memory_is_empty
                && clamp.is_none_or(|ctx| ctx.mode() == DisclosureMode::OwnerAlone)
            {
                total_in_scope
            } else {
                surfaced_candidate_count
            };
            let mut signals_used = self.signals_used;
            signals_used.extend(pipeline_signals.into_iter().map(pack_signal_from_retrieval));
            let stats = PackStats {
                critical_over_budget: false,
                critical_count: 0,
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

            let units: Vec<_> = results.iter().chain(&neighbors).map(|row| row.id).collect();
            let instruction_files = self.vault.code_instruction_handles(&units)?;
            Ok(ContextPackRun {
                vector_completed: pipeline_output.vector_completed,
                temporal_hints: pipeline_output.temporal_hints,
                cited_messages: pipeline_output.cited_messages,
                pack: ContextPack {
                    capabilities,
                    l2_base,
                    retrieval_quality,
                    results,
                    neighbors,
                    instruction_files,
                    stats,
                    empty,
                },
                telemetry_run_id,
                telemetry,
                total_in_scope,
                clamped,
                replay_config,
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
        let mut replay_config = run.replay_config;
        if let Some(value) = replay_config.as_mut() {
            value["terminal_kind"] = "serialized".into();
        }
        let telemetry_run_id = finalize_context_pack_telemetry(
            run.telemetry,
            run.telemetry_run_id,
            telemetry.stats.query_time_us,
            run.total_in_scope,
            telemetry.stats.claims_suppressed,
            &telemetry.result_ids,
            serialized_context_pack_empty_reason(&run.pack, &telemetry),
            replay_config,
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
