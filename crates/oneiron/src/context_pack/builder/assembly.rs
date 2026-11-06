//! Executing a configured builder: the retrieval run, hydration, validation, and every run_* terminal.

use std::collections::HashSet;
use std::time::Instant;

use crate::disclosure::DisclosureMode;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::WorldScope;
use crate::serialize::{SerializeConfig, serialize_pack_with_telemetry};
use crate::store::retrieval_values::RetrievalWithTelemetry;

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
use super::super::types::{ContextPack, ContextPackRetrievalBudget, PackStats, PackWorldShare};
use super::super::validation::{
    disclosure_admits_candidate, disclosure_admits_target, validate_hydrated_pack_entities,
    validate_pack_disclosure, validate_pack_edge_references, validate_pack_entity_reference,
    validate_scored_candidates,
};
use super::super::world_partition::{
    annotate_stale_federated_worlds, partition_pack_claims, resolve_edge_short_ids,
};
use super::{
    ContextPackBuilder, ContextPackRun, ContextPackTelemetry, HydrateOptions,
    SerializedContextPack, UnfinalizedContextPack,
};

/// What a scoped pack run reports beside its pack.
pub(crate) struct PackRunStatus {
    pub(crate) embedding_matches:
        std::collections::HashMap<EntityId, Vec<crate::store::embedding::EmbeddingMatchEvidence>>,
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

impl ContextPackBuilder<'_> {
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
        key: &crate::write_envelope::profile_snapshot::PsychProfileKey,
    ) -> Result<PsychProfilePackSection> {
        let id = crate::write_envelope::profile_snapshot::psych_profile_entity_id(key);
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
            .for_destination(lane.actor_key().destination())
            .run_unfinalized()?;
        let mut status = PackRunStatus {
            embedding_matches: run.embedding_matches,
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
            critical: run.critical,
            world_share: run.world_share,
        };
        lane.end_recall_plan()?;
        let receipt = match pending.filter_scoped_under(lane, disclosure.as_ref()) {
            Ok(receipt) => receipt,
            Err(error) => {
                pending.discard_telemetry();
                return Err(error);
            }
        };
        // Instruction files name only units this read returns (FIX 9761).
        pending.project_instruction_files_under(lane, disclosure.as_ref())?;
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
        let (vault, read, reader) = (self.vault, self.read, self.l2_summary_reader);
        let (destination, clamp) = (self.destination.clone(), self.disclosure.clone());
        // Instruction files name only units the projection's cuts kept (FIX 9761).
        self.run_unfinalized_with_telemetry()?
            .finish_projected_json(config, |pack| {
                super::instruction_files::returned_pack_instruction_files(
                    vault,
                    &read,
                    reader,
                    &destination,
                    clamp.as_ref(),
                    pack,
                )
            })
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
        let tokenizer = self.tokenizer;
        let config = SerializeConfig {
            format: self.format,
            profile: self.field_profile,
            budget: self.effective_token_budget(),
            allocation: self.token_allocation,
            include_stats: self.include_stats,
            merge_neighbors: self.merge_neighbors,
            max_field_chars: self.max_field_chars,
            max_item_tokens: self.max_item_tokens,
        };
        let run = self.run_unfinalized()?;
        let (bytes, telemetry) = serialize_pack_with_telemetry(&run.pack, &config, tokenizer);
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
