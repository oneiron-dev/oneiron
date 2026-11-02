//! What a pack run produces and how its telemetry row is finalized or discarded.

use std::collections::HashMap;

use crate::claim::ClaimBody;
use crate::codebase::CodeInstructionHandle;
use crate::disclosure::DisclosureContext;
use crate::edge::EdgeInfo;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::RetrievalWithTelemetry;
use crate::serialize::SerializeConfig;
use crate::store::{RetrievalRunFinalize, RetrievalRunId, Store};

use super::super::empty_pack::{
    context_pack_empty_reason, projected_context_pack_empty_reason, refresh_projected_empty_context,
};
use super::super::telemetry::{
    discard_failed_context_pack_telemetry, finalize_context_pack_telemetry,
};
use super::super::types::{
    ContextPack, ContextPackRetrievalBudget, PackCriticalAccounting, PackStats, PackWorldShare,
};

#[derive(Debug, Clone)]
pub struct SerializedContextPack {
    pub bytes: Vec<u8>,
    pub stats: PackStats,
}

#[derive(Clone, Copy)]
pub(in crate::context_pack) struct HydrateOptions<'a> {
    pub(in crate::context_pack) read_mode: crate::vault::ReadMode,
    /// A reranker scored this row's words at `read_mode`'s pin, so its fields
    /// come from that pinned row and not a live NOTE projection.
    pub(in crate::context_pack) words_pinned: bool,
    pub(in crate::context_pack) policy: &'a crate::gate::PolicyManifestResolution,
    pub(in crate::context_pack) criticality: Option<bool>,
    pub(in crate::context_pack) hydrate_fields: bool,
    pub(in crate::context_pack) include_edges: bool,
    pub(in crate::context_pack) include_vectors: bool,
    pub(in crate::context_pack) edge_cache: Option<&'a HashMap<EntityId, Vec<EdgeInfo>>>,
    /// Claim bodies already decoded and accepted before hydration: pipeline
    /// result claims from the D19 gate, plus any neighbor claims decoded by
    /// pre-assembly validation. The hydrator projects fields from these
    /// instead of re-decoding, so each surfaced claim body is decoded once.
    pub(in crate::context_pack) claim_bodies: Option<&'a HashMap<EntityId, ClaimBody>>,
    /// OF-365 disclosure clamp: hydrated edge lists filter non-admitted
    /// targets next to the off-record fence check.
    pub(in crate::context_pack) clamp: Option<&'a DisclosureContext>,
    /// Absolute answer deadline for hydration and edge filtering.
    pub(in crate::context_pack) deadline: Option<&'a crate::retrieval_depth::RetrievalDeadline>,
}

/// Where this assembly's retrieval-run telemetry lives, CAPTURED ONCE at run
/// entry (ONE-1570 Arm B).
///
/// A context pack registers a PROVISIONAL run row and finalizes it in a SECOND
/// write. Both writes must reach the same row. Re-deriving the target between
/// them would let an assembly whose room flipped mid-run stage its provisional
/// into the session overlay and then finalize into BASE — publishing the
/// room's `result_ids` durably under a route it no longer held. Carrying the
/// target as a value makes that unrepresentable, which is why this replaced
/// the bare `&Store` these structs used to hold.
#[derive(Clone, Copy)]
pub(in crate::context_pack) enum ContextPackTelemetry<'a> {
    /// The canonical base ledger. Every non-session entry takes this arm and
    /// is behaviorally unchanged.
    Base(&'a Store),
    /// A retrieval issued inside a live room (ARCH-0052 K8/K10). Both writes
    /// go back through the room's own registration door, which owns the route
    /// check and the overlay-vs-base decision for the whole assembly — this
    /// enum names WHOSE door, never a resolved target.
    Session(&'a crate::off_record::SessionRetrievalTelemetry<'a>),
}

impl ContextPackTelemetry<'_> {
    /// Whether a failed telemetry write here is a failure of the RETRIEVAL.
    /// It is, for a room: its run row is what close consumes.
    pub(in crate::context_pack) const fn is_session(self) -> bool {
        matches!(self, Self::Session(_))
    }

    /// Clears the provisional marker and publishes the final row, against
    /// whichever target registered the provisional.
    pub(in crate::context_pack) fn finalize(
        self,
        finalize: RetrievalRunFinalize<'_>,
    ) -> Result<()> {
        match self {
            Self::Base(store) => store.finalize_context_pack_retrieval_run(finalize),
            Self::Session(session) => session.finalize_run(finalize),
        }
    }

    /// Removes a provisional row whose assembly failed, leaving no residue on
    /// the target that holds it.
    pub(in crate::context_pack) fn discard(self, run_id: RetrievalRunId) -> Result<()> {
        match self {
            Self::Base(store) => store.delete_retrieval_run(run_id),
            Self::Session(session) => session.discard_run(run_id),
        }
    }
}

pub(in crate::context_pack) struct ContextPackRun<'a> {
    pub(in crate::context_pack) embedding_matches:
        HashMap<EntityId, Vec<crate::embed::EmbeddingMatchEvidence>>,
    pub(in crate::context_pack) vector_completed: bool,
    pub(in crate::context_pack) temporal_hints: Vec<crate::temporal::TemporalHintReport>,
    pub(in crate::context_pack) cited_messages:
        std::collections::HashMap<crate::EntityId, Vec<crate::EntityId>>,
    pub(in crate::context_pack) pack: ContextPack,
    pub(in crate::context_pack) telemetry_run_id: Option<RetrievalRunId>,
    pub(in crate::context_pack) telemetry: ContextPackTelemetry<'a>,
    /// Original pipeline scope count, retained by ordinary finalization.
    pub(in crate::context_pack) total_in_scope: usize,
    /// Scored candidates the disclosure clamp's candidate sweep dropped.
    pub(in crate::context_pack) clamped: Vec<EntityId>,
    pub(in crate::context_pack) replay_config: Option<serde_json::Value>,
    /// The critical rows the run found and its budgets cut (FIX 9760).
    pub(in crate::context_pack) critical: PackCriticalAccounting,
    /// An `All`-world pack's world share, for a cut after assembly (FIX 9759).
    pub(in crate::context_pack) world_share: Option<PackWorldShare>,
}

pub struct UnfinalizedContextPack<'a> {
    pub value: ContextPack,
    pub(super) telemetry_run_id: Option<RetrievalRunId>,
    pub(super) telemetry: ContextPackTelemetry<'a>,
    pub(super) total_in_scope: usize,
    pub(super) clamped: Vec<EntityId>,
    pub(super) replay_config: Option<serde_json::Value>,
    pub(super) critical: PackCriticalAccounting,
    pub(super) world_share: Option<PackWorldShare>,
}

impl UnfinalizedContextPack<'_> {
    pub fn discard_telemetry(&mut self) {
        discard_failed_context_pack_telemetry(self.telemetry, self.telemetry_run_id.take());
    }

    /// Scored candidates dropped by the disclosure clamp's candidate sweep
    /// this assembly (OF-365 ILD-2). Non-clamped runs report 0.
    #[must_use]
    pub fn clamped_out(&self) -> u64 {
        u64::try_from(self.clamped.len()).unwrap_or(u64::MAX)
    }

    /// [`Self::clamped_out`] as a caller reading through `read` may learn
    /// it: only dropped rows `read` would retrieve count, judged in one
    /// snapshot under its own retrieval floor, so the number never says that
    /// a row the caller cannot retrieve matched. A TURN counts only while
    /// every message in it does: its words are theirs. Denial reads as
    /// absence.
    pub fn clamped_out_under(&self, read: &crate::claim::ScopedRead<'_>) -> Result<u64> {
        use crate::ppr::PprNodeVisibility as _;
        read.persist_grant_clock()?;
        let rtxn = read.vault().store.env.read_txn()?;
        let visibility = read.retrieval_visibility_in(&rtxn, None)?;
        let mut count: u64 = 0;
        for id in &self.clamped {
            if visibility.ppr_node_visible(&rtxn, id)? {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    /// Filters the pack to what `read` may be served under `disclosure`
    /// (`ScopedRead::filter_context_pack_under`), and counts its critical
    /// claims, the ones its budgets cut included, over the ids `read` is
    /// admitted to (FIX 9760).
    pub fn filter_scoped_under(
        &mut self,
        read: &crate::claim::ScopedRead<'_>,
        disclosure: Option<&DisclosureContext>,
    ) -> Result<crate::claim::ScopedReadReceipt> {
        read.filter_context_pack_critical_under(&mut self.value, &self.critical, disclosure)
    }

    /// Cuts the pack to a response's limits by the pipeline's share-aware
    /// selection: its results to the per-kind `budget` and `results`, then its
    /// neighbors to `neighbors`, critical rows first in each, an `All`-world
    /// pack's share held over both (FIX 9759, FIX 9760). The kept rows keep
    /// their order. Returns whether a cut left out a critical row.
    pub fn select_response_rows(
        &mut self,
        budget: ContextPackRetrievalBudget,
        results: usize,
        neighbors: usize,
    ) -> bool {
        crate::pipeline::select_context_pack_rows(
            &mut self.value.results,
            &mut self.value.neighbors,
            budget,
            (results, neighbors),
            self.world_share.as_ref(),
        )
    }

    /// Resolves the pack's instruction files afresh over the units it now
    /// returns, under `read` and `disclosure` (FIX 9761): call it after the
    /// pack's last row filter and cut. A failure discards the provisional run
    /// row before it returns.
    pub fn project_instruction_files_under(
        &mut self,
        read: &crate::claim::ScopedRead<'_>,
        disclosure: Option<&DisclosureContext>,
    ) -> Result<()> {
        let units: Vec<EntityId> = self
            .value
            .results
            .iter()
            .chain(&self.value.neighbors)
            .map(|row| row.id)
            .collect();
        match read.context_pack_instruction_files_under(&units, disclosure) {
            Ok(files) => {
                self.value.instruction_files = files;
                Ok(())
            }
            Err(error) => {
                self.discard_telemetry();
                Err(error)
            }
        }
    }

    /// Projects the pack for a JSON response, then sets its instruction files
    /// to what `instruction_files` resolves over the rows that projection's
    /// token and item cuts kept, its last cut (FIX 9761), and only then
    /// finalizes the run row. A failed resolution discards the provisional
    /// run row before it returns.
    pub fn finish_projected_json(
        mut self,
        config: &SerializeConfig,
        instruction_files: impl FnOnce(&ContextPack) -> Result<Vec<CodeInstructionHandle>>,
    ) -> Result<RetrievalWithTelemetry<ContextPack>> {
        let pre_projection_stats = self.value.stats.clone();
        let pre_projection_had_results =
            !self.value.results.is_empty() || self.value.l2_base.is_some();
        let mut pack = crate::serialize::project_pack_for_json_response(self.value, config);
        refresh_projected_empty_context(&mut pack);
        pack.instruction_files = match instruction_files(&pack) {
            Ok(files) => files,
            Err(error) => {
                discard_failed_context_pack_telemetry(self.telemetry, self.telemetry_run_id.take());
                return Err(error);
            }
        };
        let surfaced_result_ids: Vec<[u8; 16]> = pack
            .results
            .iter()
            .map(|entity| *entity.id.as_bytes())
            .collect();
        // BASE-ONLY by construction: `run_unfinalized_with_telemetry` refuses
        // a room's assembly precisely because this finalize has no channel to
        // carry a room's registration failure, and the base arm's posture is
        // best-effort `Ok`. The `Err` arm is therefore unreachable here, and
        // flattening it cannot hide a room's failure.
        let mut replay_config = self.replay_config.take();
        if let Some(value) = replay_config.as_mut() {
            value["projection"] = super::replay::projection_config(config);
            value["terminal_kind"] = "projected_json".into();
        }
        let telemetry_run_id = finalize_context_pack_telemetry(
            self.telemetry,
            self.telemetry_run_id.take(),
            pack.stats.query_time_us,
            self.total_in_scope,
            pack.stats.claims_suppressed,
            &surfaced_result_ids,
            projected_context_pack_empty_reason(
                &pack,
                &pre_projection_stats,
                pre_projection_had_results,
                &surfaced_result_ids,
            ),
            replay_config,
        )
        .ok()
        .flatten();
        Ok(RetrievalWithTelemetry {
            retrieval_quality: pack.retrieval_quality.clone(),
            value: pack,
            run_id: telemetry_run_id,
        })
    }

    /// Finalizes this assembly's retrieval-run row against the pack AS IT NOW
    /// STANDS — after the caller's own scope filtering, clamping and
    /// truncation — and returns it UNPROJECTED.
    ///
    /// The sibling of [`Self::finish_projected_json`] for a caller that
    /// answers with the engine-canonical pack instead of an HTTP JSON
    /// projection (ONE-1433's `code_run::vault_read` adapter). Deferring the
    /// finalize is the whole point of the door: a durable run row published
    /// out of an actor-scoped read must carry EXACTLY the ids that actor
    /// received, so the surfaced ids, candidate and suppression counts, and
    /// empty reason are all read back off the post-filter value rather than
    /// off the assembly's own pre-filter results. An entity the caller's filter
    /// removed is then as absent from telemetry as it is from the response —
    /// the same fail-closed boundary OF-365 states for the disclosure clamp,
    /// where a durable trace must not retain ids a clamp removed.
    ///
    /// # Errors
    ///
    /// Propagates a failed finalize after discarding the provisional row.
    /// This door deliberately does NOT take [`Self::finish_projected_json`]'s
    /// best-effort posture: its caller has a `Result` to carry the failure,
    /// so even a base-vault finalize failure must fail this read.
    pub fn finish_post_filter(mut self) -> Result<RetrievalWithTelemetry<ContextPack>> {
        let surfaced_result_ids: Vec<[u8; 16]> = self
            .value
            .results
            .iter()
            .map(|entity| *entity.id.as_bytes())
            .collect();
        let telemetry_run_id = self.telemetry_run_id.take();
        let mut replay_config = self.replay_config.take();
        if let Some(value) = replay_config.as_mut() {
            value["terminal_kind"] = "structured".into();
        }
        if let Some(run_id) = telemetry_run_id
            && let Err(error) = self.telemetry.finalize(RetrievalRunFinalize {
                run_id,
                elapsed_us: self.value.stats.query_time_us,
                total_in_scope: self.value.stats.candidates_considered,
                claims_suppressed: self.value.stats.claims_suppressed,
                surfaced_result_ids: &surfaced_result_ids,
                empty_reason: context_pack_empty_reason(&self.value, &surfaced_result_ids),
                pack_config: replay_config,
            })
        {
            discard_failed_context_pack_telemetry(self.telemetry, Some(run_id));
            return Err(error);
        }
        Ok(RetrievalWithTelemetry {
            retrieval_quality: self.value.retrieval_quality.clone(),
            value: self.value,
            run_id: telemetry_run_id,
        })
    }
}
