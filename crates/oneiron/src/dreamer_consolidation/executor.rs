//! Partition executor: runs one prepared consolidation partition end to end.
//! Entry: `ConsolidationExecutor`, the consolidation attempt executor.
//! Definitions live here and in the executor's private children.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

mod conflicts;
mod decisions;
pub(super) mod extraction;
mod failure;
mod merge_resolution;
mod partition_run;

use conflicts::{ConflictInput, ResolvedSets};
pub use decisions::ConsolidationDecisions;
pub(super) use decisions::{Decider, ScopedRead};
use merge_resolution::MergeResolution;

use super::evidence::{
    ExtractedCandidate, ResolvedConflictOutput, VerifiedCandidate, VerifiedEvidenceSet,
};
use super::resources::BranchResources;
use super::roles::{DREAMER_VERDICT_ROLE, RoleBackends, RoleCall};
use super::value_projection::{json_to_rmpv, rmpv_to_json};
use rmpv::Value;

use super::branch::BranchAxes;
use super::conflict::{ConflictIdentity, ConflictSet, candidate_facts, deterministic_claim_id};
use super::failure_rules::{self, Stage};
use super::gap::{ReflectionGap, ReflectionGapKind};
use super::partition::decode_partition_payload;
use super::provenance::{
    ConsolidationProvenanceHop, ConsolidationSink, KeptDecision, PromotionCandidate,
    join_decisions, source_meet,
};
use super::step_charge::StepChargeTally;
use super::support::{
    DREAMER_GAP_SCAN_ATTEMPT_TYPE, DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE, SCOPE_PROJECT_KEY,
    TURN_BODY_FACET_REF_KEY, invalid_consolidation,
};
use super::watermark::{WorkingSetTurn, conversation_of, read_turn_facts};
use crate::claim::{ClaimSource, ClaimSubject};
use crate::dreamer_runner::{DreamerClaimAuthoringStrategy, DreamerParkCause, dreamer_turn_role};
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, DurableStepResult, HostInferenceContext, LlmBackend, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResponse, ModelId, ModelTierRef, ResponseFormat, StepOutcome,
    TierPrecedence, call_as_step,
};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor};

// ---------------------------------------------------------------------------
// Phase 3 executor — bucket attempts over the step layer
// ---------------------------------------------------------------------------

/// Extraction/merge executor for partition attempts. Implements ONE-1288's
/// [`DreamerAttemptExecutor`]: decodes the partition payload, extracts
/// candidates AS DATA through `call_as_step` (single-pass strategy),
/// resolves conflicts, and hands survivors to the [`ConsolidationSink`].
/// The tournament strategy routes through the landed `dreamer_tournament`
/// machinery under its admission gate (steps still via `call_as_step`).
pub struct ConsolidationExecutor<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub strategy: DreamerClaimAuthoringStrategy,
    /// The resolved vault Dreamer authority, checked against the queued stamp.
    pub actor: WriteActor,
    pub model: ModelId,
    /// Explicit host binding and extraction egress decision for this backend.
    pub inference: HostInferenceContext<'a>,
    /// The backend each role's calls go out on; a role it does not name
    /// calls `backend` as `model`. It holds the sieve's and a child
    /// extraction's ports too (OF-498a), by default on these roles.
    pub roles: RoleBackends,
    pub sink: &'a mut dyn ConsolidationSink,
    /// Trusted caller's exact branch scope, in addition to actor authority.
    /// A queued scope is its upper bound. None inherits that scope, or admits
    /// only the queued partition's resources when no caller bound was queued.
    pub scope: Option<crate::llm::Scope>,
    /// The host's ladder for the typed questions: how a conflict resolves,
    /// and which listed claim a candidate corrects.
    pub decisions: ConsolidationDecisions,
}

/// Outcome of the (possibly multi-step) LLM work inside one consolidation
/// partition attempt.
///
/// `Trapped` means a durable `call_as_step` suspended the attempt — the step layer
/// has ALREADY parked it for resume. A trapped attempt must therefore Park, never
/// Complete: no candidates are accepted (the work is not silently dropped-as-
/// done) and no `ContradictionLeftStanding` gap is written from a merge that
/// never decided. On resume the memoized steps replay and the attempt re-runs to a
/// real decision (#485-1, #485-2).
pub(super) enum PartitionRun {
    Completed {
        candidates: Vec<VerifiedCandidate>,
    },
    Trapped,
    /// The response was charged but the run must stop before publishing it.
    Checkpoint,
    /// The reply broke the extraction contract: charged, not memoized, and
    /// the attempt parks with the reason, to ask again on resume.
    Refused {
        reason: String,
    },
    Held {
        candidates: Vec<VerifiedCandidate>,
        retry_at_ms: u64,
    },
}

impl PartitionRun {
    /// This run with work that waits on a role's answer: what it took is kept,
    /// and the attempt comes back to read the ask again.
    pub(super) fn waiting_on_ask(self, now_ms: u64) -> Self {
        let recheck = now_ms.saturating_add(decisions::ASK_RECHECK_MS);
        match self {
            Self::Completed { candidates } => Self::Held {
                candidates,
                retry_at_ms: recheck,
            },
            Self::Held {
                candidates,
                retry_at_ms,
            } => Self::Held {
                candidates,
                retry_at_ms: retry_at_ms.min(recheck),
            },
            run => run,
        }
    }
}

impl ConsolidationExecutor<'_> {
    /// Scoped merge over conflicting sets — ONLY conflicting sets. One typed
    /// pack per set through the host's ladder, with the pinned outcome
    /// vocabulary (a merge's value is generation beside it):
    /// `merge` (one merged value) | `supersede` (single prior head — with no
    /// prior in scope it degrades to merge) | `accumulate` (multi-value
    /// predicates keep all) | `escalate` (drop the set to the gap queue as
    /// `ContradictionLeftStanding`; contradictions never land silently).
    /// A pack whose question went up the role chain and waits holds its set
    /// out of the pass, and the attempt comes back for the answer. Every
    /// output keeps the decisions that shaped it.
    pub(super) async fn resolve_conflicts(
        &mut self,
        candidates: Vec<ExtractedCandidate>,
        resources: &BranchResources<'_>,
        ctx: &WakeAttemptContext<'_>,
        step_identity: (crate::attempt_queue::AttemptId, Option<String>),
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<PartitionRun> {
        let assembled =
            super::assembly::assemble_extracted(ctx.vault, resources, candidates, ctx.now_ms)?;
        let candidates = assembled.candidates;
        let conflicts = assembled.conflicts;
        let corrections = assembled.corrections;
        let policy = {
            let txn = ctx.vault.store.env.read_txn().map_err(crate::Error::from)?;
            crate::gate::resolve_policy_manifest(&ctx.vault.store, &txn)?
        };
        if conflicts.is_empty() {
            return Ok(if assembled.held {
                PartitionRun::Held {
                    candidates,
                    retry_at_ms: assembled.retry_at_ms,
                }
            } else {
                PartitionRun::Completed { candidates }
            });
        }

        let state = match self
            .resolve_sets(
                ConflictInput {
                    candidates: &candidates,
                    conflicts: &conflicts,
                    corrections: &corrections,
                    policy: &policy,
                },
                resources,
                ctx,
                step_identity,
                charges,
            )
            .await?
        {
            ControlFlow::Break(run) => return Ok(run),
            ControlFlow::Continue(state) => state,
        };
        let ResolvedSets {
            dropped,
            merged,
            escalated,
            kept_by,
            mut answered,
            waiting,
        } = state;

        if ctx.deadline.expired() {
            return Ok(PartitionRun::Checkpoint);
        }
        if !escalated.is_empty() {
            resources.upsert_verified_gaps(resources.scope(), escalated, ctx.now_ms)?;
        }

        let mut surviving: Vec<VerifiedCandidate> = candidates
            .into_iter()
            .enumerate()
            .filter(|(index, _)| !dropped.contains(index))
            .map(|(index, mut candidate)| {
                if let Some(decisions) = kept_by.get(&index) {
                    join_decisions(&mut candidate.proposal.decisions, decisions);
                }
                if let Some(bound) = answered.remove(&index) {
                    candidate.answers.extend(bound);
                }
                candidate
            })
            .collect();
        surviving.extend(merged);
        let run = if assembled.held {
            PartitionRun::Held {
                candidates: surviving,
                retry_at_ms: assembled.retry_at_ms,
            }
        } else {
            PartitionRun::Completed {
                candidates: surviving,
            }
        };
        Ok(if waiting {
            run.waiting_on_ask(ctx.now_ms)
        } else {
            run
        })
    }

    /// Where `role`'s calls go in this executor.
    pub(super) fn role(&self, role: crate::llm::manifest::ModelRole) -> RoleCall<'_> {
        RoleCall::resolve(
            &self.roles,
            role,
            self.backend,
            &self.model,
            &self.inference.binding,
            self.inference.extraction_egress,
        )
    }

    /// How a conflict step's failure ends the partition: a refusal of spent
    /// work checkpoints; any other failure parks the attempt with a durable
    /// Proposed marker (the marker and every source pin share the write
    /// transaction) and fails it; a refused call's paid usage rides on the
    /// error to the attempt's park, which records it (FIX 414).
    #[expect(
        clippy::too_many_arguments,
        reason = "the failure joins the conflict, its branch, the wake and the charge tally"
    )]
    fn conflict_failed(
        &self,
        error: DurableStepError,
        conflict: &ConflictSet,
        members: &[&VerifiedCandidate],
        resources: &BranchResources<'_>,
        ctx: &WakeAttemptContext<'_>,
        attempt_id: crate::attempt_queue::AttemptId,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<PartitionRun> {
        match error {
            DurableStepError::SpentFinalizeRefused { usage } => {
                charges.record_usage(&usage);
                Ok(PartitionRun::Checkpoint)
            }
            DurableStepError::SpentSchemaValidation { usage, .. } if ctx.deadline.expired() => {
                charges.record_usage(&usage);
                Ok(PartitionRun::Checkpoint)
            }
            error => {
                resources.require_output(resources.scope())?;
                let mut decisions = Vec::new();
                for member in members {
                    join_decisions(&mut decisions, &member.decisions);
                }
                super::open_conflict::park_open_conflict(
                    ctx.vault,
                    self.actor,
                    attempt_id,
                    conflict,
                    members,
                    &decisions,
                    &resources.write_fence(),
                    ctx.now_ms,
                )?;
                Err(error)
            }
        }
    }
}

/// The merged head: `decisions` are the pack's that merged it, joined with
/// every member's.
fn merged_candidate(
    conflict: &ConflictSet,
    members: &[&VerifiedCandidate],
    priors: &[super::conflict::PriorHead],
    value: Value,
    decisions: Vec<KeptDecision>,
    attempt_id: crate::attempt_queue::AttemptId,
    now_ms: u64,
) -> Result<VerifiedCandidate> {
    let mut evidence: Vec<EntityId> = Vec::new();
    let mut combined: Option<VerifiedEvidenceSet> = None;
    let mut chain: Vec<ConsolidationProvenanceHop> = Vec::new();
    let mut meet = ClaimSource::UserStated;
    let mut confidence = 0.0_f32;
    for member in members {
        combined = Some(combined.map_or_else(
            || member.evidence.clone(),
            |old| old.union(&member.evidence),
        ));
        for turn in &member.evidence_turn_refs {
            if !evidence.contains(turn) {
                evidence.push(*turn);
            }
        }
        // A merge inherits every member's lineage: dropping a hop here would
        // launder the merged head past the evidence it descends from.
        for hop in &member.provenance_chain {
            if !chain.contains(hop) {
                chain.push(*hop);
            }
        }
        meet = source_meet(meet, member.evidence_meet);
        confidence = confidence.max(0.5);
    }
    evidence.sort();
    evidence.dedup();
    for prior in priors
        .iter()
        .filter(|p| conflict.prior_heads.contains(&p.claim_id))
    {
        meet = source_meet(
            meet,
            crate::claim::claim_evidence_taint(&prior.body)
                .or(prior.body.source)
                .unwrap_or(ClaimSource::Generated),
        );
    }
    let claim_id = deterministic_claim_id(
        attempt_id,
        conflict.identity.subject,
        &conflict.identity.predicate,
        &value,
        conflict.identity.world,
        conflict.identity.facet,
        conflict.identity.rel,
        conflict.identity.project,
        conflict.identity.topic.as_deref(),
    )?;
    let mut candidate = ClaimCandidate::new(
        conflict.identity.predicate.clone(),
        ClaimSubject::Entity(conflict.identity.subject),
        value,
        confidence,
    );
    if let Some(rel) = conflict.identity.rel {
        candidate = candidate.with_relationship(rel);
    }
    if let Some(world) = conflict.identity.world {
        candidate = candidate.with_world(world);
    }
    candidate = candidate.with_scope(super::persistence::identity_scope(&conflict.identity)?);
    let hints: Vec<&str> = members
        .iter()
        .flat_map(|member| member.candidate.lexical_hints().iter().map(String::as_str))
        .collect();
    candidate = candidate.with_lexical_hints(crate::claim::normalize_lexical_query_hints(&hints)?);
    let combined = combined
        .ok_or_else(|| invalid_consolidation("merge has no verified members"))?
        .restrict(meet);
    // A claim's times are Unix seconds; the wake's clock is milliseconds
    // (FIX 8695).
    let at = now_ms / 1_000;
    Ok(VerifiedCandidate {
        proposal: PromotionCandidate {
            claim_id,
            candidate,
            evidence_turn_refs: evidence,
            provenance_chain: chain,
            supersedes: conflict.prior_head,
            evidence_meet: meet,
            occurred: TimeRange { start: at, end: at },
            learned_at: at,
            decisions,
        },
        evidence: combined,
        answers: Vec::new(),
    })
}

fn contradiction_gap(
    conflict: &ConflictSet,
    members: &[&VerifiedCandidate],
    now_ms: u64,
) -> Result<(ReflectionGap, VerifiedEvidenceSet)> {
    let mut evidence: Vec<EntityId> = Vec::new();
    let mut combined: Option<VerifiedEvidenceSet> = None;
    for member in members {
        combined = Some(combined.map_or_else(
            || member.evidence.clone(),
            |old| old.union(&member.evidence),
        ));
        for turn in &member.evidence_turn_refs {
            if !evidence.contains(turn) {
                evidence.push(*turn);
            }
        }
    }
    let combined =
        combined.ok_or_else(|| invalid_consolidation("conflict has no verified evidence"))?;
    Ok((
        ReflectionGap {
            kind: ReflectionGapKind::ContradictionLeftStanding,
            subject: conflict.identity.subject,
            evidence_turn_refs: evidence,
            evidence_refs: combined.locators(),
            verified_evidence: Some(combined.envelope(Vec::new())),
            first_seen: now_ms,
            last_seen: now_ms,
            escalations: 0,
            decayed: false,
        },
        combined,
    ))
}

impl DreamerAttemptExecutor for ConsolidationExecutor<'_> {
    async fn execute(
        &mut self,
        attempt: &crate::dreamer_runner::DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        // A resident dreams under its own stamp on the model its host lends
        // it (OF-490), and spends its free time for its human so too (FIX
        // 4453); this Dreamer-bound executor never runs either. Each such
        // park waits on the host's loan, no owner act: it resumes after its
        // retry delay (FIX 7272).
        if attempt.status.payload.attempt_type
            == crate::dreamer_runner::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND
            || attempt.status.payload.attempt_type
                == crate::dreamer_runner::DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND
        {
            return Ok(DreamerAttemptExecution::Park {
                reason: "resident dreaming needs its host's model".to_owned(),
                cause: DreamerParkCause::Retry,
            });
        }
        // A TASK realizes on the model and wording its host lends; this
        // executor holds neither.
        if attempt.status.payload.attempt_type
            == crate::dreamer_runner::DREAMER_TASK_REALIZE_ATTEMPT_KIND
        {
            return Ok(DreamerAttemptExecution::Park {
                reason: crate::dreamer_consolidation::TASK_REALIZE_UNLENT_PARK_REASON.to_owned(),
                cause: DreamerParkCause::Retry,
            });
        }
        // A weave lens renders on the model its host lends; this executor
        // holds none.
        if attempt.status.payload.attempt_type
            == crate::dreamer_runner::DREAMER_WEAVE_LENS_ATTEMPT_KIND
        {
            return Ok(DreamerAttemptExecution::Park {
                reason: crate::dreamer_consolidation::WEAVE_LENS_UNLENT_PARK_REASON.to_owned(),
                cause: DreamerParkCause::Retry,
            });
        }
        if self.actor
            != ctx
                .vault
                .dreamer_actor_for_attempt(attempt.status.attempt.id)?
        {
            return Err(invalid_consolidation(
                "executor actor is not the queued Dreamer authority",
            ));
        }
        if attempt.status.payload.attempt_type == super::nightly_merge::ATTEMPT {
            return self.run_nightly_merge(attempt, ctx).await;
        }
        if attempt.status.payload.attempt_type == super::nightly_links::ATTEMPT {
            return self.run_nightly_links(attempt, ctx).await;
        }
        if attempt.status.payload.attempt_type
            == crate::dreamer_runner::DREAMER_NOTE_REVIEW_ATTEMPT_KIND
        {
            return self.run_note_review(attempt, ctx).await;
        }
        if attempt.status.payload.attempt_type == crate::dreamer_wake::nightly::CONTINUE_ATTEMPT {
            return crate::dreamer_wake::nightly::continue_nightly(attempt, ctx);
        }
        // A Timer wake's plan parent (FIX 336): its children and remainder
        // landed with it at enqueue, so running it only completes it.
        if attempt.status.payload.attempt_type == crate::dreamer_wake::nightly::PLAN_ATTEMPT {
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            });
        }
        if attempt.status.payload.attempt_type == crate::dreamer_wake::sieve::RUNG_ATTEMPT {
            return self.run_sieve_rungs(attempt, ctx).await;
        }
        if attempt.status.payload.attempt_type == crate::dreamer_wake::follower::FOLLOWER_ATTEMPT {
            return self.run_follower(attempt, ctx).await;
        }
        // The session-end miner carries its own pinned `{session}` payload,
        // not a partition map. Reject a supplied branch scope explicitly,
        // then let the miner's codec validate the exact session ref below.
        let branch_scope =
            if attempt.status.payload.attempt_type == DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE {
                if self.scope.is_some() || attempt.status.payload.parent_attempt.is_some() {
                    return Err(invalid_consolidation(
                        "the miner has no branch resource contract",
                    ));
                }
                None
            } else if attempt.status.payload.attempt_type == DREAMER_GAP_SCAN_ATTEMPT_TYPE {
                super::branch_scope::resolve_scope(
                    ctx.vault,
                    attempt.status.payload.parent_attempt,
                    super::branch_scope::decode_branch_scope(&attempt.status.payload.input)?,
                    self.scope.as_ref(),
                )?
            } else {
                None
            };
        // ED-04 (ONE-1760): the recurring-substitution miner is a
        // consolidation-scope job like the gap scan — deterministic, no LLM
        // step, so it spends no units. The payload shape and the pass itself
        // are the miner's; this arm is the registration.
        if branch_scope.is_some()
            && matches!(
                attempt.status.payload.attempt_type.as_str(),
                DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE | DREAMER_GAP_SCAN_ATTEMPT_TYPE
            )
        {
            return Err(invalid_consolidation(
                "this job has no branch resource contract",
            ));
        }
        if attempt.status.payload.attempt_type == DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE {
            let session = crate::edit_distance::miner::miner_session_from_input(
                &attempt.status.payload.input,
            )?;
            let run = crate::edit_distance::miner::MinerRun {
                session,
                // The QUEUE's run id is the mined proposals' inbox group. A
                // session close enqueues without one, so the miner's own
                // per-sitting group is the ordinary case rather than a fallback
                // for broken rows.
                run_id: attempt
                    .status
                    .attempt
                    .run_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|run_id| !run_id.is_empty())
                    .map_or_else(
                        || crate::edit_distance::miner::miner_run_id(&session),
                        str::to_owned,
                    ),
                // The DEPLOYMENT's claim-authoring actor, which is where the
                // milestone-envelope rule puts that policy: the engine holds no
                // opinion about which agent a host trusts to author claims.
                agent: self.actor,
            };
            crate::edit_distance::miner::run_substitution_miner(ctx.vault, &run)?;
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            });
        }

        if attempt.status.payload.attempt_type == DREAMER_GAP_SCAN_ATTEMPT_TYPE {
            // Gap-scan child attempt: deterministic detectors + queue upsert.
            let turn_ids = decode_partition_payload(&attempt.status.payload.input)?.turn_ids();
            let mut working_set = Vec::new();
            for turn_id in &turn_ids {
                let facts = read_turn_facts(ctx.vault, turn_id)?;
                let role = dreamer_turn_role(
                    facts.speaker.as_deref(),
                    &ctx.vault.config.assistant_display_names,
                );
                working_set.push(WorkingSetTurn {
                    turn_id: *turn_id,
                    role,
                    learned_at: 0,
                    carrier: None,
                    conversation: conversation_of(ctx.vault, turn_id)?,
                });
            }
            return super::gap::run_gap_scan(ctx.vault, &working_set, ctx.now_ms);
        }

        // Direct executor calls and wake-driver calls consume the SAME
        // preparation code. The driver supplies a preselected branch; a direct
        // caller prepares a one-pass view before any model call or write.
        let direct_wake;
        let wake = if let Some(wake) = ctx.prepared_wake {
            wake
        } else {
            direct_wake = super::PreparedWake::prepare_one(
                ctx.vault,
                match attempt.status.attempt.kind.as_str() {
                    crate::dreamer_runner::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND => {
                        crate::dreamer_runner::DreamerConsolidationScope::Micro
                    }
                    crate::dreamer_runner::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND => {
                        crate::dreamer_runner::DreamerConsolidationScope::Meso
                    }
                    crate::dreamer_runner::DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND => {
                        crate::dreamer_runner::DreamerConsolidationScope::Macro
                    }
                    _ => {
                        return Err(invalid_consolidation(
                            "attempt is not a consolidation partition",
                        ));
                    }
                },
                self.scope.as_ref(),
                attempt.status.attempt.id,
            )?;
            &direct_wake
        };
        let plan = match ctx.prepared_attempt.or_else(|| {
            match wake.preparation(attempt.status.attempt.id) {
                Some(super::AttemptPreparation::Ready(plan)) => Some(plan),
                _ => None,
            }
        }) {
            Some(plan) => plan,
            None => {
                return match wake.preparation(attempt.status.attempt.id) {
                    Some(super::AttemptPreparation::Refused {
                        reason,
                        scope_error: true,
                    }) => Err(crate::Error::InvalidConfig((*reason).into())),
                    Some(super::AttemptPreparation::Refused { reason, .. }) => {
                        Err(invalid_consolidation(reason))
                    }
                    // A source away from this replica (OF-534) waits, queued,
                    // for the promotion that brings it back.
                    Some(super::AttemptPreparation::ResidencyDeferred) => {
                        Ok(DreamerAttemptExecution::Deferred {
                            completed_units: 0,
                            retry_at: ctx
                                .now_ms
                                .div_ceil(1_000)
                                .saturating_add(super::RESIDENCY_RETRY_SECS),
                            step_hashes: Vec::new(),
                        })
                    }
                    _ => Err(invalid_consolidation(
                        "consolidation attempt was not prepared at the wake revision",
                    )),
                };
            }
        };
        if plan.attempt_id() != attempt.status.attempt.id
            || !plan.matches_queued(&attempt.status.payload.input)
            || (ctx.prepared_wake.is_some()
                && self.scope.as_ref().is_some()
                && self.scope.as_ref() != plan.scope())
        {
            return Err(invalid_consolidation(
                "executor scope/identity differs from prepared attempt",
            ));
        }
        let branch_scope = super::branch_scope::pin_execution_scope(
            ctx.vault,
            attempt.status.attempt.id,
            plan.scope(),
        )?;
        if branch_scope.as_ref() != plan.scope() {
            return Err(invalid_consolidation(
                "prepared branch scope changed after the wake pin",
            ));
        }
        self.execute_prepared_partition(attempt, ctx, plan, wake)
            .await
    }
}
