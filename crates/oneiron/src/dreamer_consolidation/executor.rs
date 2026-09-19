use std::collections::{BTreeMap, BTreeSet};

mod extraction;

use super::resources::BranchResources;
use super::value_projection::{json_to_rmpv, rmpv_to_json};
use rmpv::Value;

use super::conflict::{ConflictIdentity, ConflictSet, candidate_facts, deterministic_claim_id};
use super::gap::{ReflectionGap, ReflectionGapKind, scan_reflection_gaps, upsert_gap_queue};
use super::partition::{ConsolidationPartitionKey, decode_partition_payload};
use super::provenance::{
    ConsolidationProvenanceHop, ConsolidationSink, PromotionCandidate, source_meet,
};
use super::support::{
    DREAMER_GAP_SCAN_ATTEMPT_TYPE, DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE, TURN_BODY_FACET_REF_KEY,
    invalid_consolidation,
};
use super::watermark::{WorkingSetTurn, conversation_of, read_turn_facts};
use crate::claim::{ClaimSource, ClaimSubject};
use crate::dreamer_runner::{DreamerClaimAuthoringStrategy, dreamer_turn_role};
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepResult, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence, call_as_step,
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
    pub sink: &'a mut dyn ConsolidationSink,
    /// Trusted caller's exact branch scope, in addition to actor authority.
    /// A queued scope is its upper bound. None inherits that scope, or admits
    /// only the queued partition's resources when no caller bound was queued.
    pub scope: Option<crate::llm::Scope>,
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
enum PartitionRun {
    Completed {
        candidates: Vec<PromotionCandidate>,
        spent: u64,
    },
    Trapped,
    Held {
        candidates: Vec<PromotionCandidate>,
        spent: u64,
    },
}

impl ConsolidationExecutor<'_> {
    async fn run_partition_attempt(
        &mut self,
        payload_input: &Value,
        resources: &BranchResources<'_>,
        ctx: &WakeAttemptContext<'_>,
        attempt_id: crate::attempt_queue::AttemptId,
        run_id: Option<String>,
    ) -> DurableStepResult<PartitionRun> {
        let run_id_ref = run_id.as_ref();
        let (partition, turn_ids, _watermark) = decode_partition_payload(payload_input)?;

        resources.require_output(resources.scope())?;
        resources.require_signals(resources.scope())?;
        let transcript = resources.transcript(resources.scope(), &turn_ids)?;

        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: run_id_ref.cloned(),
            envelope_actor: self.actor,
            subject: partition.conversation_ref,
            pinned_config: None,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let request = self.extraction_request(&partition, &transcript, resources.scope());
        let outcome = call_as_step(&step_ctx, self.backend, self.guard, request).await?;
        let (response, spent) = match outcome {
            StepOutcome::Finished { response, .. } => {
                let spent = response
                    .usage
                    .input
                    .total
                    .saturating_add(response.usage.output.total);
                (response, spent)
            }
            // The extraction step suspended: the attempt is parked. Surface the
            // trap so `execute` parks it for resume instead of completing an
            // empty extraction (#485-1).
            StepOutcome::Trapped(_) => return Ok(PartitionRun::Trapped),
        };
        let candidates = self.decode_candidates(
            &partition,
            &response,
            resources.scope(),
            attempt_id,
            ctx.now_ms,
        )?;
        resources.validate_candidates(resources.scope(), &candidates)?;
        resources.require_output(resources.scope())?;
        super::extracted_people::mint_extracted_people(
            ctx.vault,
            &response,
            &turn_ids,
            resources.scope(),
            ctx.now_ms,
        )?;
        match self
            .resolve_conflicts(
                candidates,
                resources,
                ctx,
                attempt_id_for_steps(attempt_id, run_id_ref),
            )
            .await?
        {
            PartitionRun::Completed {
                candidates,
                spent: merge_spent,
            } => Ok(PartitionRun::Completed {
                candidates,
                spent: spent.saturating_add(merge_spent),
            }),
            PartitionRun::Trapped => Ok(PartitionRun::Trapped),
            PartitionRun::Held {
                candidates,
                spent: merge_spent,
            } => Ok(PartitionRun::Held {
                candidates,
                spent: spent.saturating_add(merge_spent),
            }),
        }
    }

    /// Scoped LLM merge over conflicting sets — ONLY conflicting sets. One
    /// `call_as_step` per set with the pinned outcome vocabulary:
    /// `merge` (one merged value) | `supersede` (single prior head — with no
    /// prior in scope it degrades to merge) | `accumulate` (multi-value
    /// predicates keep all) | `escalate` (drop the set to the gap queue as
    /// `ContradictionLeftStanding`; contradictions never land silently).
    async fn resolve_conflicts(
        &mut self,
        candidates: Vec<PromotionCandidate>,
        resources: &BranchResources<'_>,
        ctx: &WakeAttemptContext<'_>,
        step_identity: (crate::attempt_queue::AttemptId, Option<String>),
    ) -> DurableStepResult<PartitionRun> {
        let assembled = super::assembly::assemble(ctx.vault, resources, candidates, ctx.now_ms)?;
        let candidates = assembled.candidates;
        let conflicts = assembled.conflicts;
        if conflicts.is_empty() {
            return Ok(if assembled.held {
                PartitionRun::Held {
                    candidates,
                    spent: 0,
                }
            } else {
                PartitionRun::Completed {
                    candidates,
                    spent: 0,
                }
            });
        }

        let mut dropped: BTreeSet<usize> = BTreeSet::new();
        let mut merged: Vec<PromotionCandidate> = Vec::new();
        let mut escalated: Vec<ReflectionGap> = Vec::new();
        let mut spent = 0_u64;

        for conflict in &conflicts {
            let members: Vec<&PromotionCandidate> = conflict
                .candidate_indexes
                .iter()
                .map(|index| &candidates[*index])
                .collect();
            let request = self.merge_request(&conflict.identity, &members, resources.scope())?;
            let step_ctx = DurableStepContext {
                vault: ctx.vault,
                attempt_id: step_identity.0,
                run_id: step_identity.1.clone(),
                envelope_actor: self.actor,
                subject: conflict.identity.subject,
                pinned_config: None,
                deadline: Some(ctx.deadline),
                now_ms: ctx.now_ms,
            };
            let outcome = match call_as_step(&step_ctx, self.backend, self.guard, request).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    // Budget/consent traps are StepOutcome, not judge outages.
                    // A failed admitted judge leaves an observable open question.
                    resources.require_output(resources.scope())?;
                    super::open_conflict::park_open_conflict(
                        ctx.vault,
                        self.actor,
                        step_identity.0,
                        conflict,
                        &members,
                        ctx.now_ms,
                    )?;
                    return Err(error);
                }
            };
            let response = match outcome {
                StepOutcome::Finished { response, .. } => {
                    spent = spent.saturating_add(
                        response
                            .usage
                            .input
                            .total
                            .saturating_add(response.usage.output.total),
                    );
                    response
                }
                StepOutcome::Trapped(_) => {
                    // Suspended mid-merge: the attempt is parked. STOP and surface
                    // the trap. Writing a contradiction gap here would fabricate
                    // a `ContradictionLeftStanding` for a merge that never
                    // decided (#485-2); accepting partial survivors would drop
                    // the rest as done. On resume the memoized steps replay and
                    // this merge re-runs to a real resolution.
                    return Ok(PartitionRun::Trapped);
                }
            };

            match decode_merge_resolution(&response)? {
                MergeResolution::Accumulate => {} // keep every member
                MergeResolution::Merge { value } => {
                    dropped.extend(conflict.candidate_indexes.iter().copied());
                    merged.push(merged_candidate(
                        conflict,
                        &members,
                        value,
                        step_identity.0,
                        ctx.now_ms,
                    ));
                }
                MergeResolution::Escalate => {
                    dropped.extend(conflict.candidate_indexes.iter().copied());
                    escalated.push(contradiction_gap(conflict, &members, ctx.now_ms));
                }
            }
        }

        if !escalated.is_empty() {
            resources.upsert_gaps(resources.scope(), escalated, ctx.now_ms)?;
        }

        let mut surviving: Vec<PromotionCandidate> = candidates
            .into_iter()
            .enumerate()
            .filter_map(|(index, candidate)| (!dropped.contains(&index)).then_some(candidate))
            .collect();
        surviving.extend(merged);
        Ok(if assembled.held {
            PartitionRun::Held {
                candidates: surviving,
                spent,
            }
        } else {
            PartitionRun::Completed {
                candidates: surviving,
                spent,
            }
        })
    }

    fn merge_request(
        &self,
        identity: &ConflictIdentity,
        members: &[&PromotionCandidate],
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        let mut lines = String::new();
        for member in members {
            let facts = candidate_facts(&member.candidate)?;
            lines.push_str(&format!(
                "- predicate: {} value: {}\n",
                facts.predicate,
                serde_json::to_string(&rmpv_to_json(&facts.value)).unwrap_or_default()
            ));
        }
        let system = "Conflicting values were extracted for one claim identity. Respond \
             with JSON: {\"resolution\": \"merge\"|\"accumulate\"|\"escalate\", \
             \"value\": <json when resolution is merge>}. Choose accumulate only for \
             genuinely multi-valued predicates; escalate real contradictions.";
        Ok(LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                scope: scope.clone(),
                purpose: CallPurpose::Consolidation,
                class: CallClass::BestEffort,
                tier: TierPrecedence {
                    per_call: None,
                    vault_policy: None,
                    purpose_default: None,
                    global_default: ModelTierRef("consolidation".to_owned()),
                },
                response_format: ResponseFormat::Json {
                    schema: serde_json::json!({"type": "object"}),
                },
                locality: ModelLocality::OwnServer,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: system.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: format!("predicate {}\n{lines}", identity.predicate),
                    }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        })
    }
}

enum MergeResolution {
    Merge { value: Value },
    Accumulate,
    Escalate,
}

fn decode_merge_resolution(response: &LlmResponse) -> Result<MergeResolution> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let parsed: serde_json::Value = serde_json::from_str(text.trim())
        .map_err(|_| invalid_consolidation("merge response must be JSON"))?;
    match parsed.get("resolution").and_then(|value| value.as_str()) {
        // With no prior head in scope, supersede degrades to merge (D7: at
        // most one prior head; the promotion writer owns the supersession).
        Some("merge" | "supersede") => Ok(MergeResolution::Merge {
            value: json_to_rmpv(parsed.get("value").unwrap_or(&serde_json::Value::Null)),
        }),
        Some("accumulate") => Ok(MergeResolution::Accumulate),
        Some("escalate") => Ok(MergeResolution::Escalate),
        _ => Err(invalid_consolidation("unknown merge resolution")),
    }
}

fn merged_candidate(
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    value: Value,
    attempt_id: crate::attempt_queue::AttemptId,
    now_ms: u64,
) -> PromotionCandidate {
    let mut evidence: Vec<EntityId> = Vec::new();
    let mut chain: Vec<ConsolidationProvenanceHop> = Vec::new();
    let mut meet = ClaimSource::UserStated;
    let mut confidence = 0.0_f32;
    for member in members {
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
    let claim_id = deterministic_claim_id(
        attempt_id,
        conflict.identity.subject,
        &conflict.identity.predicate,
        &value,
        conflict.identity.world,
        conflict.identity.facet,
        conflict.identity.rel,
    );
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
    if let Some(facet) = conflict.identity.facet {
        candidate = candidate.with_scope(Value::Map(vec![(
            Value::from(TURN_BODY_FACET_REF_KEY),
            Value::Binary(facet.as_bytes().to_vec()),
        )]));
    }
    PromotionCandidate {
        claim_id,
        candidate,
        evidence_turn_refs: evidence,
        provenance_chain: chain,
        supersedes: conflict.prior_head,
        evidence_meet: meet,
        occurred: TimeRange {
            start: now_ms,
            end: now_ms,
        },
        learned_at: now_ms,
    }
}

fn contradiction_gap(
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    now_ms: u64,
) -> ReflectionGap {
    let mut evidence: Vec<EntityId> = Vec::new();
    for member in members {
        for turn in &member.evidence_turn_refs {
            if !evidence.contains(turn) {
                evidence.push(*turn);
            }
        }
    }
    ReflectionGap {
        kind: ReflectionGapKind::ContradictionLeftStanding,
        subject: conflict.identity.subject,
        evidence_turn_refs: evidence,
        first_seen: now_ms,
        last_seen: now_ms,
        escalations: 0,
        decayed: false,
    }
}

fn attempt_id_for_steps(
    attempt_id: crate::attempt_queue::AttemptId,
    run_id: Option<&String>,
) -> (crate::attempt_queue::AttemptId, Option<String>) {
    (attempt_id, run_id.cloned())
}

impl DreamerAttemptExecutor for ConsolidationExecutor<'_> {
    async fn execute(
        &mut self,
        attempt: &crate::dreamer_runner::DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if self.actor
            != ctx
                .vault
                .dreamer_actor_for_attempt(attempt.status.attempt.id)?
        {
            return Err(invalid_consolidation(
                "executor actor is not the queued Dreamer authority",
            ));
        }
        let branch_scope = super::branch_scope::resolve_scope(
            ctx.vault,
            attempt.status.payload.parent_attempt,
            super::branch_scope::decode_branch_scope(&attempt.status.payload.input)?,
            self.scope.as_ref(),
        )?;
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
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }

        if attempt.status.payload.attempt_type == DREAMER_GAP_SCAN_ATTEMPT_TYPE {
            // Gap-scan child attempt: deterministic detectors + queue upsert.
            let (_, turn_ids, _) = decode_partition_payload(&attempt.status.payload.input)?;
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
                    conversation: conversation_of(ctx.vault, turn_id)?,
                });
            }
            let gaps = scan_reflection_gaps(ctx.vault, &working_set, ctx.now_ms)?;
            upsert_gap_queue(ctx.vault, gaps, ctx.now_ms)?;
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }

        let (partition, turns, _) = decode_partition_payload(&attempt.status.payload.input)?;
        let resources = BranchResources::open(
            ctx.vault,
            self.actor,
            partition,
            &turns,
            attempt.status.attempt.id,
            branch_scope.as_ref(),
        )?;
        let run_id = attempt.status.attempt.run_id.clone();
        match self
            .run_partition_attempt(
                &attempt.status.payload.input,
                &resources,
                ctx,
                attempt.status.attempt.id,
                run_id,
            )
            .await
        {
            Ok(PartitionRun::Completed { candidates, spent }) => {
                resources.accept(resources.scope(), self.sink, candidates)?;
                Ok(DreamerAttemptExecution::Completed {
                    completed_units: spent,
                })
            }
            Ok(PartitionRun::Held { candidates, spent }) => {
                resources.accept(resources.scope(), self.sink, candidates)?;
                let _ = spent;
                Ok(DreamerAttemptExecution::Park {
                    reason: "consolidation selection hold".into(),
                })
            }
            // The step layer already parked the trapped attempt; Park it for resume
            // WITHOUT accepting candidates or completing it (#485-1, #485-2).
            Ok(PartitionRun::Trapped) => Ok(DreamerAttemptExecution::Park {
                reason: "durable step trapped for resume".to_owned(),
            }),
            Err(crate::llm::DurableStepError::DeadlineHardCut) => {
                Ok(DreamerAttemptExecution::Park {
                    reason: crate::dreamer_wake::DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                })
            }
            Err(crate::llm::DurableStepError::FinalizeRefused) => {
                Ok(DreamerAttemptExecution::Park {
                    reason: "wake pass finalize window".to_owned(),
                })
            }
            Err(crate::llm::DurableStepError::Engine(error)) => Err(error),
            Err(other) => Ok(DreamerAttemptExecution::Park {
                reason: other.to_string(),
            }),
        }
    }
}
