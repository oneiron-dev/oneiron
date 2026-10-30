//! Read-only neighbourhood fan-out, followed by one parent-owned merge. The
//! fan-out is the child's extraction port (OF-498a,
//! `NeighbourhoodExtractionPort`): by default its slices on the extraction
//! role, side by side. A thing's branch first runs its scoped agent (FIX
//! 7508, `thing_agent`), whose extracts are these same durable steps.
use std::sync::Arc;
use std::time::Instant;

use rmpv::Value;

use super::assembly::tournament_claim_of_verified;
use super::evidence::VerifiedCandidate;
use super::executor::{ConsolidationExecutor, PartitionRun, extraction};
use super::extracted_people::MintNamespace;
use super::failure_rules::{self, Stage};
use super::partition::decode_partition_payload;
use super::resources::{BranchResources, FallbackOutputPin};
use super::roles::DREAMER_EXTRACTION_ROLE;
use super::sieve_ports::{NeighbourhoodExtraction, SliceCall, SliceStep};
use super::stage_log::{PartitionStages, ms_since};
use super::step_charge::StepChargeTally;
use super::thing_agent::{ThingPass, ThingPassEnd};
use crate::{Result, Vault};
use crate::attempt_queue::{AttemptId, ReadSetProducer};
use crate::autoreason_campaign::authoring::{ClaimAuthoringChoice, authoring_campaign};
use crate::autoreason_campaign::beam_promotion::default_strategy;
use crate::autoreason_campaign::research::bound_research_roots;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::critic::{
    CritiqueArtifact, CritiqueProvenance, CritiqueSeverity, CritiqueVerdict, LensCatalog,
};
use crate::dreamer_runner::{
    DreamerClaimAuthoringBatchTier, DreamerClaimAuthoringGateDecision,
    DreamerClaimAuthoringStrategy, DreamerRunnerStore,
};
use crate::dreamer_tournament::{
    DreamerTournamentAuthorFork, DreamerTournamentBordaBallot, DreamerTournamentBranch,
    DreamerTournamentCandidate, DreamerTournamentJudgeClaim, DreamerTournamentRound,
    DreamerTournamentRun, run_dreamer_claim_tournament,
};
use crate::dreamer_wake::{BoundClaimAuthoringSelector, WakeAttemptContext};
use crate::entity_id::bytes_to_hex_lower;
use crate::learning::{LearningCell, LearningPredicate, TypeRef};
use crate::llm::{
    DurableStepContext, DurableStepError, DurableStepResult, StepEffectBinding, StepOutcome,
};
use crate::temporal::TimeRange;
use crate::write_envelope::{WriteEnvelope, WriteProvenance};

impl ConsolidationExecutor<'_> {
    /// The partition's model work; `stages` takes the wall ms of its
    /// correction read and its conflict resolution.
    #[expect(
        clippy::too_many_arguments,
        reason = "the run joins its payload, branch, wake, identity, charge tally and stage clock"
    )]
    pub(super) async fn run_partition_attempt(
        &mut self,
        payload_input: &Value,
        resources: &BranchResources<'_>,
        ctx: &WakeAttemptContext<'_>,
        attempt_id: AttemptId,
        run_id: Option<String>,
        charges: &mut StepChargeTally,
        stages: &mut PartitionStages,
    ) -> DurableStepResult<PartitionRun> {
        // A drain's pause parks the attempt before its preparation burns
        // more of the pass: its checkpoint exit resumes it. Only the pause
        // parks here: an expired deadline still runs its memoized steps
        // below, so a finished partition can land in its grace (FIX 11570).
        if ctx.cancel_requested() {
            return Ok(PartitionRun::Checkpoint);
        }
        let branch = decode_partition_payload(payload_input)?;
        let turn_ids = branch.turn_ids();
        let axes = branch.axes();
        // A one-part branch's steps record its conversation; a multi-part
        // one's its thing, never one of its parts (FIX 7524).
        let subject = match branch.subject() {
            Some(subject) => subject,
            None => {
                crate::EntityId::from_bytes(*attempt_id.as_bytes()).map_err(crate::Error::from)?
            }
        };
        resources.require_output(resources.scope())?;
        resources.require_signals(resources.scope())?;
        super::neighbourhood::pin(ctx.vault, attempt_id, resources.known())?;
        let config = ctx.vault.consolidation_selection()?;
        let (slices, low_trust) =
            resources.extraction_slices(&turn_ids, config.extraction_turns_per_child)?;
        // The attempt's read set: every row its slices' calls read and
        // every row its branch pinned, which every later read of this branch
        // reads within (FIX 7019).
        let read = slices
            .iter()
            .flat_map(|slice| slice.sources.iter().copied())
            .chain(resources.pinned_source_ids())
            .collect();
        super::declare_attempt_reads(
            ctx.vault,
            attempt_id,
            &[ReadSetProducer::DREAMER_EXTRACTION],
        );
        super::record_attempt_reads(
            ctx.vault,
            attempt_id,
            ReadSetProducer::DREAMER_EXTRACTION,
            Some(read),
        );
        let width = if low_trust {
            1
        } else {
            config.extraction_parallelism
        };
        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: run_id.clone(),
            envelope_actor: self.actor,
            subject,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let call = self.role(DREAMER_EXTRACTION_ROLE);
        let rules = failure_rules::load(ctx.vault)?;
        // The people a reply declares are minted under its queued parent's
        // namespace, so nightly children and retry chunks share one (FIX 7506);
        // with no parent, under its lineage's first try (FIX 7579).
        let parent = DreamerRunnerStore::new(ctx.vault)
            .status(attempt_id)?
            .and_then(|status| status.payload.parent_attempt);
        let namespace = MintNamespace::new(
            super::extracted_people::original_try(ctx.vault, attempt_id)?,
            parent,
            axes.world_ref,
            axes.facet_ref,
            resources.scope().relationship,
        );
        // Each child's reply check reads the citations its candidates would
        // carry into verification against the branch's own pinned text: a
        // range verification refuses the whole partition over refuses the
        // reply here, never memoized (FIX 7274).
        let citations = Arc::new(extraction::CitationCheck::new(
            resources, axes, attempt_id, ctx.now_ms, namespace,
        ));
        // A thing's branch runs as one scoped code-mode agent first (FIX
        // 7508): each slice it extracts is the very durable step below, so
        // the fan-out below replays it from its memo. Its low-trust slices
        // are never lent: the fan-out runs them (FIX 9017).
        if branch.thing.is_some() {
            let pass = ThingPass {
                ctx,
                resources,
                slices: &slices,
                step: &step_ctx,
                namespace,
                rules: rules.as_ref(),
                citations: &citations,
                attempt_id,
            };
            if let ThingPassEnd::Run(run) = self.thing_agent_pass(&pass, charges).await? {
                return Ok(run);
            }
        }
        let steps = self
            .roles
            .extraction_ports()
            .neighbourhood_extraction()
            .extract(NeighbourhoodExtraction {
                step: &step_ctx,
                guard: self.guard,
                call,
                slices: slices
                    .iter()
                    .map(|slice| SliceCall {
                        transcript: &slice.transcript,
                        labels: &slice.labels,
                        scope: &slice.scope,
                        sources: &slice.sources,
                    })
                    .collect(),
                namespace,
                rules: rules.as_ref(),
                citations,
                width,
            })
            .await?;
        // A port answers every slice, in order: another count is a fault,
        // never a shorter pairing.
        if steps.len() != slices.len() {
            return Err(crate::Error::InvariantViolation(
                "a child extraction port answered another number of slices",
            )
            .into());
        }

        // Account for ALL terminal siblings before examining any failure.
        // Successful replies are durable memos, so a failed slot can resume
        // without cancelling or paying again for completed siblings.
        let mut replies = Vec::new();
        let mut refused = None;
        let mut trapped = false;
        let mut checkpoint = false;
        for (slice, SliceStep { step_hash, outcome }) in slices.iter().zip(steps) {
            match outcome {
                Ok(StepOutcome::Finished {
                    response,
                    failure_policy,
                    ..
                }) => {
                    charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)?;
                    replies.push((slice, step_hash, response, failure_policy));
                }
                Ok(StepOutcome::Trapped { .. }) => trapped = true,
                Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                    charges.record_usage(&usage);
                    checkpoint = true;
                }
                Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
                    charges.record_usage(&usage);
                    refused.get_or_insert_with(|| {
                        format!("extraction reply refused: {}", errors.join("; "))
                    });
                }
                Err(DurableStepError::FinalizeRefused | DurableStepError::DeadlineHardCut) => {
                    checkpoint = true
                }
                Err(error) => {
                    refused.get_or_insert_with(|| error.to_string());
                }
            }
        }
        if trapped {
            return Ok(PartitionRun::Trapped);
        }
        if checkpoint || ctx.deadline.expired() || ctx.cancel_requested() {
            return Ok(PartitionRun::Checkpoint);
        }
        if let Some(reason) = refused {
            return Ok(PartitionRun::Refused { reason });
        }

        let mut parsed = Vec::new();
        let mut skipped = 0;
        for (slice, step_hash, response, failure_policy) in replies {
            // Live rules, not the policy copy sent before the parallel calls.
            let rules = failure_rules::load(ctx.vault)?;
            let accepted = failure_policy.is_none_or(|decision| {
                decision.consolidation_with_stage(
                    rules
                        .as_ref()
                        .map(|rules| rules.accepts(Stage::Extraction, &response)),
                )
            });
            if !accepted {
                continue;
            }
            let reply = extraction::extraction_reply(&response)?;
            // The deterministic empty fallback contributes no data or trust.
            // A fallback that does contribute output keeps the existing live
            // eligibility fence; it is never turned into ordinary model data.
            if failure_policy.is_some()
                && (!reply.candidates.is_empty() || !reply.persons.is_empty())
            {
                resources.bind_fallback(FallbackOutputPin::new(
                    StepEffectBinding {
                        attempt_id,
                        step_hash,
                    },
                    &response,
                )?)?;
            }
            // Each declared person binds once, before any candidate reads
            // it; the candidates and the mint read these same ids.
            let call = extraction::CallPins {
                labels: &slice.labels,
                pins: resources.pins(),
            };
            let people = super::extracted_people::bind_people(&reply.persons, &call, &namespace);
            let (taken, missed) = Self::parse_candidates(
                &response,
                resources,
                &slice.scope,
                extraction::ReplyContext {
                    call,
                    people: &people,
                },
                &slice.sources,
            )?;
            parsed.extend(taken);
            skipped += missed;
            resources.require_output(resources.scope())?;
            if ctx.deadline.expired() || ctx.cancel_requested() {
                return Ok(PartitionRun::Checkpoint);
            }
            #[cfg(test)]
            if accepted {
                ctx.vault
                    .test_hooks()
                    .run_before_dreamer_person_mint(ctx.vault);
            }
            if let Err(error) = super::extracted_people::mint_extracted_people(
                ctx.vault,
                &people,
                &slice.turns,
                &slice.scope,
                ctx.now_ms,
                Some(ctx.deadline),
                Some(&resources.write_fence()),
            ) {
                if ctx.deadline.expired() || ctx.cancel_requested() {
                    return Ok(PartitionRun::Checkpoint);
                }
                return Err(error.into());
            }
        }
        // Which listed claim each candidate corrects is decided beside the
        // extraction, as one typed pack over every child's candidates.
        let corrections_started = Instant::now();
        let decided = self
            .decide_corrections(&step_ctx, ctx.deadline, &parsed, resources, charges)
            .await;
        stages.corrections_ms = ms_since(corrections_started);
        let corrects = match decided {
            Ok(Some(corrects)) => corrects,
            Ok(None) => return Ok(PartitionRun::Trapped),
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(PartitionRun::Checkpoint);
            }
            Err(DurableStepError::FinalizeRefused | DurableStepError::DeadlineHardCut) => {
                return Ok(PartitionRun::Checkpoint);
            }
            Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
                charges.record_usage(&usage);
                return Ok(PartitionRun::Refused {
                    reason: format!("correction read refused: {}", errors.join("; ")),
                });
            }
            Err(error) => {
                return Ok(PartitionRun::Refused {
                    reason: error.to_string(),
                });
            }
        };
        if ctx.deadline.expired() || ctx.cancel_requested() {
            return Ok(PartitionRun::Checkpoint);
        }
        let (candidates, waiting) = Self::build_candidates(
            parsed, &corrects, skipped, &axes, resources, attempt_id, ctx.now_ms,
        );
        // Assembly verifies and collapses evidence across ALL child slots
        // before counting corroboration or routing coupled conflicts.
        let resolve_started = Instant::now();
        let run = self
            .resolve_conflicts(
                candidates,
                resources,
                ctx,
                (attempt_id, run_id),
                charges,
                stages,
            )
            .await;
        stages.resolve_ms = ms_since(resolve_started).saturating_sub(stages.gap_ms);
        let run = run?;
        // The tournament arm (FIX 9009) refines survivors only when the
        // executor's strategy names it; single-pass returns unchanged.
        let run = if matches!(self.strategy, DreamerClaimAuthoringStrategy::Tournament) {
            self.tournament_refine_run(run, ctx.vault, ctx.now_ms, attempt_id)
        } else {
            run
        };
        // A candidate whose correction waits on a role's answer is read again
        // when the attempt comes back; what the pass took is kept.
        Ok(if waiting {
            run.waiting_on_ask(ctx.now_ms)
        } else {
            run
        })
    }

    /// The tournament arm's survivor refinement (FIX 9008, FIX 9009): every
    /// survivor's per-claim tournament admission, and one deterministic
    /// single-round tournament among the admitted string-valued claims,
    /// written through `run_dreamer_claim_tournament`. The winner lands
    /// there; losers and the inadmissible stay for the sink. Any failure
    /// falls back to the survivors unchanged, never failing the partition.
    fn tournament_refine_run(
        &self,
        run: PartitionRun,
        vault: &Vault,
        now_ms: u64,
        attempt_id: AttemptId,
    ) -> PartitionRun {
        match run {
            PartitionRun::Completed { candidates } => PartitionRun::Completed {
                candidates: self
                    .tournament_refine_candidates(candidates, vault, now_ms, attempt_id),
            },
            PartitionRun::Held {
                candidates,
                retry_at_ms,
            } => PartitionRun::Held {
                candidates: self
                    .tournament_refine_candidates(candidates, vault, now_ms, attempt_id),
                retry_at_ms,
            },
            run => run,
        }
    }

    /// The survivors with the tournament winner removed, or unchanged when
    /// no tournament ran (fewer than two admitted claims, no bound campaign,
    /// or any build or run failure).
    fn tournament_refine_candidates(
        &self,
        candidates: Vec<VerifiedCandidate>,
        vault: &Vault,
        now_ms: u64,
        attempt_id: AttemptId,
    ) -> Vec<VerifiedCandidate> {
        if candidates.len() < 2 {
            return candidates;
        }
        let selector = match tournament_selector(vault) {
            Ok(Some(selector)) => selector,
            Ok(None) => return candidates,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "tournament survivors stay single-pass; the bound campaign was not read"
                );
                return candidates;
            }
        };
        let mut eligible = Vec::new();
        for candidate in &candidates {
            if let Some(confidence) = self.tournament_admitted(vault, &selector, candidate) {
                eligible.push((candidate, confidence));
            }
        }
        if eligible.len() < 2 {
            return candidates;
        }
        let run = match self.tournament_run_of_eligible(&eligible, attempt_id, now_ms) {
            Ok(run) => run,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "tournament survivors stay single-pass; the tournament run did not build"
                );
                return candidates;
            }
        };
        let result = match run_dreamer_claim_tournament(vault, run) {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "tournament survivors stay single-pass; the tournament run did not land"
                );
                return candidates;
            }
        };
        let Some(winner) = result.winner else {
            return candidates;
        };
        tracing::info!(
            claim_id = %winner.claim_id.to_hex(),
            "tournament winner landed through the tournament gate"
        );
        candidates
            .into_iter()
            .filter(|candidate| candidate.claim_id != winner.claim_id)
            .collect()
    }

    /// The incumbent confidence when `candidate` is admitted to the
    /// tournament and carries a string value the judges can read; `None`
    /// when it stays single-pass.
    fn tournament_admitted(
        &self,
        vault: &Vault,
        selector: &BoundClaimAuthoringSelector,
        candidate: &VerifiedCandidate,
    ) -> Option<f32> {
        let claim = tournament_claim_of_verified(candidate, false).ok()?;
        let admission = selector
            .claim_admission(vault, ClaimAuthoringChoice::Tournament, &claim)
            .ok()?;
        let gate = admission
            .gate_decision(DreamerClaimAuthoringBatchTier::batch())
            .ok()?;
        if !matches!(gate, DreamerClaimAuthoringGateDecision::Tournament(_)) {
            return None;
        }
        let text = candidate.candidate.value_str()?;
        if text.is_empty() || text.len() > 8192 {
            return None;
        }
        Some(claim.incumbent_confidence)
    }

    /// One deterministic single-round tournament over the admitted survivors
    /// (FIX 9009): each survivor authors one branch, four deterministic
    /// carryover critiques accept it, and one confidence-ordered blind
    /// ballot ranks them. Model-driven critiques and ballots are future
    /// work; the provenance names the deterministic carryover.
    fn tournament_run_of_eligible(
        &self,
        eligible: &[(&VerifiedCandidate, f32)],
        attempt_id: AttemptId,
        now_ms: u64,
    ) -> Result<DreamerTournamentRun> {
        let catalog = LensCatalog::of366_seed()?;
        let run_id = format!("tournament-{}", bytes_to_hex_lower(attempt_id.as_bytes()));
        let at = now_ms / 1_000;
        let mut branches = Vec::with_capacity(eligible.len());
        let mut branch_attempts = Vec::with_capacity(eligible.len());
        for (candidate, _) in eligible {
            let branch_attempt = AttemptId::from_bytes(candidate.claim_id.as_bytes())?;
            let judge_refs = candidate
                .evidence
                .refs()
                .into_iter()
                .take(64)
                .map(|id| id.to_hex())
                .collect::<Vec<_>>();
            let judge_text = candidate.candidate.value_str().ok_or_else(|| {
                crate::error::Error::InvalidClaimBody("tournament candidate has no judge text")
            })?;
            let author = DreamerTournamentCandidate::new(
                candidate.claim_id.to_hex(),
                branch_attempt,
                candidate.claim_id,
                candidate.candidate.clone(),
                DreamerTournamentJudgeClaim::new(judge_text, judge_refs.clone())?,
                self.strategy.as_str(),
                1,
            )?;
            let provenance = CritiqueProvenance::new(
                self.actor,
                "deterministic-tournament-carryover-v1",
                Some("v1".to_owned()),
            )?;
            let executor = provenance.executor()?;
            let mut critiques = Vec::with_capacity(4);
            for (lens_id, domain) in [
                ("groundedness", "claim_authoring"),
                ("overreach", "claim_authoring"),
                ("temporal", "claim_authoring"),
                ("redundancy", "claim_authoring"),
            ] {
                let lens = catalog.lens(lens_id, domain).ok_or_else(|| {
                    crate::error::Error::InvalidConfig("OF-366 seed catalog lost a lens".into())
                })?;
                critiques.push(CritiqueArtifact::new(
                    format!("t_{}_{}", candidate.claim_id.to_hex(), lens.id),
                    run_id.clone(),
                    branch_attempt,
                    author.candidate_ref.clone(),
                    lens,
                    provenance.clone(),
                    LearningCell::new(LearningPredicate::Reliability, candidate.claim_id)
                        .executor(executor.clone())
                        .type_ref(TypeRef {
                            node_id: "claim_authoring".to_owned(),
                            tree_version: 1,
                        })
                        .axis("quality"),
                    CritiqueVerdict::Accept,
                    CritiqueSeverity::Info,
                    lens.hard_check.then_some(true),
                    judge_refs.clone(),
                    None,
                    at,
                )?);
            }
            let synthesis = DreamerTournamentSynthesisArtifact::survivor(
                format!("t_{}_synthesis", candidate.claim_id.to_hex()),
                &author,
            )?;
            branch_attempts.push(branch_attempt);
            branches.push(DreamerTournamentBranch::new(author, critiques, synthesis)?);
        }
        let mut ranking: Vec<usize> = (0..eligible.len()).collect();
        ranking.sort_by(|&left, &right| {
            eligible[right]
                .1
                .total_cmp(&eligible[left].1)
                .then_with(|| left.cmp(&right))
        });
        let round = DreamerTournamentRound::new(
            branches,
            None,
            vec![DreamerTournamentBordaBallot::new(
                "deterministic-confidence-order",
                ranking,
            )?],
        )?;
        let fork =
            DreamerTournamentAuthorFork::new(run_id.clone(), attempt_id, branch_attempts)?;
        DreamerTournamentRun::new(
            run_id,
            fork,
            eligible.len() as u16,
            1,
            vec![round],
            Vec::new(),
            WriteEnvelope::new(
                self.actor,
                ClaimSource::Generated,
                WriteProvenance::new(Value::from("dreamer-tournament-carryover-v1"))?,
                ClaimApprovalStatus::Proposed,
            ),
            TimeRange { start: at, end: at },
            at,
        )
    }
}

/// The single bound claim-authoring campaign pinning the promoted default,
/// if exactly one does (FIX 9008): `None` while no default is promoted,
/// none is bound, or several bind (ambiguous campaigns stay single-pass).
fn tournament_selector(vault: &Vault) -> Result<Option<BoundClaimAuthoringSelector>> {
    let Some(default) = default_strategy(vault)? else {
        return Ok(None);
    };
    let mut bound = Vec::new();
    for root in bound_research_roots(vault)? {
        if authoring_campaign(vault, root)?.is_some_and(|campaign| campaign.strategy == default) {
            bound.push(root);
        }
    }
    Ok(match bound.as_slice() {
        [root] => Some(BoundClaimAuthoringSelector::new(*root)),
        _ => None,
    })
}
