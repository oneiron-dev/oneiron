//! The conflict loop of `resolve_conflicts`: each conflicting set decided
//! through the host's ladder, merged, accumulated or escalated, in order.
//! A trap, a checkpoint or a failed set stops the loop with its run.

use std::ops::ControlFlow;

use super::*;
use crate::attempt_queue::AttemptId;
use crate::gate::PolicyManifestResolution;

/// What the conflict loop reads: the assembled candidates and their
/// conflicting sets, the extractor's bound corrections, and the policy.
pub(super) struct ConflictInput<'a> {
    pub(super) candidates: &'a [VerifiedCandidate],
    pub(super) conflicts: &'a [ConflictSet],
    pub(super) corrections: &'a BTreeMap<EntityId, EntityId>,
    pub(super) policy: &'a PolicyManifestResolution,
}

/// What the conflict loop decided, for the survivors after it.
pub(super) struct ResolvedSets {
    pub(super) dropped: BTreeSet<usize>,
    pub(super) merged: Vec<VerifiedCandidate>,
    pub(super) escalated: Vec<(ReflectionGap, VerifiedEvidenceSet)>,
    pub(super) kept_by: BTreeMap<usize, Vec<KeptDecision>>,
    pub(super) answered: BTreeMap<usize, Vec<ResolvedConflictOutput>>,
    pub(super) waiting: bool,
}

impl ConsolidationExecutor<'_> {
    /// Decides each conflicting set in order. `Break` carries the run a trap,
    /// a checkpoint or a failed set ends the attempt with; `Continue` what
    /// every set decided.
    pub(super) async fn resolve_sets(
        &mut self,
        input: ConflictInput<'_>,
        resources: &BranchResources<'_>,
        ctx: &WakeAttemptContext<'_>,
        step_identity: (AttemptId, Option<String>),
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<ControlFlow<PartitionRun, ResolvedSets>> {
        let ConflictInput {
            candidates,
            conflicts,
            corrections,
            policy,
        } = input;
        let mut dropped: BTreeSet<usize> = BTreeSet::new();
        let mut merged: Vec<VerifiedCandidate> = Vec::new();
        let mut escalated: Vec<(ReflectionGap, VerifiedEvidenceSet)> = Vec::new();
        // An accumulated member keeps the pack that kept it, and the first
        // try's open marker its conflict answers (FIX 7325).
        let mut kept_by: BTreeMap<usize, Vec<KeptDecision>> = BTreeMap::new();
        let mut answered: BTreeMap<usize, Vec<ResolvedConflictOutput>> = BTreeMap::new();
        let mut waiting = false;

        for conflict in conflicts {
            let members: Vec<&VerifiedCandidate> = conflict
                .candidate_indexes
                .iter()
                .map(|index| &candidates[*index])
                .collect();
            let prior = conflict
                .prior_head
                .map(|id| resources.prior(id))
                .transpose()?;
            let member_data: Vec<_> = members.iter().map(|member| &member.proposal).collect();
            if super::super::judge_context::fast_path(policy, conflict, &member_data, prior)
                || super::super::judge_context::bound_correction(
                    corrections,
                    conflict,
                    &member_data,
                    prior,
                )
            {
                let mut candidate = (*members[0]).clone();
                candidate.proposal.supersedes = conflict.prior_head;
                for member in &members[1..] {
                    join_decisions(&mut candidate.proposal.decisions, &member.decisions);
                    candidate.sources = crate::skill_optimize::union_source_rows([
                        candidate.sources.take(),
                        member.sources.clone(),
                    ]);
                }
                let answer = ResolvedConflictOutput::of_first_try(
                    ctx.vault,
                    conflict,
                    step_identity.0,
                    vec![candidate.claim_id],
                    "fast_path",
                );
                candidate.answers.extend(answer);
                dropped.extend(conflict.candidate_indexes.iter().copied());
                merged.push(candidate);
                continue;
            }
            let prior_heads = conflict
                .prior_heads
                .iter()
                .map(|id| resources.prior(*id).cloned())
                .collect::<Result<Vec<_>>>()?;
            let step_ctx = DurableStepContext {
                vault: ctx.vault,
                attempt_id: step_identity.0,
                run_id: step_identity.1.clone(),
                envelope_actor: self.actor,
                subject: conflict.identity.subject,
                deadline: Some(ctx.deadline),
                now_ms: ctx.now_ms,
            };
            // Suspended mid-merge, the attempt is parked: STOP and surface the
            // trap. Writing a contradiction gap here would fabricate a
            // `ContradictionLeftStanding` for a merge that never decided
            // (#485-2); accepting partial survivors would drop the rest as done.
            // On resume the memoized steps replay and this merge re-runs to a
            // real resolution.
            let answers = match self
                .decide_conflict(
                    &step_ctx,
                    ctx.deadline,
                    conflict,
                    &members,
                    &prior_heads,
                    resources,
                    charges,
                )
                .await
            {
                Ok(Some(answers)) => answers,
                Ok(None) => return Ok(ControlFlow::Break(PartitionRun::Trapped)),
                Err(error) => {
                    return self
                        .conflict_failed(
                            error,
                            conflict,
                            &members,
                            resources,
                            ctx,
                            step_identity.0,
                            charges,
                        )
                        .map(ControlFlow::Break);
                }
            };
            if ctx.deadline.expired() {
                return Ok(ControlFlow::Break(PartitionRun::Checkpoint));
            }
            // Asked up and not answered yet: neither resolved nor left
            // standing. Its members wait out the pass with it.
            if answers.waiting() {
                dropped.extend(conflict.candidate_indexes.iter().copied());
                waiting = true;
                continue;
            }
            let mut decisions = answers.decisions.clone();
            for member in &members {
                join_decisions(&mut decisions, &member.decisions);
            }
            let resolution = match answers.resolution.as_deref() {
                Some(label @ ("merge" | "supersede")) => {
                    match self
                        .merged_value(
                            &step_ctx,
                            label,
                            answers.identity,
                            conflict,
                            &member_data,
                            &prior_heads,
                            resources.scope(),
                            charges,
                        )
                        .await
                    {
                        Ok(Some(resolution)) => resolution,
                        Ok(None) => return Ok(ControlFlow::Break(PartitionRun::Trapped)),
                        Err(error) => {
                            return self
                                .conflict_failed(
                                    error,
                                    conflict,
                                    &members,
                                    resources,
                                    ctx,
                                    step_identity.0,
                                    charges,
                                )
                                .map(ControlFlow::Break);
                        }
                    }
                }
                Some("accumulate") => MergeResolution::Accumulate,
                // An escalation, or no answer: the contradiction stays standing.
                _ => MergeResolution::Escalate,
            };
            if ctx.deadline.expired() {
                return Ok(ControlFlow::Break(PartitionRun::Checkpoint));
            }
            match resolution {
                // Keep every member, each with the pack that kept it.
                MergeResolution::Accumulate => {
                    let answer = ResolvedConflictOutput::of_first_try(
                        ctx.vault,
                        conflict,
                        step_identity.0,
                        members.iter().map(|member| member.claim_id).collect(),
                        "accumulate",
                    );
                    for index in &conflict.candidate_indexes {
                        join_decisions(kept_by.entry(*index).or_default(), &answers.decisions);
                        answered.entry(*index).or_default().extend(answer.clone());
                    }
                }
                MergeResolution::Merge {
                    value,
                    candidate_ref,
                } => {
                    let mut selected = conflict.clone();
                    if let Some(id) = candidate_ref {
                        let member = members
                            .iter()
                            .find(|member| member.claim_id == id)
                            .ok_or_else(|| {
                                invalid_consolidation("merge selected an unlisted candidate")
                            })?;
                        selected.identity =
                            super::super::routing::candidate_keys(member, resources.key_rules())?
                                .identity;
                        let matching = resources.matching_priors(member, resources.key_rules())?;
                        selected.prior_head = (matching.len() == 1).then(|| matching[0].0);
                    } else if members.iter().any(|member| {
                        candidate_facts(&member.candidate)
                            .is_ok_and(|facts| facts.predicate != conflict.identity.predicate)
                    }) {
                        return Err(invalid_consolidation(
                            "cross-predicate merge requires a candidate identity",
                        )
                        .into());
                    }
                    dropped.extend(conflict.candidate_indexes.iter().copied());
                    let mut output = merged_candidate(
                        &selected,
                        &members,
                        &prior_heads,
                        value,
                        decisions,
                        step_identity.0,
                        ctx.now_ms,
                    )?;
                    // The marker is the original conflict's, minted before
                    // a cross-predicate selection moved its identity.
                    let answer = ResolvedConflictOutput::of_first_try(
                        ctx.vault,
                        conflict,
                        step_identity.0,
                        vec![output.claim_id],
                        answers.resolution.as_deref().unwrap_or("merge"),
                    );
                    output.answers.extend(answer);
                    merged.push(output);
                }
                MergeResolution::Escalate => {
                    // A durable outage fallback is still an unresolved question,
                    // not permission to lose the prior head's conflict marker.
                    resources.require_output(resources.scope())?;
                    super::super::open_conflict::park_open_conflict(
                        ctx.vault,
                        self.actor,
                        step_identity.0,
                        conflict,
                        &members,
                        &decisions,
                        &resources.write_fence(),
                        ctx.now_ms,
                    )?;
                    dropped.extend(conflict.candidate_indexes.iter().copied());
                    escalated.push(contradiction_gap(conflict, &members, ctx.now_ms)?);
                }
            }
        }
        Ok(ControlFlow::Continue(ResolvedSets {
            dropped,
            merged,
            escalated,
            kept_by,
            answered,
            waiting,
        }))
    }
}
