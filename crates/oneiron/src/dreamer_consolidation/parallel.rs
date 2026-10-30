//! Read-only neighbourhood fan-out, followed by one parent-owned merge. The
//! fan-out is the child's extraction port (OF-498a,
//! `NeighbourhoodExtractionPort`): by default its slices on the extraction
//! role, side by side. A thing's branch first runs its scoped agent (FIX
//! 7508, `thing_agent`), whose extracts are these same durable steps.
use std::sync::Arc;
use std::time::Instant;

use rmpv::Value;

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
use crate::attempt_queue::{AttemptId, ReadSetProducer};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::dreamer_wake::WakeAttemptContext;
use crate::llm::{
    DurableStepContext, DurableStepError, DurableStepResult, StepEffectBinding, StepOutcome,
};

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
        super::neighbourhood::pin(
            ctx.vault,
            super::neighbourhood::ListingPin::attempt(attempt_id),
            resources.known(),
        )?;
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
        // A candidate whose correction waits on a role's answer is read again
        // when the attempt comes back; what the pass took is kept.
        Ok(if waiting {
            run.waiting_on_ask(ctx.now_ms)
        } else {
            run
        })
    }
}
