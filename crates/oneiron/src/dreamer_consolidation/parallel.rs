//! Read-only neighbourhood fan-out, followed by one parent-owned merge.
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

use rmpv::Value;

use super::executor::{ConsolidationExecutor, PartitionRun, extraction};
use super::failure_rules::{self, Stage};
use super::partition::decode_partition_payload;
use super::resources::{BranchResources, FallbackOutputPin};
use super::roles::DREAMER_EXTRACTION_ROLE;
use super::step_charge::StepChargeTally;
use crate::attempt_queue::AttemptId;
use crate::dreamer_wake::WakeAttemptContext;
use crate::llm::{
    DurableStepContext, DurableStepError, DurableStepResult, StepEffectBinding, StepOutcome,
    call_as_step_checked,
};

/// Poll at most `width` children together. A ready error is just a slot
/// value: every admitted sibling drains, and outputs retain spawn order.
async fn ordered_slots<F: Future>(jobs: Vec<F>, width: usize) -> Vec<F::Output> {
    let count = jobs.len();
    let mut queued = jobs.into_iter().enumerate();
    let mut active: Vec<(usize, Pin<Box<F>>)> = Vec::new();
    let mut slots: Vec<Option<F::Output>> = (0..count).map(|_| None).collect();
    let mut completed = 0;
    poll_fn(|cx| {
        loop {
            while active.len() < width {
                let Some((index, job)) = queued.next() else {
                    break;
                };
                active.push((index, Box::pin(job)));
            }
            let mut progress = false;
            let mut index = 0;
            while index < active.len() {
                match active[index].1.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        let (slot, _) = active.remove(index);
                        slots[slot] = Some(value);
                        completed += 1;
                        progress = true;
                    }
                    Poll::Pending => index += 1,
                }
            }
            if completed == count {
                return Poll::Ready(());
            }
            if !progress {
                return Poll::Pending;
            }
        }
    })
    .await;
    slots
        .into_iter()
        .map(|slot| slot.expect("completed extraction slot"))
        .collect()
}

impl ConsolidationExecutor<'_> {
    pub(super) async fn run_partition_attempt(
        &mut self,
        payload_input: &Value,
        resources: &BranchResources<'_>,
        ctx: &WakeAttemptContext<'_>,
        attempt_id: AttemptId,
        run_id: Option<String>,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<PartitionRun> {
        let (partition, turn_ids, _) = decode_partition_payload(payload_input)?;
        resources.require_output(resources.scope())?;
        resources.require_signals(resources.scope())?;
        super::neighbourhood::pin(ctx.vault, attempt_id, resources.known())?;
        let config = ctx.vault.consolidation_selection()?;
        let (slices, low_trust) =
            resources.extraction_slices(&turn_ids, config.extraction_turns_per_child)?;
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
            subject: partition.conversation_ref,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        let call = self.role(DREAMER_EXTRACTION_ROLE);
        let rules = failure_rules::load(ctx.vault)?;
        let mut requests = Vec::with_capacity(slices.len());
        for slice in &slices {
            let mut request =
                Self::extraction_request(&call, &partition, &slice.transcript, &slice.scope)?;
            if let Some(rules) = &rules {
                rules.bind(Stage::Extraction, &mut request);
            }
            let mut request = ctx
                .vault
                .authorize_model_role(DREAMER_EXTRACTION_ROLE, request, &call.inference)?
                .into_request();
            super::roles::bind_reasoning(ctx.vault, call.backend, &mut request)?;
            requests.push((request.canonical_hash()?, request));
        }
        let jobs = requests
            .iter()
            .map(|(_, request)| {
                call_as_step_checked(
                    &step_ctx,
                    call.backend,
                    self.guard,
                    request.clone(),
                    &extraction::check_extraction_reply,
                )
            })
            .collect();
        let outcomes = ordered_slots(jobs, width).await;

        // Account for ALL terminal siblings before examining any failure.
        // Successful replies are durable memos, so a failed slot can resume
        // without cancelling or paying again for completed siblings.
        let mut replies = Vec::new();
        let mut refused = None;
        let mut trapped = false;
        let mut checkpoint = false;
        for ((slice, (step_hash, _)), outcome) in slices.iter().zip(&requests).zip(outcomes) {
            match outcome {
                Ok(StepOutcome::Finished {
                    response,
                    failure_policy,
                    ..
                }) => {
                    charges.record_terminal(ctx.vault, attempt_id, *step_hash, &response.usage)?;
                    replies.push((slice, *step_hash, response, failure_policy));
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
        if checkpoint || ctx.deadline.expired() {
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
            let (taken, missed) = Self::parse_candidates(&response, resources, &slice.scope)?;
            parsed.extend(taken);
            skipped += missed;
            resources.require_output(resources.scope())?;
            if ctx.deadline.expired() {
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
                &response,
                &slice.turns,
                &slice.scope,
                ctx.now_ms,
                Some(ctx.deadline),
                Some(&resources.write_fence()),
            ) {
                if ctx.deadline.expired() {
                    return Ok(PartitionRun::Checkpoint);
                }
                return Err(error.into());
            }
        }
        // Which listed claim each candidate corrects is decided beside the
        // extraction, as one typed pack over every child's candidates.
        let corrects = match self
            .decide_corrections(&step_ctx, ctx.deadline, &parsed, resources, charges)
            .await
        {
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
        if ctx.deadline.expired() {
            return Ok(PartitionRun::Checkpoint);
        }
        let candidates = Self::build_candidates(
            parsed, &corrects, skipped, &partition, resources, attempt_id, ctx.now_ms,
        );
        // Assembly verifies and collapses evidence across ALL child slots
        // before counting corroboration or routing coupled conflicts.
        self.resolve_conflicts(candidates, resources, ctx, (attempt_id, run_id), charges)
            .await
    }
}
