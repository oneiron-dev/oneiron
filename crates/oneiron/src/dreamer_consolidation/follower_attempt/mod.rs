//! The follower's attempt (FIX 7510): one queued per session, on the
//! extraction role's route and the wake's budget, deadline and durable
//! step layer. It replaces the unsampled owed novelty rung's per-span calls
//! with batched readings over the session's retained prefix; typing, the
//! sampled audits and the window audits keep their own jobs. Each pass
//! takes the session's next step (a suffix to drain or prepare, or a
//! keyframe to fold) until nothing is owed, the deadline comes, or a step
//! parks. A suffix the provider refuses as a request hands its spans back
//! to their own rungs, as does a fold the provider refuses, so the
//! follower never stops work the per-span path would do.

mod output;
mod request;

use super::executor::ConsolidationExecutor;
use super::roles::{DREAMER_EXTRACTION_ROLE, RoleCall, bind_reasoning};
use super::step_charge::{StepChargeTally, reply_text, retry_fallback};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::follower::{
    self, AskWork, CallEvidence, FoldWork, FollowerCall, KeyframeCommit, Next, Pin, Publication,
    Receipt, Sizing, Writer,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext, WakeRecipePolicy};
use crate::llm::{
    DurableStepContext, DurableStepError, LlmRequest, LlmResponse, ModelLocality, StepOutcome,
    call_as_step_checked,
};
use crate::{EntityId, Error, Result};

/// Why a follower call parks on a deterministic fallback.
const FOLLOWER_FALLBACK: &str = "follower call requires a model reading";

/// One pass's fixed inputs.
struct Leg<'c> {
    attempt: &'c DreamerAdmittedAttempt,
    ctx: &'c WakeAttemptContext<'c>,
    call: &'c RoleCall<'c>,
    locality: ModelLocality,
    policy: &'c WakeRecipePolicy,
    sizing: Sizing,
    key: [u8; 32],
    writer: Writer,
}

impl Leg<'_> {
    fn follower_call(&self) -> FollowerCall<'_> {
        FollowerCall {
            key: self.key,
            writer: self.writer,
            parent: &self.attempt.status,
            policy: self.policy,
            route: request::route_digest(self.call.model, self.locality),
            sizing: self.sizing,
            now: self.ctx.now_ms / 1_000,
        }
    }

    fn step(&self, actor: crate::WriteActor, subject: EntityId) -> DurableStepContext<'_> {
        DurableStepContext {
            vault: self.ctx.vault,
            attempt_id: self.attempt.status.attempt.id,
            run_id: self.attempt.status.attempt.run_id.clone(),
            envelope_actor: actor,
            subject,
            deadline: Some(self.ctx.deadline),
            now_ms: self.ctx.now_ms,
        }
    }

    /// A scheduled retry after the policy's rung delay, settling what the
    /// attempt spent: another writer holds the session now, or the suffix
    /// it asked went.
    fn deferred(&self, charges: &StepChargeTally) -> DreamerAttemptExecution {
        DreamerAttemptExecution::Deferred {
            completed_units: charges.units,
            retry_at: self
                .ctx
                .now_ms
                .div_ceil(1_000)
                .saturating_add(self.policy.rung_retry_secs),
            step_hashes: charges.step_hashes.clone(),
        }
    }

    /// The charge of the steps tallied since `before`, for a result row.
    fn receipt(&self, charges: &StepChargeTally, before: (u64, usize)) -> Receipt {
        Receipt {
            completed_units: charges.units.saturating_sub(before.0),
            step_hashes: charges
                .step_hashes
                .get(before.1..)
                .unwrap_or_default()
                .to_vec(),
            run_id: self.attempt.status.attempt.run_id.clone(),
            at: self.ctx.now_ms / 1_000,
        }
    }
}

/// Why a request could not go out.
enum Refusal {
    Error(Error),
    Unhashed,
}

/// `request` authorized for the extraction role with its reasoning bound,
/// and its step hash.
fn admit(
    leg: &Leg<'_>,
    request: LlmRequest,
) -> std::result::Result<(LlmRequest, [u8; 32]), Refusal> {
    let mut request = leg
        .ctx
        .vault
        .authorize_model_role(DREAMER_EXTRACTION_ROLE, request, &leg.call.inference)
        .map_err(Refusal::Error)?
        .into_request();
    bind_reasoning(leg.ctx.vault, leg.call.backend, &mut request).map_err(Refusal::Error)?;
    let hash = request.canonical_hash().map_err(|_| Refusal::Unhashed)?;
    Ok((request, hash))
}

/// The park a refused request makes.
fn refused(charges: &StepChargeTally, refusal: &Refusal) -> DreamerAttemptExecution {
    match refusal {
        Refusal::Error(error) => charges.park_on_error(error),
        Refusal::Unhashed => {
            charges.park_for("follower request did not hash", DreamerParkCause::Retry)
        }
    }
}

/// An engine error once the attempt has spent: it parks and settles what it
/// spent, as an error before any spend fails the attempt.
fn engine(charges: &StepChargeTally, error: Error) -> Result<DreamerAttemptExecution> {
    if charges.units == 0 {
        Err(error)
    } else {
        Ok(charges.park_on_error(&error))
    }
}

/// One fold's progress: the evidence of each call and the folded texts.
#[derive(Default)]
struct FoldRun {
    calls: Vec<CallEvidence>,
    folded: Vec<String>,
}

impl ConsolidationExecutor<'_> {
    pub(super) async fn run_follower(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if self.scope.is_some() {
            return Err(Error::InvalidConfig(
                "the sieve follower does not accept a branch scope".into(),
            ));
        }
        let key = follower::check_input(&attempt.status.payload.input)?;
        let (units, step_hashes) = follower::unpaid_in(ctx.vault, attempt.status.attempt.id)?;
        let mut charges = StepChargeTally { units, step_hashes };
        let call = RoleCall::resolve(
            &self.roles,
            DREAMER_EXTRACTION_ROLE,
            self.backend,
            &self.model,
            &self.inference.binding,
            self.inference.extraction_egress,
        );
        // A missing locality waits on no owner act (OF-193a).
        let Some(locality) = call.inference.selected_locality() else {
            return Ok(charges.park_for(
                "sieve follower host binding needs locality",
                DreamerParkCause::Retry,
            ));
        };
        let writer = Writer {
            attempt: attempt.status.attempt.id,
            generation: attempt.status.attempt.attempt_count,
        };
        loop {
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
            let policy = match ctx.vault.dreamer_recipe_policy() {
                Ok(policy) => policy,
                Err(error) => return Ok(charges.park_on_error(&error)),
            };
            // Off, every owed span is asked on its own rung again, as before.
            if !policy.follower_enabled {
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units: charges.units,
                    step_hashes: charges.step_hashes.clone(),
                });
            }
            let leg = Leg {
                attempt,
                ctx,
                call: &call,
                locality,
                policy: &policy,
                sizing: Sizing::new(
                    self.roles.follower_window_tokens(),
                    policy.follower_sizing_bytes_per_token,
                ),
                key,
                writer,
            };
            let follower_call = leg.follower_call();
            let next = ctx.vault.with_write_txn_grouped(|txn| {
                follower::next_in_txn(ctx.vault, txn, &follower_call, &request::question)
            });
            let next = match next {
                Ok(next) => next,
                Err(error) => return engine(&charges, error),
            };
            let stop = match next {
                Next::Idle => {
                    return Ok(DreamerAttemptExecution::Completed {
                        completed_units: charges.units,
                        step_hashes: charges.step_hashes.clone(),
                    });
                }
                Next::Fold(work) => self.fold(&leg, &work, &mut charges).await?,
                Next::Ask(work) => self.ask(&leg, &work, &mut charges).await?,
            };
            if let Some(stop) = stop {
                return Ok(stop);
            }
        }
    }

    /// Sends one suffix and publishes its readings; `Some` parks the attempt.
    async fn ask(
        &self,
        leg: &Leg<'_>,
        work: &AskWork,
        charges: &mut StepChargeTally,
    ) -> Result<Option<DreamerAttemptExecution>> {
        let vault = leg.ctx.vault;
        let attempt_id = leg.attempt.status.attempt.id;
        let Some(subject) = work.asked.first().map(|entry| entry.asked.span.turn) else {
            return Err(Error::InvariantViolation("a follower suffix asks nothing"));
        };
        let labels = request::labels(&work.asked);
        let request = match request::ask_request(leg.call.model, leg.locality, work, &labels) {
            Ok(request) => request,
            Err(error) => return Ok(Some(charges.park_on_error(&error))),
        };
        let (request, step_hash) = match admit(leg, request) {
            Ok(admitted) => admitted,
            Err(refusal) => return Ok(Some(refused(charges, &refusal))),
        };
        let step = leg.step(self.actor, subject);
        let candidates: Vec<Vec<EntityId>> = work
            .asked
            .iter()
            .map(|entry| entry.asked.candidates.clone())
            .collect();
        let check_labels = labels.clone();
        let check_candidates = candidates.clone();
        // A fallback whose park would resume as a Retry is refused inside
        // the step, never memoized (FIX 7431); so is a reply off the wire.
        let check = move |response: &LlmResponse| {
            if retry_fallback(response) {
                return Err(FOLLOWER_FALLBACK.to_owned());
            }
            output::decode(response, &check_labels, &check_candidates).map(|_| ())
        };
        let before = (charges.units, charges.step_hashes.len());
        let (response, memoized) = match call_as_step_checked(
            &step,
            leg.call.backend,
            self.guard,
            request,
            &check,
        )
        .await
        {
            Ok(StepOutcome::Finished {
                response,
                memoized,
                failure_policy,
                ..
            }) => {
                if let Err(error) =
                    charges.record_terminal(vault, attempt_id, step_hash, &response.usage)
                {
                    return super::residency::spent_or_deferred(error, leg.ctx, charges).map(Some);
                }
                if failure_policy.is_some() {
                    return match charges.park_on_fallback(
                        vault,
                        attempt_id,
                        step_hash,
                        FOLLOWER_FALLBACK,
                        &response,
                    ) {
                        Ok(parked) => Ok(Some(parked)),
                        Err(error) => {
                            super::residency::spent_or_deferred(error, leg.ctx, charges).map(Some)
                        }
                    };
                }
                (response, memoized)
            }
            Ok(StepOutcome::Trapped { .. }) => {
                return Ok(Some(charges.park_for(
                    "durable step trapped for resume",
                    DreamerParkCause::Signal,
                )));
            }
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(Some(charges.checkpoint()));
            }
            // A refused reading asks again after its retry delay.
            Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
                charges.record_usage(&usage);
                return Ok(Some(charges.park_for(
                    "sieve follower readings refused",
                    DreamerParkCause::Retry,
                )));
            }
            Err(error) if output::refused_request(&error) => {
                if let DurableStepError::SpentLlm { usage, .. } = &error {
                    charges.record_usage(usage);
                }
                return hand_back(leg, work, charges);
            }
            Err(DurableStepError::Engine(error)) if charges.units == 0 => return Err(error),
            Err(error) => {
                return Ok(Some(charges.park_for(
                    "sieve follower step failed",
                    DreamerParkCause::of_step(&error),
                )));
            }
        };
        let Ok(readings) = output::decode(&response, &labels, &candidates) else {
            return Ok(Some(charges.park_for(
                "sieve follower readings refused",
                DreamerParkCause::Retry,
            )));
        };
        let publication = Publication {
            key: leg.key,
            writer: leg.writer,
            seq: work.seq,
            readings: &readings,
            call: output::evidence(&response, step_hash, memoized),
            reported_cache: output::reported_cache(&response, memoized),
            receipt: leg.receipt(charges, before),
        };
        match vault.with_write_txn_grouped(|txn| follower::publish_in_txn(vault, txn, publication))
        {
            Ok(true) => Ok(None),
            Ok(false) => Ok(Some(leg.deferred(charges))),
            Err(error) => engine(charges, error).map(Some),
        }
    }

    /// Folds the work's parts into one keyframe, split and folded again
    /// until one remains, and stands it; `Some` parks the attempt.
    async fn fold(
        &self,
        leg: &Leg<'_>,
        work: &FoldWork,
        charges: &mut StepChargeTally,
    ) -> Result<Option<DreamerAttemptExecution>> {
        let before = (charges.units, charges.step_hashes.len());
        let room = leg
            .sizing
            .room(leg.policy.follower_keyframe_instruction.len());
        let mut run = FoldRun::default();
        let mut level = work.parts.clone();
        // An erase can leave a coverage with no part left: it stands empty.
        let text = if level.is_empty() {
            String::new()
        } else {
            loop {
                let groups = follower::fold_groups(&level, room);
                run.folded = Vec::with_capacity(groups.len());
                for group in &groups {
                    if leg.ctx.deadline.expired() {
                        return Ok(Some(charges.checkpoint()));
                    }
                    if let Some(stop) = self
                        .fold_call(leg, &work.pins, group, charges, &mut run)
                        .await?
                    {
                        return Ok(Some(stop));
                    }
                }
                // One fold left, or a level that folded nothing smaller:
                // every part it holds stands, none cut.
                if run.folded.len() <= 1 || run.folded.len() >= level.len() {
                    break run.folded.join("\n\n");
                }
                level = std::mem::take(&mut run.folded);
            }
        };
        let vault = leg.ctx.vault;
        let commit = KeyframeCommit {
            key: leg.key,
            writer: leg.writer,
            work,
            text,
            calls: run.calls,
            receipt: leg.receipt(charges, before),
        };
        match vault
            .with_write_txn_grouped(|txn| follower::commit_keyframe_in_txn(vault, txn, commit))
        {
            Ok(true) => Ok(None),
            Ok(false) => Ok(Some(leg.deferred(charges))),
            Err(error) => engine(charges, error).map(Some),
        }
    }

    /// One fold call over `group`; its text joins `run`. `Some` parks.
    async fn fold_call(
        &self,
        leg: &Leg<'_>,
        pins: &[Pin],
        group: &[String],
        charges: &mut StepChargeTally,
        run: &mut FoldRun,
    ) -> Result<Option<DreamerAttemptExecution>> {
        let vault = leg.ctx.vault;
        let attempt_id = leg.attempt.status.attempt.id;
        let request = request::fold_request(
            leg.call.model,
            leg.locality,
            &leg.policy.follower_keyframe_instruction,
            group,
            pins,
        );
        let (request, step_hash) = match admit(leg, request) {
            Ok(admitted) => admitted,
            Err(refusal) => return Ok(Some(refused(charges, &refusal))),
        };
        let step = leg.step(
            self.actor,
            crate::dreamer_runner::authority::dreamer_actor_id()?,
        );
        let check = |response: &LlmResponse| {
            if retry_fallback(response) {
                return Err(FOLLOWER_FALLBACK.to_owned());
            }
            if reply_text(response).trim().is_empty() {
                return Err("follower keyframe is empty".to_owned());
            }
            Ok(())
        };
        match call_as_step_checked(&step, leg.call.backend, self.guard, request, &check).await {
            Ok(StepOutcome::Finished {
                response,
                memoized,
                failure_policy,
                ..
            }) => {
                if let Err(error) =
                    charges.record_terminal(vault, attempt_id, step_hash, &response.usage)
                {
                    return super::residency::spent_or_deferred(error, leg.ctx, charges).map(Some);
                }
                if failure_policy.is_some() {
                    return match charges.park_on_fallback(
                        vault,
                        attempt_id,
                        step_hash,
                        FOLLOWER_FALLBACK,
                        &response,
                    ) {
                        Ok(parked) => Ok(Some(parked)),
                        Err(error) => {
                            super::residency::spent_or_deferred(error, leg.ctx, charges).map(Some)
                        }
                    };
                }
                run.calls
                    .push(output::evidence(&response, step_hash, memoized));
                run.folded.push(reply_text(&response).trim().to_owned());
                Ok(None)
            }
            Ok(StepOutcome::Trapped { .. }) => Ok(Some(
                charges.park_for("durable step trapped for resume", DreamerParkCause::Signal),
            )),
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                Ok(Some(charges.checkpoint()))
            }
            Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
                charges.record_usage(&usage);
                Ok(Some(charges.park_for(
                    "sieve follower keyframe refused",
                    DreamerParkCause::Retry,
                )))
            }
            // A fold the provider refuses as a request cannot shrink the
            // prefix: every owed span goes back to its own rung.
            Err(error) if output::refused_request(&error) => {
                if let DurableStepError::SpentLlm { usage, .. } = &error {
                    charges.record_usage(usage);
                }
                hand_back_owed(leg, charges)
            }
            Err(DurableStepError::Engine(error)) if charges.units == 0 => Err(error),
            Err(error) => Ok(Some(charges.park_for(
                "sieve follower keyframe step failed",
                DreamerParkCause::of_step(&error),
            ))),
        }
    }
}

/// Hands a refused suffix's spans back to their own rungs; the session goes
/// on with what is left.
fn hand_back(
    leg: &Leg<'_>,
    work: &AskWork,
    charges: &StepChargeTally,
) -> Result<Option<DreamerAttemptExecution>> {
    let vault = leg.ctx.vault;
    let call = leg.follower_call();
    match vault
        .with_write_txn_grouped(|txn| follower::hand_back_in_txn(vault, txn, &call, work.seq))
    {
        Ok(true) => {
            vault.store.notify_attempt_observers();
            Ok(None)
        }
        Ok(false) => Ok(Some(leg.deferred(charges))),
        Err(error) => engine(charges, error).map(Some),
    }
}

/// Hands every owed span back to its own rung, and settles the attempt.
fn hand_back_owed(
    leg: &Leg<'_>,
    charges: &StepChargeTally,
) -> Result<Option<DreamerAttemptExecution>> {
    let vault = leg.ctx.vault;
    let call = leg.follower_call();
    match vault.with_write_txn_grouped(|txn| follower::hand_back_owed_in_txn(vault, txn, &call)) {
        Ok(_) => {
            vault.store.notify_attempt_observers();
            Ok(Some(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
                step_hashes: charges.step_hashes.clone(),
            }))
        }
        Err(error) => engine(charges, error).map(Some),
    }
}
