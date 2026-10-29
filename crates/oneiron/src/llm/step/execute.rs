//! Durable step execution: memo/admission/deadline orchestration with retry and lease settlement.

use super::super::{
    BudgetDenied, BudgetGuard, CallClass, FatalLlmError, LlmBackend, LlmError, LlmRequest,
    LlmResponse,
};
use super::step_claim::{
    decode_step_claim_value, load_step_response, load_step_response_in_txn, log_terminal_step,
    step_claim_matches_request, step_index_lookup, step_index_lookup_in_txn,
};
use super::step_state::{
    StepStateDisposition, StepStateOwners, step_state_delete, step_state_read,
    step_state_write_owned,
};
use super::trap::{open_trap_in_txn, trap_park_owner};
use super::trap_binding::TrapBindingScope;
use super::types::{
    DREAMER_STEP_RETRY_BACKOFF_MS, DreamerTrapKind, DurableStepContext, DurableStepError,
    DurableStepResult, ReplyCheck, StepOutcome, StepProgression,
};
use crate::dreamer_wake::{BudgetLegibilityEnvelope, StepCalls, StepTerminal, current_legibility};
use crate::error::Error;

/// An execution-completion capability, not a decoded claim or memo index.
/// Private fields prevent ordinary claim authors and replay from minting it.
pub(crate) struct ExecutedModelWitness<'vault> {
    vault: &'vault crate::Vault,
    claim_id: crate::EntityId,
    attempt_id: crate::attempt_queue::AttemptId,
    run_ref: Option<String>,
    request_hash: [u8; 32],
    model: super::super::ModelId,
    at_ms: u64,
    /// The step's host-owned envelope actor (FIX 2146).
    actor: crate::EntityId,
    /// A deterministic fallback answered the step: a failed execution.
    fell_back: bool,
}

impl<'vault> ExecutedModelWitness<'vault> {
    fn completed(
        ctx: &DurableStepContext<'vault>,
        claim_id: crate::EntityId,
        request_hash: [u8; 32],
        model: super::super::ModelId,
        fell_back: bool,
    ) -> Self {
        Self {
            vault: ctx.vault,
            claim_id,
            attempt_id: ctx.attempt_id,
            run_ref: ctx.run_id.clone(),
            request_hash,
            model,
            at_ms: ctx.now_ms,
            actor: ctx.envelope_actor.entity_ref(),
            fell_back,
        }
    }

    pub(crate) const fn actor(&self) -> crate::EntityId {
        self.actor
    }

    pub(crate) const fn fell_back(&self) -> bool {
        self.fell_back
    }

    pub(crate) fn parts(
        &self,
    ) -> (
        &'vault crate::Vault,
        crate::EntityId,
        crate::attempt_queue::AttemptId,
        Option<&str>,
        [u8; 32],
        &super::super::ModelId,
        u64,
    ) {
        (
            self.vault,
            self.claim_id,
            self.attempt_id,
            self.run_ref.as_deref(),
            self.request_hash,
            &self.model,
            self.at_ms,
        )
    }
}

/// Durable LLM call: memoize on `(job_id, step_hash)`, spend under a
/// [`BudgetGuard`] lease, retry retryable failures (the ONE retry
/// authority), and persist ONE terminal `dreamer.step` claim.
///
/// Recovery rule (pinned): memo-index hit → memoized terminal response with
/// ZERO admission; private row at ResponseReceived/Logged with payload →
/// finish the write path from the stored payload, ZERO new spend; row at
/// Started or absent → execute normally under a FRESH lease (one bounded
/// re-spend; the prior lease settled/aborted on its own path).
pub async fn call_as_step(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
) -> DurableStepResult<StepOutcome> {
    call_as_step_with_fallbacks(
        ctx,
        backend,
        guard,
        request,
        &super::super::FallbackRegistry::standard(),
    )
    .await
}

/// Durable step whose reply also answers to the caller's `check`: a reply
/// `check` refuses is paid and refused as a schema miss is, and never
/// memoized, so a replay asks again. Only a reply the check passed is ever
/// stored, so a memo or a recovered payload needs no second check. A request
/// with a schema passes the schema's own door first, then the check (FIX
/// 7321).
pub async fn call_as_step_checked(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
    check: &ReplyCheck,
) -> DurableStepResult<StepOutcome> {
    durable_step(
        ctx,
        backend,
        guard,
        request,
        &super::super::FallbackRegistry::standard(),
        Some(check),
        DREAMER_STEP_RETRY_BACKOFF_MS.len(),
    )
    .await
}

/// Durable step with an explicitly owned deterministic runner registry.
pub async fn call_as_step_with_fallbacks(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
    fallbacks: &super::super::FallbackRegistry,
) -> DurableStepResult<StepOutcome> {
    call_as_step_with_fallbacks_and_retries(
        ctx,
        backend,
        guard,
        request,
        fallbacks,
        DREAMER_STEP_RETRY_BACKOFF_MS.len(),
    )
    .await
}

/// The same durable execution path with the caller's own retry count; retries
/// past the engine schedule pace at its last interval (FIX 9930).
pub(super) async fn call_as_step_with_fallbacks_and_retries(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
    fallbacks: &super::super::FallbackRegistry,
    max_retries: usize,
) -> DurableStepResult<StepOutcome> {
    durable_step(ctx, backend, guard, request, fallbacks, None, max_retries).await
}

async fn durable_step(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
    fallbacks: &super::super::FallbackRegistry,
    check: Option<&ReplyCheck>,
    max_retries: usize,
) -> DurableStepResult<StepOutcome> {
    let step_hash = request.canonical_hash()?;

    // A step whose response its owner's erase took is over (KS-2B1): it is
    // never asked, or paid for, again, before any memo, recovery or
    // admission. It names no byte of the response.
    if step_state_read(ctx.vault, ctx.attempt_id, &step_hash)?.is_some_and(|row| row.erased) {
        return Err(erased_step());
    }

    // Memo-hit provenance check (ONE-1344): a stored terminal response is
    // returned ONLY when the WITH-WHAT identity it recorded — model id,
    // purpose, and params hash — is the identity of THIS request. The index key
    // is `(attempt, step_hash)` and the step hash already covers model and
    // params, so a divergent row means the index points at a foreign response
    // (a poisoned/forged index row, a rewritten claim, or a digest collision).
    // Such a row MISSES and the step recomputes; it is never returned.
    if let Some(claim_id) = step_index_lookup(ctx.vault, ctx.attempt_id, &step_hash)? {
        let body = ctx
            .vault
            .get_claim(&claim_id)?
            .ok_or(Error::InvalidClaimBody("dreamer step index claim missing"))?;
        let decoded = decode_step_claim_value(&body.value)?;
        if step_claim_matches_request(&decoded, &request)? {
            let response = load_step_response(ctx.vault, &decoded)?;
            let failure_policy = failure_policy(ctx.vault, &response)?;
            return Ok(StepOutcome::Finished {
                response,
                memoized: true,
                legibility: step_legibility(ctx, guard),
                failure_policy,
            });
        }
    }

    if let Some(row) = step_state_read(ctx.vault, ctx.attempt_id, &step_hash)?
        && matches!(
            row.progression,
            StepProgression::ResponseReceived | StepProgression::Logged
        )
        && let Some(payload) = row.response_payload.as_deref()
    {
        let response: LlmResponse = serde_json::from_slice(payload)?;
        let failure_policy = failure_policy(ctx.vault, &response)?;
        // An erase that took an owner since the answer came keeps the row
        // erased, with nothing filed (FIX 6226).
        if log_terminal_step(
            ctx,
            &step_hash,
            &request,
            &response,
            payload,
            StepTerminal::Recovered,
        )?
        .is_none()
        {
            return Err(erased_step());
        }
        step_state_delete(ctx.vault, ctx.attempt_id, &step_hash)?;
        return Ok(StepOutcome::Finished {
            response,
            memoized: true,
            legibility: step_legibility(ctx, guard),
            failure_policy,
        });
    }

    // Graceful wrap (ONE-1305): once the finalize window opens, NEW steps
    // are refused — memoized hits and stored-payload recoveries above still
    // return without spending.
    if let Some(deadline) = ctx.deadline
        && deadline.in_finalize_window()
    {
        return Err(DurableStepError::FinalizeRefused);
    }

    // An owner already gone keeps the row's erased skeleton (FIX 6226):
    // the step is over before it is admitted, asked or paid for.
    if step_state_write_owned(
        ctx.vault,
        ctx.attempt_id,
        &step_hash,
        StepProgression::Started,
        StepStateOwners::of(ctx),
        None,
        ctx.now_ms,
    )? == StepStateDisposition::Erased
    {
        return Err(erased_step());
    }

    let admission = match guard.admit_for_request(&request) {
        Ok(admission) => admission,
        Err(BudgetDenied::Exhausted) => {
            return budget_trap(ctx, step_hash).inspect(|_| step_budget_hit(ctx, guard, &request));
        }
        Err(denied) => {
            let source = LlmError::from(denied);
            return Err(classified_failure(ctx.vault, source)?);
        }
    };
    // FIX 1662: the request is kept before it is sent, for an exact replay
    // of a failure; a capture that fails never fails the step. It stamps the
    // owners the Started row stamps, and keeps nothing for one gone by the
    // time it writes (FIX 6659).
    // Each corrective call's wire is kept the same way, under its own call
    // index, before it is sent (FIX 6145).
    let (vault, attempt, actor, subject, now_ms) = (
        ctx.vault,
        ctx.attempt_id,
        ctx.envelope_actor.entity_ref(),
        ctx.subject,
        ctx.now_ms,
    );
    let capture = move |wire: &LlmRequest, call: u32| {
        crate::self_heal::blocked_reports::capture_durable_step(
            vault, attempt, step_hash, actor, subject, wire, call, now_ms,
        );
    };
    capture(&request, 0);
    // The admitted call binds to its wake in one short write before it is
    // sent (DOOR-144), best-effort: unobserved, it runs exactly as before.
    // Declared before the settlement guard, it closes after the lease does.
    let calls = StepCalls {
        vault: ctx.vault,
        deadline: ctx.deadline,
        attempt_id: ctx.attempt_id,
        step_hash,
    };
    let mut observed = calls.admitted(guard, &admission.lease, 0);

    // The deadline only gates admission. Once admitted, the provider (and any
    // retries) runs to a terminal response so its lease can settle real usage.
    let generated = ctx
        .vault
        .during_journaled_model_wait(
            ctx.attempt_id,
            step_hash,
            ctx.now_ms,
            super::schema::generate(
                backend,
                &request,
                &admission.lease,
                guard,
                calls,
                &capture,
                check,
                max_retries,
            ),
        )
        .await;
    // A corrective call failed: an earlier response was already answered and
    // paid, whatever usage it reported.
    let answered = matches!(generated, Err(DurableStepError::SpentLlm { .. }));
    // A correction's admission found the budget spent: the step fails as a
    // spent correction does, and the hit still runs its hooks.
    if let Err(DurableStepError::SpentLlm {
        source: LlmError::BudgetDenied(BudgetDenied::Exhausted),
        ..
    }) = &generated
    {
        step_budget_hit(ctx, guard, &request);
    }
    let (generated, failed_usage) = match generated {
        Err(DurableStepError::SpentLlm { source, usage }) => {
            (Err(DurableStepError::Llm(source)), *usage)
        }
        result => (result, super::LlmUsage::zero()),
    };
    let response = match generated {
        Ok(response) => response,
        // An erased answer is terminal: it never triggers a fallback (FIX 6296).
        Err(DurableStepError::Llm(LlmError::Fatal(error)))
            if matches!(request.envelope.class, CallClass::Durable { .. })
                && error != FatalLlmError::ResponseErased =>
        {
            let CallClass::Durable { fallback } = &request.envelope.class else {
                unreachable!()
            };
            match fallbacks.run(fallback, &request, &error) {
                Ok(mut response) => {
                    if let Err(error) = super::schema::validate_fallback(&request, &response, check)
                    {
                        settle_failed_usage(guard, &admission.lease, &failed_usage);
                        ctx.vault.count_failed_step(ctx, step_hash, None);
                        return Err(error);
                    }
                    response.usage = failed_usage;
                    response
                }
                Err(error) => {
                    settle_failed_usage(guard, &admission.lease, &failed_usage);
                    ctx.vault.count_failed_step(ctx, step_hash, None);
                    return Err(error.into());
                }
            }
        }
        // A metered backend below the step (a host's run admission, rung by
        // rung) found the budget spent before any response was answered: the
        // same trap as this step's own admission, never a model failure. Once
        // a response was answered, a spent budget fails the step as a spent
        // correction admission does. A host check holding new host-paid work
        // parks the step the same way, and is no budget hit (FIX 9924).
        Err(DurableStepError::Llm(LlmError::BudgetDenied(
            denied @ (BudgetDenied::Exhausted | BudgetDenied::HostCheck),
        ))) if !answered => {
            settle_failed_usage(guard, &admission.lease, &failed_usage);
            return budget_trap(ctx, step_hash).inspect(|_| {
                if denied == BudgetDenied::Exhausted {
                    step_budget_hit(ctx, guard, &request);
                }
            });
        }
        Err(error) => {
            settle_failed_usage(guard, &admission.lease, &failed_usage);
            // FIX 2146: a fresh call that failed counts once.
            ctx.vault.count_failed_step(ctx, step_hash, Some(&error));
            // A provider limit's stated reset stays on the call's end row: the
            // Retry park the refusal makes comes due then (FIX 11226).
            if let DurableStepError::Llm(source) = &error
                && let Some(reset) = super::retry::stated_reset_at(source)
            {
                observed.refused_until(reset);
            }
            return Err(match error {
                DurableStepError::Llm(LlmError::Fatal(source))
                    if matches!(request.envelope.class, CallClass::BestEffort) =>
                {
                    DurableStepError::Llm(LlmError::Fatal(source))
                }
                // Nor does a failure policy route it to one.
                erased @ DurableStepError::Llm(LlmError::Fatal(FatalLlmError::ResponseErased)) => {
                    erased
                }
                DurableStepError::Llm(source) => classified_failure(ctx.vault, source)?,
                other => other,
            });
        }
    };

    // The provider answered, so the tokens were really spent: the reserved
    // lease MUST settle on EVERY exit from the post-response persistence block.
    // A `?` out of response serialization / `step_state_write` /
    // `log_terminal_step` returns BEFORE the explicit settle below, which would
    // leak the reserved units for the guard's lifetime and throttle later
    // admissions (#478-1). This RAII guard settles on drop; `settle_absolute`
    // is idempotent on an already-settled lease, so the happy-path settle stays
    // a no-op once the guard is disarmed.
    let lease_settle = LeaseSettleOnDrop::new(guard, &admission.lease, &response.usage);

    let payload = serde_json::to_vec(&response)?;
    // A late answer for an owner its erase took is never kept (FIX 6226):
    // the row keeps its erased skeleton, nothing is filed, and the spend
    // settles as `lease_settle` drops; the call closes after it.
    if step_state_write_owned(
        ctx.vault,
        ctx.attempt_id,
        &step_hash,
        StepProgression::ResponseReceived,
        StepStateOwners::of(ctx),
        Some(&payload),
        ctx.now_ms,
    )? == StepStateDisposition::Erased
    {
        return Err(erased_step());
    }

    // The response is recoverable before any policy read that can fail. An
    // error may refuse downstream use, but replay must not re-spend the call.
    let failure_policy = failure_policy(ctx.vault, &response)?;
    let Some(claim_id) = log_terminal_step(
        ctx,
        &step_hash,
        &request,
        &response,
        &payload,
        observed.terminal(),
    )?
    else {
        // The erase landed between the answer and its claim: the same
        // erased disposition, with the row kept erased, never deleted.
        return Err(erased_step());
    };
    observed.claimed();

    lease_settle.settle().map_err(LlmError::from)?;
    step_state_delete(ctx.vault, ctx.attempt_id, &step_hash)?;
    let witness = ExecutedModelWitness::completed(
        ctx,
        claim_id,
        step_hash,
        request.model.clone(),
        failure_policy.is_some(),
    );
    ctx.vault.capture_tier1_executed_step(&witness)?;

    Ok(StepOutcome::Finished {
        response,
        memoized: false,
        legibility: step_legibility(ctx, guard),
        failure_policy,
    })
}

/// Verify a persisted step and resolve resident eligibility in the SAME
/// snapshot as outbound Gate admission or Pending live-retry governance.
/// Terminal Done/Abandoned replay does not call this door.
pub(crate) fn verified_step_effector_eligible_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    binding: super::types::StepEffectBinding,
    effect_actor: crate::entity_id::EntityId,
) -> DurableStepResult<bool> {
    let (response, purpose) = verified_step_response_in_txn(vault, txn, binding, effect_actor)?;
    let Some(class) = super::super::fallback_failure_class(&response) else {
        return Ok(true);
    };
    let stage = crate::dreamer_consolidation::step_effector_eligible_in_txn(
        vault, txn, &purpose, &response,
    )?;
    Ok(policy
        .dreamer_failure_decision(class)
        .effector_with_stage(stage))
}

/// Recheck one persisted fallback in the governing PERSON or promotion write
/// transaction. A revoked manifest or stage rule cannot reuse the earlier
/// read-side step decision as permission to publish.
pub(crate) fn verified_step_consolidation_eligible_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    binding: super::types::StepEffectBinding,
    actor: crate::entity_id::EntityId,
    expected_response_hash: [u8; 32],
) -> DurableStepResult<bool> {
    let (response, purpose) = verified_step_response_in_txn(vault, txn, binding, actor)?;
    let payload = serde_json::to_vec(&response)?;
    if blake3::hash(&payload).as_bytes() != &expected_response_hash {
        return Err(Error::InvalidClaimBody("consolidation fallback response changed").into());
    }
    let class = super::super::fallback_failure_class(&response).ok_or(Error::InvalidClaimBody(
        "consolidation binding is not a fallback",
    ))?;
    let decision = policy.dreamer_failure_decision(class);
    let stage = crate::dreamer_consolidation::step_consolidation_eligible_in_txn(
        vault, txn, &purpose, &response,
    )?;
    Ok(decision.consolidation_with_stage(stage))
}

fn verified_step_response_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    binding: super::types::StepEffectBinding,
    effect_actor: crate::entity_id::EntityId,
) -> DurableStepResult<(LlmResponse, String)> {
    let claim_id = step_index_lookup_in_txn(vault, txn, binding.attempt_id, &binding.step_hash)?
        .ok_or(Error::InvalidClaimBody(
            "step-derived effect requires a completed step",
        ))?;
    let body = vault
        .get_claim_in_txn(txn, &claim_id)?
        .ok_or(Error::InvalidClaimBody("dreamer step index claim missing"))?;
    let decoded = decode_step_claim_value(&body.value)?;
    if body.predicate != super::types::DREAMER_STEP_PREDICATE
        || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        || body.stale
        || decoded.attempt_id != binding.attempt_id
        || decoded.step_hash != binding.step_hash
        || !super::step_claim::step_claim_binding_is_trusted(&decoded, &body)
    {
        return Err(Error::InvalidClaimBody("step-derived effect request mismatch").into());
    }
    let actor_matches = match body.evidence.as_ref() {
        Some(rmpv::Value::Map(entries)) => entries.iter().any(|(key, value)| {
            key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)
                && value.as_slice() == Some(effect_actor.as_bytes().as_slice())
        }),
        _ => false,
    };
    if !actor_matches {
        return Err(Error::InvalidClaimBody("step-derived effect actor mismatch").into());
    }
    let response = load_step_response_in_txn(vault, txn, &decoded)?;
    Ok((response, decoded.purpose))
}

/// A step whose response its owner's erase took (KS-2B1, FIX 6226): over,
/// never asked or paid for again, naming no byte of the response.
fn erased_step() -> DurableStepError {
    Error::Refused("this step's response was erased by its owner; it is not asked again".into())
        .into()
}

fn failure_policy(
    vault: &crate::Vault,
    response: &LlmResponse,
) -> DurableStepResult<Option<super::super::DreamerFailureDecision>> {
    let Some(class) = super::super::fallback_failure_class(response) else {
        return Ok(None);
    };
    #[cfg(test)]
    if vault
        .test_hooks()
        .take_fail_next_dreamer_failure_policy_read()
    {
        return Err(Error::InvariantViolation("injected dreamer failure policy read").into());
    }
    Ok(Some(resolve_failure_policy(vault, class)?))
}

/// A spent budget parks the step's attempt behind a budget trap. The trap
/// and its park land in one transaction: an open trap over an unparked
/// attempt reads as plain leased work, which boot recovery requeues and a
/// fresh budget runs without the signal.
fn budget_trap(
    ctx: &DurableStepContext<'_>,
    step_hash: [u8; 32],
) -> DurableStepResult<StepOutcome> {
    let failure_policy =
        resolve_failure_policy(ctx.vault, super::super::DreamerFailureClass::Budget)?;
    let store = crate::dreamer_runner::DreamerRunnerStore::new(ctx.vault);
    let trap = ctx.vault.with_write_txn_grouped(|wtxn| {
        let trap = open_trap_in_txn(
            ctx.vault,
            wtxn,
            ctx,
            DreamerTrapKind::Budget,
            step_hash,
            "durable step budget exhausted",
            TrapBindingScope::Attempt,
        )?;
        store.park_attempt_in_txn(
            wtxn,
            crate::dreamer_runner::ParkDreamerAttempt {
                attempt_id: ctx.attempt_id,
                reason: "durable step budget exhausted".to_owned(),
                cause: crate::dreamer_runner::DreamerParkCause::Signal,
                park_owner: trap_park_owner(&trap.trap_claim_id),
                now: ctx.now_s(),
            },
        )?;
        Ok(trap)
    })?;
    step_state_delete(ctx.vault, ctx.attempt_id, &step_hash)?;
    Ok(StepOutcome::Trapped {
        trap,
        failure_policy,
    })
}

/// `host.budget.hit` for a step whose budget is spent, once the host acted
/// on it: the request's model is the seat, the step's actor paid for it.
fn step_budget_hit(ctx: &DurableStepContext<'_>, guard: &BudgetGuard, request: &LlmRequest) {
    ctx.vault.budget_denied_hooks(
        &BudgetDenied::Exhausted,
        guard,
        request.model.as_str(),
        Some(ctx.envelope_actor.entity_ref()),
    );
}

fn classified_failure(
    vault: &crate::Vault,
    source: LlmError,
) -> DurableStepResult<DurableStepError> {
    let class = super::super::DreamerFailureClass::of(&source);
    let failure_policy = resolve_failure_policy(vault, class)?;
    Ok(DurableStepError::ClassifiedLlm {
        source,
        failure_policy,
    })
}

fn resolve_failure_policy(
    vault: &crate::Vault,
    class: super::super::DreamerFailureClass,
) -> DurableStepResult<super::super::DreamerFailureDecision> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    Ok(policy.dreamer_failure_decision(class))
}

fn settle_failed_usage(guard: &BudgetGuard, lease: &super::BudgetLease, usage: &super::LlmUsage) {
    // A checked or schema step that refused an answered reply settled its
    // lease before it failed (FIX 7218); settling again is a no-op, where an
    // abort would be refused as an invalid lease.
    let settled_already = matches!(
        guard.lease_observation(lease.id()),
        Some(super::super::BudgetLeaseState::Settled { .. })
    );
    let settled = if settled_already || usage.input.total > 0 || usage.output.total > 0 {
        guard.settle_per_call(lease, usage)
    } else {
        guard.abort(lease)
    };
    if let Err(denied) = settled {
        report_unsettled(lease, denied);
    }
}

/// A settlement the meter refused once the provider was called. The step's
/// own outcome still returns; the refusal is reported, never dropped.
fn report_unsettled(lease: &super::BudgetLease, denied: BudgetDenied) {
    tracing::error!(lease = lease.id(), %denied, "durable step settlement refused");
}

/// The wake-pass legibility envelope for this step's outcome: Some inside
/// wake passes (deadline present), None outside.
fn step_legibility(
    ctx: &DurableStepContext<'_>,
    guard: &BudgetGuard,
) -> Option<BudgetLegibilityEnvelope> {
    ctx.deadline
        .map(|deadline| current_legibility(&guard.read(), deadline))
}

/// RAII settlement for a durable step's reserved lease once the provider has
/// answered. The spend is real from that point, so the lease must settle on
/// every exit from the post-response persistence block — otherwise a
/// persistence error leaks the reservation for the guard's lifetime (#478-1).
/// The happy path calls [`LeaseSettleOnDrop::settle`], which disarms the guard
/// and surfaces the settlement result; any early return drops the guard, which
/// settles best-effort. `used_units` mirrors `settle_terminal` (absolute
/// input+output totals), so both paths count the SAME spend — no undercount.
struct LeaseSettleOnDrop<'a> {
    guard: &'a BudgetGuard,
    lease: &'a super::BudgetLease,
    used_units: u64,
    armed: bool,
}

impl<'a> LeaseSettleOnDrop<'a> {
    fn new(guard: &'a BudgetGuard, lease: &'a super::BudgetLease, usage: &super::LlmUsage) -> Self {
        Self {
            guard,
            lease,
            used_units: usage.input.total.saturating_add(usage.output.total),
            armed: true,
        }
    }

    fn settle(mut self) -> std::result::Result<super::BudgetSettlement, BudgetDenied> {
        self.armed = false;
        self.guard.settle_usage(self.lease, self.used_units)
    }
}

impl Drop for LeaseSettleOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Err(denied) = self.guard.settle_usage(self.lease, self.used_units)
        {
            report_unsettled(self.lease, denied);
        }
    }
}
