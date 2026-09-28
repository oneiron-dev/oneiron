//! Durable step execution: memo/admission/deadline orchestration with retry and lease settlement.

use super::super::{
    BudgetDenied, BudgetGuard, CallClass, LlmBackend, LlmError, LlmRequest, LlmResponse, LlmResult,
};
use super::step_claim::{
    decode_step_claim_value, load_step_response, load_step_response_in_txn, log_terminal_step,
    step_claim_matches_request, step_index_lookup, step_index_lookup_in_txn,
};
use super::step_state::{step_state_delete, step_state_read, step_state_write};
use super::trap::{open_trap, trap_park_owner};
use super::types::{
    DREAMER_STEP_RETRY_BACKOFF_MS, DreamerTrapKind, DurableStepContext, DurableStepError,
    DurableStepResult, StepOutcome, StepProgression,
};
use crate::dreamer_wake::{BudgetLegibilityEnvelope, current_legibility};
use crate::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

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
}

impl<'vault> ExecutedModelWitness<'vault> {
    fn completed(
        ctx: &DurableStepContext<'vault>,
        claim_id: crate::EntityId,
        request_hash: [u8; 32],
        model: super::super::ModelId,
    ) -> Self {
        Self {
            vault: ctx.vault,
            claim_id,
            attempt_id: ctx.attempt_id,
            run_ref: ctx.run_id.clone(),
            request_hash,
            model,
            at_ms: ctx.now_ms,
        }
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

/// Durable step with an explicitly owned deterministic runner registry.
pub async fn call_as_step_with_fallbacks(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
    fallbacks: &super::super::FallbackRegistry,
) -> DurableStepResult<StepOutcome> {
    let step_hash = request.canonical_hash()?;

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
        log_terminal_step(ctx, &step_hash, &request, &response, payload)?;
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

    step_state_write(
        ctx.vault,
        ctx.attempt_id,
        &step_hash,
        StepProgression::Started,
        None,
        ctx.now_ms,
    )?;

    let admission = match guard.admit_for_request(&request) {
        Ok(admission) => admission,
        Err(BudgetDenied::Exhausted) => {
            let failure_policy =
                resolve_failure_policy(ctx.vault, super::super::DreamerFailureClass::Budget)?;
            let trap = open_trap(
                ctx.vault,
                ctx,
                DreamerTrapKind::Budget,
                step_hash,
                "durable step budget exhausted",
            )?;
            let store = crate::dreamer_runner::DreamerRunnerStore::new(ctx.vault);
            store.park_attempt(crate::dreamer_runner::ParkDreamerAttempt {
                attempt_id: ctx.attempt_id,
                reason: "durable step budget exhausted".to_owned(),
                park_owner: trap_park_owner(&trap.trap_claim_id),
                now: ctx.now_s(),
            })?;
            step_state_delete(ctx.vault, ctx.attempt_id, &step_hash)?;
            return Ok(StepOutcome::Trapped {
                trap,
                failure_policy,
            });
        }
        Err(denied) => {
            let source = LlmError::from(denied);
            return Err(classified_failure(ctx.vault, source)?);
        }
    };

    // The deadline only gates admission. Once admitted, the provider (and any
    // retries) runs to a terminal response so its lease can settle real usage.
    let generated =
        super::schema::generate(backend, &request, &admission.lease, guard, ctx.deadline).await;
    let (generated, failed_usage) = match generated {
        Err(DurableStepError::SpentLlm { source, usage }) => {
            (Err(DurableStepError::Llm(source)), *usage)
        }
        result => (result, super::LlmUsage::zero()),
    };
    let response = match generated {
        Ok(response) => response,
        Err(DurableStepError::Llm(LlmError::Fatal(error)))
            if matches!(request.envelope.class, CallClass::Durable { .. }) =>
        {
            let CallClass::Durable { fallback } = &request.envelope.class else {
                unreachable!()
            };
            match fallbacks.run(fallback, &request, &error) {
                Ok(mut response) => {
                    if let Err(error) = super::schema::validate_fallback(&request, &response) {
                        settle_failed_usage(guard, &admission.lease, &failed_usage);
                        return Err(error);
                    }
                    response.usage = failed_usage;
                    response
                }
                Err(error) => {
                    settle_failed_usage(guard, &admission.lease, &failed_usage);
                    return Err(error.into());
                }
            }
        }
        Err(error) => {
            settle_failed_usage(guard, &admission.lease, &failed_usage);
            return Err(match error {
                DurableStepError::Llm(LlmError::Fatal(source))
                    if matches!(request.envelope.class, CallClass::BestEffort) =>
                {
                    DurableStepError::Llm(LlmError::Fatal(source))
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
    ctx.vault.resume_from_slim_on_inbound()?;

    let payload = serde_json::to_vec(&response)?;
    step_state_write(
        ctx.vault,
        ctx.attempt_id,
        &step_hash,
        StepProgression::ResponseReceived,
        Some(&payload),
        ctx.now_ms,
    )?;

    // The response is recoverable before any policy read that can fail. An
    // error may refuse downstream use, but replay must not re-spend the call.
    let failure_policy = failure_policy(ctx.vault, &response)?;
    let claim_id = log_terminal_step(ctx, &step_hash, &request, &response, &payload)?;

    lease_settle.settle().map_err(LlmError::from)?;
    step_state_delete(ctx.vault, ctx.attempt_id, &step_hash)?;
    let witness = ExecutedModelWitness::completed(ctx, claim_id, step_hash, request.model.clone());
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
    if usage.input.total > 0 || usage.output.total > 0 {
        let _ = guard.settle_per_call(lease, usage);
    } else {
        let _ = guard.abort(lease);
    }
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
        if self.armed {
            let _ = self.guard.settle_usage(self.lease, self.used_units);
        }
    }
}

pub(super) async fn generate_with_retry(
    backend: &dyn LlmBackend,
    request: &LlmRequest,
    lease: &super::BudgetLease,
) -> LlmResult<LlmResponse> {
    let mut retries = 0_usize;
    loop {
        match backend.generate(request.clone(), lease).await {
            Ok(response) => return Ok(response),
            Err(LlmError::Retryable(error)) => {
                if retries >= DREAMER_STEP_RETRY_BACKOFF_MS.len() {
                    return Err(LlmError::Retryable(error));
                }
                sleep_ms(DREAMER_STEP_RETRY_BACKOFF_MS[retries]).await;
                retries += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// std-only timer future (zero-new-deps pin, design D1): a helper thread
/// wakes the most recent waker once the deadline passes.
fn sleep_ms(ms: u64) -> SleepFuture {
    SleepFuture {
        deadline: Instant::now() + Duration::from_millis(ms),
        shared_waker: None,
    }
}

struct SleepFuture {
    deadline: Instant,
    shared_waker: Option<Arc<Mutex<Waker>>>,
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(());
        }
        if let Some(shared) = &self.shared_waker {
            *shared.lock().expect("sleep waker mutex poisoned") = cx.waker().clone();
            return Poll::Pending;
        }
        let shared = Arc::new(Mutex::new(cx.waker().clone()));
        self.shared_waker = Some(Arc::clone(&shared));
        let deadline = self.deadline;
        std::thread::spawn(move || {
            let now = Instant::now();
            if deadline > now {
                std::thread::sleep(deadline - now);
            }
            shared
                .lock()
                .expect("sleep waker mutex poisoned")
                .wake_by_ref();
        });
        Poll::Pending
    }
}
