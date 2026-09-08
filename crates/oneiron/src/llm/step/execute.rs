//! Durable step execution: memo/admission/deadline orchestration plus deadline-race, retry, and lease-settle helpers.

use super::super::{
    BudgetDenied, BudgetGuard, CallClass, LlmBackend, LlmError, LlmRequest, LlmResponse, LlmResult,
};
use super::step_claim::{
    decode_step_claim_value, load_step_response, log_terminal_step, step_claim_matches_request,
    step_index_lookup,
};
use super::step_state::{step_state_delete, step_state_read, step_state_write};
use super::trap::{open_trap, trap_park_owner};
use super::types::{
    DREAMER_STEP_RETRY_BACKOFF_MS, DreamerTrapKind, DurableStepContext, DurableStepError,
    DurableStepResult, StepOutcome, StepProgression,
};
use crate::dreamer_wake::{
    BudgetLegibilityEnvelope, DREAMER_HARD_CUT_PARK_OWNER, DREAMER_HARD_CUT_PARK_REASON,
    WakePassDeadline, current_legibility,
};
use crate::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

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
    // Purity gate (ONE-1344): the FIRST executable branch, so a refused
    // request never hashes, never reads the memo index, never writes private
    // step state, never reserves budget, and never reaches the backend.
    if let Some(pinned) = ctx.pinned_config {
        pinned.admit(&request)?;
    }

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
            return Ok(StepOutcome::Finished {
                response,
                memoized: true,
                legibility: step_legibility(ctx, guard),
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
        log_terminal_step(ctx, &step_hash, &request, &response, payload)?;
        step_state_delete(ctx.vault, ctx.attempt_id, &step_hash)?;
        return Ok(StepOutcome::Finished {
            response,
            memoized: true,
            legibility: step_legibility(ctx, guard),
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
            return Ok(StepOutcome::Trapped(trap));
        }
        Err(denied) => return Err(LlmError::from(denied).into()),
    };

    // Mid-step preemption (ONE-1305, G1): inside a wake pass the in-flight
    // generate future races the deadline; on loss the lease aborts (actual
    // spend settled) and the attempt parks at the hard cut.
    let generated = match ctx.deadline {
        Some(deadline) => {
            match race_deadline(
                generate_with_retry(backend, &request, &admission.lease),
                deadline,
            )
            .await
            {
                DeadlineRace::Completed(result) => result,
                DeadlineRace::DeadlineExpired => {
                    let _ = guard.abort(&admission.lease);
                    let store = crate::dreamer_runner::DreamerRunnerStore::new(ctx.vault);
                    store.park_attempt(crate::dreamer_runner::ParkDreamerAttempt {
                        attempt_id: ctx.attempt_id,
                        reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                        park_owner: DREAMER_HARD_CUT_PARK_OWNER.to_owned(),
                        now: ctx.now_s(),
                    })?;
                    step_state_delete(ctx.vault, ctx.attempt_id, &step_hash)?;
                    return Err(DurableStepError::DeadlineHardCut);
                }
            }
        }
        None => generate_with_retry(backend, &request, &admission.lease).await,
    };
    let response = match generated {
        Ok(response) => response,
        Err(error) => {
            let _ = guard.abort(&admission.lease);
            return Err(step_call_failure(&request, error));
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
    step_state_write(
        ctx.vault,
        ctx.attempt_id,
        &step_hash,
        StepProgression::ResponseReceived,
        Some(&payload),
        ctx.now_ms,
    )?;

    log_terminal_step(ctx, &step_hash, &request, &response, &payload)?;

    lease_settle.settle().map_err(LlmError::from)?;
    step_state_delete(ctx.vault, ctx.attempt_id, &step_hash)?;

    Ok(StepOutcome::Finished {
        response,
        memoized: false,
        legibility: step_legibility(ctx, guard),
    })
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

enum DeadlineRace<T> {
    Completed(T),
    DeadlineExpired,
}

/// Upper bound between deadline re-checks while racing an in-flight call:
/// bounds how far past the ceiling a hung provider can run, and lets
/// injected test clocks advance while the timer sleeps real time.
const DEADLINE_RACE_RECHECK_MS: u64 = 50;

/// Races a future against the wake-pass deadline: checks expiry FIRST, then
/// polls the future, re-arming a bounded timer until one side wins.
///
/// The expiry-before-poll order is load-bearing: a call whose deadline
/// passed while the racer slept loses even if its response arrived in the
/// meantime — a hard-cut pass must never record a new `Finished` step.
async fn race_deadline<F: Future>(
    future: F,
    deadline: &WakePassDeadline,
) -> DeadlineRace<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut timer: Option<Pin<Box<SleepFuture>>> = None;
    std::future::poll_fn(move |cx| {
        if deadline.expired() {
            return Poll::Ready(DeadlineRace::DeadlineExpired);
        }
        if let Poll::Ready(output) = future.as_mut().poll(cx) {
            return Poll::Ready(DeadlineRace::Completed(output));
        }
        loop {
            let armed = timer.get_or_insert_with(|| {
                Box::pin(sleep_ms(
                    deadline.remaining_ms().clamp(1, DEADLINE_RACE_RECHECK_MS),
                ))
            });
            match armed.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    if deadline.expired() {
                        return Poll::Ready(DeadlineRace::DeadlineExpired);
                    }
                    timer = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await
}

fn step_call_failure(request: &LlmRequest, error: LlmError) -> DurableStepError {
    if matches!(error, LlmError::Fatal(_))
        && let CallClass::Durable { fallback } = &request.envelope.class
    {
        return DurableStepError::FallbackDemanded {
            fallback: fallback.name.clone(),
            source: error,
        };
    }
    DurableStepError::Llm(error)
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
        self.guard.settle_absolute(self.lease, self.used_units)
    }
}

impl Drop for LeaseSettleOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.guard.settle_absolute(self.lease, self.used_units);
        }
    }
}

async fn generate_with_retry(
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
