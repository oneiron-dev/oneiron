use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use serde_json::json;

use crate::config::VaultConfig;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{
    CallEnvelope, ContentPart, DeterministicFallback, FatalLlmError, FinishReason, LlmCapability,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmResult,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    RetryableLlmError, TierPrecedence, UnsupportedCapability,
};

use super::super::{BudgetExhaustionPolicy, BudgetLease};
use super::*;

fn block_on<F: Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl std::task::Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

struct StepFixture {
    attempt_id: AttemptId,
    actor: WriteActor,
    subject: EntityId,
}

fn step_fixture(vault: &Vault, now: u64) -> Result<StepFixture> {
    let actor_entity = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(
        &actor_entity,
        ENTITY_TYPE_PERSON,
        occurred(now),
        now,
        b"actor",
    )?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(now), now, b"subject")?;

    let runner = DreamerRunnerStore::new(vault);
    let status = match runner.enqueue(EnqueueDreamerAttempt {
        attempt_type: "consolidation-step-test".to_owned(),
        input: rmpv::Value::from("input"),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-test".to_owned()),
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };

    Ok(StepFixture {
        attempt_id: status.attempt.id,
        actor: WriteActor::new(actor_entity, EdgeActorClass::Agent),
        subject,
    })
}

fn ctx<'a>(vault: &'a Vault, fixture: &StepFixture, now_ms: u64) -> DurableStepContext<'a> {
    DurableStepContext {
        vault,
        attempt_id: fixture.attempt_id,
        run_id: Some("run-test".to_owned()),
        envelope_actor: fixture.actor,
        subject: fixture.subject,
        deadline: None,
        now_ms,
    }
}

fn request_fixture() -> LlmRequest {
    let mut params = std::collections::BTreeMap::new();
    params.insert("temperature".to_owned(), json!(0.2));
    params.insert("max_tokens".to_owned(), json!(256));
    LlmRequest {
        model: ModelId::new("test/model@r1").expect("model id"),
        envelope: CallEnvelope {
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence {
                per_call: None,
                vault_policy: None,
                purpose_default: None,
                global_default: ModelTierRef("default".to_owned()),
            },
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "consolidate this".to_owned(),
            }],
        }],
        tools: Vec::new(),
        params,
        provider_options: std::collections::BTreeMap::new(),
    }
}

fn response_fixture(text: &str) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: text.to_owned(),
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 100,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 50,
                text: 50,
                reasoning: 0,
            },
            raw_provider: serde_json::Value::Null,
        },
        finish_reason: FinishReason::Stop,
    }
}

struct ScriptedBackend {
    calls: AtomicUsize,
    script: Mutex<VecDeque<LlmResult<LlmResponse>>>,
}

impl ScriptedBackend {
    fn new(script: Vec<LlmResult<LlmResponse>>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            script: Mutex::new(script.into_iter().collect()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for ScriptedBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let next = self
            .script
            .lock()
            .expect("script mutex")
            .pop_front()
            .expect("scripted backend exhausted");
        Box::pin(async move { next })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

fn guard_with_limit(limit: u64) -> BudgetGuard {
    BudgetGuard::with_reserve_units("step-test", limit, 500, BudgetExhaustionPolicy::Suspend)
}

#[test]
fn kill_and_resume_no_respend() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let backend = ScriptedBackend::new(vec![Ok(response_fixture("terminal answer"))]);
    let guard = guard_with_limit(10_000);

    let outcome =
        block_on(call_as_step(&ctx, &backend, &guard, request_fixture())).expect("first execution");
    let StepOutcome::Finished {
        response, memoized, ..
    } = outcome
    else {
        panic!("expected finished step");
    };
    assert!(!memoized);
    assert_eq!(backend.calls(), 1);
    let used_after_first = guard.read().used_units;
    assert_eq!(used_after_first, 150);

    // Simulated process death: a NEW call with the identical request must
    // memo-hit — no backend call, no admission, zero spend.
    let outcome = block_on(call_as_step(&ctx, &backend, &guard, request_fixture()))
        .expect("memoized re-execution");
    let StepOutcome::Finished {
        response: replayed,
        memoized,
        ..
    } = outcome
    else {
        panic!("expected finished step");
    };
    assert!(memoized);
    assert_eq!(replayed, response);
    assert_eq!(backend.calls(), 1, "backend must not be re-invoked");
    assert_eq!(guard.read().used_units, used_after_first, "zero re-spend");
    assert_eq!(guard.read().reserved_units, 0, "no lease admitted");
    Ok(())
}

#[test]
fn death_after_response_before_log_recovers_without_respend() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let request = request_fixture();
    let step_hash = request.canonical_hash().expect("hash");
    let response = response_fixture("answered before death");
    let payload = serde_json::to_vec(&response).expect("payload");

    // Seed the private row exactly as a death after the provider answered
    // but before logging leaves it.
    step_state_write(
        &vault,
        fixture.attempt_id,
        &step_hash,
        StepProgression::ResponseReceived,
        Some(&payload),
        9_000,
    )?;

    let backend = ScriptedBackend::new(Vec::new()); // any call would panic
    let guard = guard_with_limit(10_000);
    let outcome =
        block_on(call_as_step(&ctx, &backend, &guard, request)).expect("recovery execution");
    let StepOutcome::Finished {
        response: recovered,
        memoized,
        ..
    } = outcome
    else {
        panic!("expected finished step");
    };
    assert!(memoized);
    assert_eq!(recovered, response);
    assert_eq!(backend.calls(), 0, "no backend call during recovery");
    assert_eq!(guard.read().used_units, 0, "zero new spend");
    assert_eq!(guard.read().reserved_units, 0, "zero new leases");

    // The terminal claim + memo index landed; the private row is gone.
    assert!(step_index_lookup(&vault, fixture.attempt_id, &step_hash)?.is_some());
    assert!(step_state_read(&vault, fixture.attempt_id, &step_hash)?.is_none());
    Ok(())
}

#[test]
fn persistence_error_after_response_releases_lease() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    // Same attempt/subject, but override the envelope actor with a deliberately
    // absent entity so the terminal claim write inside `log_terminal_step`
    // fails AFTER the provider answered and the lease was reserved. Cloning the
    // helper ctx (rather than an inline literal) keeps this test compiling as
    // later stack commits add fields to DurableStepContext.
    let mut ctx = ctx(&vault, &fixture, 10_000);
    ctx.envelope_actor = WriteActor::new(EntityId::now(), EdgeActorClass::Agent);
    let backend = ScriptedBackend::new(vec![Ok(response_fixture("answered then failed"))]);
    let guard = guard_with_limit(10_000);

    let error = block_on(call_as_step(&ctx, &backend, &guard, request_fixture()))
        .expect_err("terminal claim write must fail on the missing actor");
    assert!(matches!(
        error,
        DurableStepError::Engine(Error::EntityNotFound)
    ));
    // The provider was actually called: the tokens were spent.
    assert_eq!(backend.calls(), 1);

    // The reservation MUST be released despite the persistence error (#478-1);
    // otherwise the leaked units throttle every later admit_for_request.
    let read = guard.read();
    assert_eq!(
        read.reserved_units, 0,
        "reserved lease must not leak on a post-response persistence error"
    );
    assert_eq!(
        read.used_units, 150,
        "the real spend is settled (not aborted) so it is not undercounted"
    );
    Ok(())
}

#[test]
fn retry_does_not_double_count() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let backend = ScriptedBackend::new(vec![
        Err(LlmError::Retryable(RetryableLlmError::ServerError)),
        Err(LlmError::Retryable(RetryableLlmError::Timeout)),
        Ok(response_fixture("third time lucky")),
    ]);
    let guard = guard_with_limit(10_000);

    let outcome = block_on(call_as_step(&ctx, &backend, &guard, request_fixture()))
        .expect("retried execution");
    assert!(matches!(
        outcome,
        StepOutcome::Finished {
            memoized: false,
            ..
        }
    ));
    assert_eq!(backend.calls(), 3, "two retries then success");
    let read = guard.read();
    assert_eq!(
        read.used_units, 150,
        "absolute settle equals the final usage only — retries are free"
    );
    assert_eq!(read.reserved_units, 0, "the ONE lease settled");
    Ok(())
}

#[test]
fn fatal_besteffort_fails_fast_typed() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let backend = ScriptedBackend::new(vec![Err(LlmError::Fatal(FatalLlmError::InvalidRequest))]);
    let guard = guard_with_limit(10_000);

    let error = block_on(call_as_step(&ctx, &backend, &guard, request_fixture()))
        .expect_err("fatal must fail");
    assert!(matches!(
        error,
        DurableStepError::Llm(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
    assert_eq!(backend.calls(), 1, "fatal is never retried");
    let read = guard.read();
    assert_eq!(read.reserved_units, 0, "lease aborted");
    assert_eq!(read.used_units, 0, "aborted lease settles zero spend");
    Ok(())
}

#[test]
fn durable_fatal_demands_deterministic_fallback() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let backend = ScriptedBackend::new(vec![Err(LlmError::Fatal(FatalLlmError::EmptyResponse))]);
    let guard = guard_with_limit(10_000);
    let mut request = request_fixture();
    request.envelope.class = CallClass::Durable {
        fallback: DeterministicFallback {
            name: "template_summary_v1".to_owned(),
            config: None,
        },
    };

    let error =
        block_on(call_as_step(&ctx, &backend, &guard, request)).expect_err("fatal must fail");
    let DurableStepError::FallbackDemanded { fallback, .. } = error else {
        panic!("expected FallbackDemanded, got {error:?}");
    };
    assert_eq!(fallback, "template_summary_v1");
    Ok(())
}

#[test]
fn budget_denied_opens_budget_trap_and_parks() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let backend = ScriptedBackend::new(Vec::new()); // must never be called
    let guard = guard_with_limit(100); // reserve 500 > limit 100 → Exhausted

    let outcome = block_on(call_as_step(&ctx, &backend, &guard, request_fixture()))
        .expect("trap outcome is Ok");
    let StepOutcome::Trapped(trap) = outcome else {
        panic!("expected trapped step");
    };
    assert_eq!(trap.kind, DreamerTrapKind::Budget);
    assert_eq!(backend.calls(), 0);

    // The created trap claim exists and decodes.
    let body = vault
        .get_claim(&trap.trap_claim_id)?
        .expect("trap claim exists");
    assert_eq!(body.predicate, DREAMER_TRAP_PREDICATE);
    let decoded = decode_trap_claim_value(&body.value)?;
    assert_eq!(decoded.state, DreamerTrapState::Created);
    assert_eq!(decoded.kind, DreamerTrapKind::Budget);
    assert_eq!(decoded.attempt_id, fixture.attempt_id);
    assert_eq!(decoded.step_hash, trap.step_hash);

    // The attempt is parked UNDER THE TRAP'S OWNER TOKEN and the transition row
    // is deleted.
    let runner = DreamerRunnerStore::new(&vault);
    let parked = runner
        .parked_attempt(fixture.attempt_id)?
        .expect("attempt parked");
    assert_eq!(parked.park_owner, trap_park_owner(&trap.trap_claim_id));
    // parked_at is stored in Unix SECONDS (park_attempt_with_progress rescales it
    // *1_000 for updated_at_ms); the millisecond now_ms=10_000 must land as 10,
    // not 10_000 (#480-1).
    assert_eq!(
        parked.parked_at, 10,
        "budget-exhaustion park must store parked_at in seconds, not milliseconds"
    );
    assert!(step_state_read(&vault, fixture.attempt_id, &trap.step_hash)?.is_none());
    Ok(())
}

#[test]
fn signal_before_wait_ordering() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let step_hash = request_fixture().canonical_hash().expect("hash");
    let trap = open_trap(&vault, &ctx, DreamerTrapKind::Consent, step_hash, "consent")?;
    let runner = DreamerRunnerStore::new(&vault);
    runner.park_attempt(crate::dreamer_runner::ParkDreamerAttempt {
        attempt_id: fixture.attempt_id,
        reason: "consent".to_owned(),
        park_owner: trap_park_owner(&trap.trap_claim_id),
        now: 10_001,
    })?;

    // Signal lands BEFORE the runner registers its wait (created→sent).
    let sent_id = send_trap_signal(&vault, &trap.trap_claim_id, step_hash, 10_002)?;
    assert_ne!(sent_id, trap.trap_claim_id);

    // The wait registration observes Sent instead of writing waiting.
    assert_eq!(
        register_wait(&vault, &trap, 10_003)?,
        DreamerTrapState::Sent
    );

    // Consume validates, then commits the consumed transition AND the
    // un-park in one wtxn.
    let attempt_id = consume_trap_signal(&vault, &runner, &trap, 10_004)?;
    assert_eq!(attempt_id, fixture.attempt_id);
    let (_, head) = trap_head(&vault, &trap.trap_claim_id)?;
    assert_eq!(head.state, DreamerTrapState::Consumed);
    assert!(
        runner.parked_attempt(fixture.attempt_id)?.is_none(),
        "consume+resume must clear the parked row atomically"
    );
    Ok(())
}

#[test]
fn wait_before_signal_ordering() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let step_hash = request_fixture().canonical_hash().expect("hash");
    let trap = open_trap(&vault, &ctx, DreamerTrapKind::Consent, step_hash, "consent")?;
    let runner = DreamerRunnerStore::new(&vault);

    assert_eq!(
        register_wait(&vault, &trap, 10_001)?,
        DreamerTrapState::Waiting
    );
    send_trap_signal(&vault, &trap.trap_claim_id, step_hash, 10_002)?;
    let attempt_id = consume_trap_signal(&vault, &runner, &trap, 10_003)?;
    assert_eq!(attempt_id, fixture.attempt_id);
    let (_, head) = trap_head(&vault, &trap.trap_claim_id)?;
    assert_eq!(head.state, DreamerTrapState::Consumed);
    Ok(())
}

#[test]
fn forged_resume_signal_rejected() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let step_hash = request_fixture().canonical_hash().expect("hash");
    let trap = open_trap(&vault, &ctx, DreamerTrapKind::Budget, step_hash, "budget")?;
    let runner = DreamerRunnerStore::new(&vault);
    runner.park_attempt(crate::dreamer_runner::ParkDreamerAttempt {
        attempt_id: fixture.attempt_id,
        reason: "budget".to_owned(),
        park_owner: trap_park_owner(&trap.trap_claim_id),
        now: 10_001,
    })?;
    register_wait(&vault, &trap, 10_002)?;

    // A forged signal carrying a DIFFERENT step hash is rejected at the door…
    let forged_hash = [0xAB_u8; 32];
    assert!(send_trap_signal(&vault, &trap.trap_claim_id, forged_hash, 10_003).is_err());

    // …and a forged sent RECORD crafted outside the API is rejected at
    // consume (the security boundary): supersede the waiting head with a
    // sent-state claim carrying the wrong hash.
    let (head_id, head) = trap_head(&vault, &trap.trap_claim_id)?;
    assert_eq!(head.state, DreamerTrapState::Waiting);
    let head_body = vault.get_claim(&head_id)?.expect("head body");
    let forged_id = EntityId::now();
    let forged_value = encode_trap_claim_value(&EncodedTrapClaim {
        kind: DreamerTrapKind::Budget,
        attempt_id: fixture.attempt_id,
        step_hash: forged_hash,
        state: DreamerTrapState::Sent,
        at: 10_004,
        note: "forged".to_owned(),
    });
    let forged_candidate = ClaimCandidate::new(
        DREAMER_TRAP_PREDICATE,
        ClaimSubject::Entity(fixture.subject),
        forged_value,
        1.0,
    );
    let envelope = envelope_from_claim_body(&head_body)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(
                &forged_id,
                forged_candidate,
                &envelope,
                occurred(10_004),
                10_004,
            )
            .apply(wtxn)?;
        vault.supersede_claim_in_txn(wtxn, &forged_id, &head_id, 10_004)
    })?;

    let error = consume_trap_signal(&vault, &runner, &trap, 10_005).expect_err("forged rejected");
    assert!(matches!(error, Error::InvalidClaimBody(_)));
    // The trap is NOT consumed and the attempt stays parked.
    let (_, head) = trap_head(&vault, &trap.trap_claim_id)?;
    assert_ne!(head.state, DreamerTrapState::Consumed);
    assert!(
        runner.parked_attempt(fixture.attempt_id)?.is_some(),
        "attempt stays parked"
    );
    Ok(())
}

#[test]
fn stale_resume_signal_rejected() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let runner = DreamerRunnerStore::new(&vault);

    // Trap A completes a full legal cycle.
    let hash_a = request_fixture().canonical_hash().expect("hash");
    let trap_a = open_trap(&vault, &ctx, DreamerTrapKind::Consent, hash_a, "cycle one")?;
    register_wait(&vault, &trap_a, 10_001)?;
    send_trap_signal(&vault, &trap_a.trap_claim_id, hash_a, 10_002)?;
    consume_trap_signal(&vault, &runner, &trap_a, 10_003)?;

    // A replayed/stale consume against the already-consumed chain rejects.
    let error = consume_trap_signal(&vault, &runner, &trap_a, 10_004).expect_err("stale rejected");
    assert!(matches!(error, Error::InvalidClaimBody(_)));

    // A sent record living in ANOTHER trap's chain never validates against
    // this trap: hash from A, chain from B.
    let hash_b = [0x77_u8; 32];
    let trap_b = open_trap(&vault, &ctx, DreamerTrapKind::Consent, hash_b, "cycle two")?;
    send_trap_signal(&vault, &trap_b.trap_claim_id, hash_b, 10_005)?;
    let cross = TrapRef {
        trap_claim_id: trap_b.trap_claim_id,
        kind: trap_b.kind,
        step_hash: hash_a,
    };
    let error = consume_trap_signal(&vault, &runner, &cross, 10_006)
        .expect_err("cross-chain signal rejected");
    assert!(matches!(error, Error::InvalidClaimBody(_)));
    Ok(())
}

#[test]
fn own_anchor_sent_record_refused() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let step_hash = request_fixture().canonical_hash().expect("hash");
    let runner = DreamerRunnerStore::new(&vault);

    // The attempt is genuinely parked by its real trap, so a successful forgery
    // WOULD resume it.
    let real = open_trap(&vault, &ctx, DreamerTrapKind::Budget, step_hash, "budget")?;
    runner.park_attempt(crate::dreamer_runner::ParkDreamerAttempt {
        attempt_id: fixture.attempt_id,
        reason: "budget".to_owned(),
        park_owner: trap_park_owner(&real.trap_claim_id),
        now: 10_001,
    })?;

    // Forge ONE claim already in state Sent and present it as its own
    // anchor: head == anchor, so the lineage walk is trivially satisfied and
    // only the anchor-state check stands in the way.
    let forged_id = EntityId::now();
    let forged_value = encode_trap_claim_value(&EncodedTrapClaim {
        kind: DreamerTrapKind::Budget,
        attempt_id: fixture.attempt_id,
        step_hash,
        state: DreamerTrapState::Sent,
        at: 10_002,
        note: "forged self-anchor".to_owned(),
    });
    let candidate = ClaimCandidate::new(
        DREAMER_TRAP_PREDICATE,
        ClaimSubject::Entity(fixture.subject),
        forged_value,
        1.0,
    );
    let envelope = dreamer_runtime_envelope(&ctx)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(&forged_id, candidate, &envelope, occurred(10_002), 10_002)
            .apply(wtxn)
    })?;

    let forged = TrapRef {
        trap_claim_id: forged_id,
        kind: DreamerTrapKind::Budget,
        step_hash,
    };
    let error = consume_trap_signal(&vault, &runner, &forged, 10_003)
        .expect_err("self-anchored sent record refused");
    assert!(matches!(
        error,
        Error::InvalidClaimBody("dreamer trap anchor must be a created record")
    ));
    assert!(
        runner.parked_attempt(fixture.attempt_id)?.is_some(),
        "attempt stays parked"
    );
    Ok(())
}

#[test]
fn signal_naming_other_owners_job_refused() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);

    // Attempt J is parked under ITS OWN trap's park-owner token.
    let fixture_j = step_fixture(&vault, 10)?;
    let ctx_j = ctx(&vault, &fixture_j, 10_000);
    let hash_j = request_fixture().canonical_hash().expect("hash");
    let trap_j = open_trap(&vault, &ctx_j, DreamerTrapKind::Budget, hash_j, "budget j")?;
    runner.park_attempt(crate::dreamer_runner::ParkDreamerAttempt {
        attempt_id: fixture_j.attempt_id,
        reason: "budget j".to_owned(),
        park_owner: trap_park_owner(&trap_j.trap_claim_id),
        now: 10_001,
    })?;

    // Trap K suspends a DIFFERENT attempt.
    let fixture_k = step_fixture(&vault, 11)?;
    let ctx_k = ctx(&vault, &fixture_k, 10_010);
    let hash_k = [0x66_u8; 32];
    let trap_k = open_trap(
        &vault,
        &ctx_k,
        DreamerTrapKind::Consent,
        hash_k,
        "consent k",
    )?;
    register_wait(&vault, &trap_k, 10_011)?;

    // Forge a sent record on K's chain that names ATTEMPT J — another owner's
    // parked attempt. The private binding says trap K belongs to attempt K, so the
    // consume must refuse instead of unparking J.
    let (head_id, _) = trap_head(&vault, &trap_k.trap_claim_id)?;
    let head_body = vault.get_claim(&head_id)?.expect("head body");
    let forged_id = EntityId::now();
    let forged_value = encode_trap_claim_value(&EncodedTrapClaim {
        kind: DreamerTrapKind::Consent,
        attempt_id: fixture_j.attempt_id,
        step_hash: hash_k,
        state: DreamerTrapState::Sent,
        at: 10_012,
        note: "forged cross-attempt".to_owned(),
    });
    let forged_candidate = ClaimCandidate::new(
        DREAMER_TRAP_PREDICATE,
        ClaimSubject::Entity(fixture_k.subject),
        forged_value,
        1.0,
    );
    let envelope = envelope_from_claim_body(&head_body)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(
                &forged_id,
                forged_candidate,
                &envelope,
                occurred(10_012),
                10_012,
            )
            .apply(wtxn)?;
        vault.supersede_claim_in_txn(wtxn, &forged_id, &head_id, 10_012)
    })?;

    let error = consume_trap_signal(&vault, &runner, &trap_k, 10_013)
        .expect_err("cross-attempt signal refused");
    assert!(matches!(
        error,
        Error::InvalidClaimBody("dreamer trap signal names a different attempt")
    ));
    assert!(
        runner.parked_attempt(fixture_j.attempt_id)?.is_some(),
        "attempt J stays parked"
    );
    let (_, head) = trap_head(&vault, &trap_k.trap_claim_id)?;
    assert_ne!(head.state, DreamerTrapState::Consumed);
    Ok(())
}

#[test]
fn consume_refuses_when_parked_by_other_owner() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let step_hash = request_fixture().canonical_hash().expect("hash");
    let trap = open_trap(&vault, &ctx, DreamerTrapKind::Consent, step_hash, "consent")?;
    let runner = DreamerRunnerStore::new(&vault);

    // The attempt is parked by SOMEONE ELSE (e.g. the wake driver), not by this
    // trap's recorded owner.
    runner.park_attempt(crate::dreamer_runner::ParkDreamerAttempt {
        attempt_id: fixture.attempt_id,
        reason: "driver park".to_owned(),
        park_owner: "wake-worker".to_owned(),
        now: 10_001,
    })?;
    register_wait(&vault, &trap, 10_002)?;
    send_trap_signal(&vault, &trap.trap_claim_id, step_hash, 10_003)?;

    let error =
        consume_trap_signal(&vault, &runner, &trap, 10_004).expect_err("owner mismatch refused");
    assert!(matches!(error, Error::InvalidAttemptQueueRecord(_)));

    // The whole consume wtxn rolled back: no consumed transition landed and
    // the other owner's parked row is intact.
    let (_, head) = trap_head(&vault, &trap.trap_claim_id)?;
    assert_ne!(head.state, DreamerTrapState::Consumed);
    assert!(runner.parked_attempt(fixture.attempt_id)?.is_some());
    Ok(())
}

#[test]
fn step_hash_stable_across_field_order() {
    // Same content, different construction order → identical step identity.
    let mut request_a = request_fixture();
    let mut request_b = request_fixture();
    request_a.params.clear();
    request_a
        .params
        .insert("alpha".to_owned(), json!({"z": 1, "y": [1, 2]}));
    request_a.params.insert("beta".to_owned(), json!(2));
    request_b.params.clear();
    request_b.params.insert("beta".to_owned(), json!(2));
    request_b
        .params
        .insert("alpha".to_owned(), json!({"y": [1, 2], "z": 1}));

    assert_eq!(
        request_a.canonical_hash().expect("hash a"),
        request_b.canonical_hash().expect("hash b"),
        "content-hash identity must ignore construction order"
    );

    // Different content → different identity.
    request_b.params.insert("gamma".to_owned(), json!(3));
    assert_ne!(
        request_a.canonical_hash().expect("hash a"),
        request_b.canonical_hash().expect("hash b"),
    );
}

#[test]
fn step_and_trap_values_encode_decode_fail_closed() -> Result<()> {
    let attempt_id = AttemptId::from_bytes(&[0x11_u8; 16])?;
    let step_claim = EncodedStepClaim {
        attempt_id,
        step_hash: [0x22; 32],
        progression: StepProgression::Finished,
        model_id: "test/model@r1".to_owned(),
        purpose: "consolidation".to_owned(),
        params_hash: bytes_to_hex_lower(&[0x33; 32]),
        usage_in: 100,
        usage_out: 50,
        response: Some("{\"ok\":true}".to_owned()),
        response_ref: None,
        at: 10_000,
    };
    let value = encode_step_claim_value(&step_claim);
    let decoded = decode_step_claim_value(&value)?;
    assert_eq!(decoded.attempt_id, attempt_id);
    assert_eq!(decoded.step_hash, [0x22; 32]);
    assert_eq!(decoded.progression, StepProgression::Finished);
    assert_eq!(decoded.model_id, "test/model@r1");
    assert_eq!(decoded.purpose, "consolidation");
    assert_eq!(decoded.usage_in, 100);
    assert_eq!(decoded.usage_out, 50);

    // Unknown key → fail closed.
    let Value::Map(mut entries) = encode_step_claim_value(&step_claim) else {
        panic!("step value must be a map");
    };
    entries.push((Value::from("unknown_key"), Value::from(1_u64)));
    assert!(decode_step_claim_value(&Value::Map(entries)).is_err());

    // BOTH response and response_ref → fail closed.
    let Value::Map(mut entries) = encode_step_claim_value(&step_claim) else {
        panic!("step value must be a map");
    };
    entries.push((Value::from(KEY_RESPONSE_REF), Value::Binary(vec![0x44; 16])));
    assert!(decode_step_claim_value(&Value::Map(entries)).is_err());

    // NEITHER response nor response_ref → fail closed.
    let Value::Map(entries) = encode_step_claim_value(&step_claim) else {
        panic!("step value must be a map");
    };
    let entries: Vec<(Value, Value)> = entries
        .into_iter()
        .filter(|(key, _)| key.as_str() != Some(KEY_RESPONSE))
        .collect();
    assert!(decode_step_claim_value(&Value::Map(entries)).is_err());

    // Trap value round-trip + unknown-key fail-closed.
    let trap_claim = EncodedTrapClaim {
        kind: DreamerTrapKind::Consent,
        attempt_id,
        step_hash: [0x55; 32],
        state: DreamerTrapState::Waiting,
        at: 10_001,
        note: "note".to_owned(),
    };
    let value = encode_trap_claim_value(&trap_claim);
    let decoded = decode_trap_claim_value(&value)?;
    assert_eq!(decoded.kind, DreamerTrapKind::Consent);
    assert_eq!(decoded.attempt_id, attempt_id);
    assert_eq!(decoded.step_hash, [0x55; 32]);
    assert_eq!(decoded.state, DreamerTrapState::Waiting);
    assert_eq!(decoded.note, "note");

    let Value::Map(mut entries) = encode_trap_claim_value(&trap_claim) else {
        panic!("trap value must be a map");
    };
    entries.push((Value::from("unknown_key"), Value::from(1_u64)));
    assert!(decode_trap_claim_value(&Value::Map(entries)).is_err());
    Ok(())
}

#[test]
fn oversize_response_lands_in_blob_artifact() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let ctx = ctx(&vault, &fixture, 10_000);
    let big_text = "x".repeat(DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES + 1);
    let backend = ScriptedBackend::new(vec![Ok(response_fixture(&big_text))]);
    let guard = guard_with_limit(10_000);
    let request = request_fixture();
    let step_hash = request.canonical_hash().expect("hash");

    let outcome =
        block_on(call_as_step(&ctx, &backend, &guard, request)).expect("oversize execution");
    let StepOutcome::Finished { response, .. } = outcome else {
        panic!("expected finished step");
    };

    let claim_id =
        step_index_lookup(&vault, fixture.attempt_id, &step_hash)?.expect("memo index row");
    let body = vault.get_claim(&claim_id)?.expect("terminal claim");
    let decoded = decode_step_claim_value(&body.value)?;
    assert!(
        decoded.response.is_none(),
        "oversize response never inlines"
    );
    let artifact_id = decoded.response_ref.expect("response_ref artifact id");
    assert!(vault.get_blob_artifact(&artifact_id)?.is_some());

    // Memoized replay reads the artifact back byte-identically.
    let backend = ScriptedBackend::new(Vec::new());
    let outcome =
        block_on(call_as_step(&ctx, &backend, &guard, request_fixture())).expect("memoized replay");
    let StepOutcome::Finished {
        response: replayed,
        memoized,
        ..
    } = outcome
    else {
        panic!("expected finished step");
    };
    assert!(memoized);
    assert_eq!(replayed, response);
    Ok(())
}

#[test]
fn trap_for_durable_wait_always_consent() {
    let wait = crate::code_run::SelfDurableWait {
        wait_id: EntityId::now(),
        effect: crate::code_run::SelfEffect::AskHuman,
        reason: crate::code_run::SelfDurableWaitReason::HumanInput,
        prompt: Some("may I?".to_owned()),
    };
    assert_eq!(
        trap_for_durable_wait(&wait, [0x99; 32]),
        DreamerTrapKind::Consent
    );
}

struct HungBackend;

impl LlmBackend for HungBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(std::future::pending())
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

fn injected_deadline(
    start_elapsed_ms: u64,
    ceiling_ms: u64,
) -> (Arc<std::sync::atomic::AtomicU64>, crate::WakePassDeadline) {
    let elapsed = Arc::new(std::sync::atomic::AtomicU64::new(start_elapsed_ms));
    let clock = Arc::clone(&elapsed);
    let deadline = crate::WakePassDeadline::with_clock(
        ceiling_ms,
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    (elapsed, deadline)
}

#[test]
fn deadline_race_aborts_hung_generate() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    // Not yet in the finalize window (elapsed 1s of 180s), so the step is
    // admitted; the clock jumps past the ceiling while the call hangs.
    let (elapsed, deadline) = injected_deadline(1_000, 180_000);
    let mut ctx = ctx(&vault, &fixture, 10_000);
    ctx.deadline = Some(&deadline);
    let guard = guard_with_limit(10_000);

    let advancer = {
        let elapsed = Arc::clone(&elapsed);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(120));
            elapsed.store(180_001, Ordering::SeqCst);
        })
    };
    let error = block_on(call_as_step(&ctx, &HungBackend, &guard, request_fixture()))
        .expect_err("hung generate must lose the deadline race");
    advancer.join().expect("advancer thread");

    assert!(matches!(error, DurableStepError::DeadlineHardCut));
    let read = guard.read();
    assert_eq!(read.reserved_units, 0, "lease aborted with settled spend");
    assert_eq!(read.used_units, 0);
    let runner = DreamerRunnerStore::new(&vault);
    let parked = runner
        .parked_attempt(fixture.attempt_id)?
        .expect("attempt parked");
    assert_eq!(parked.reason, crate::DREAMER_HARD_CUT_PARK_REASON);
    let step_hash = request_fixture().canonical_hash().expect("hash");
    assert!(step_state_read(&vault, fixture.attempt_id, &step_hash)?.is_none());
    Ok(())
}

/// Backend whose generate future lets the injected deadline pass while the
/// call is in flight, then completes on the very next poll — modeling a
/// provider response that arrives after the ceiling.
struct ExpireThenCompleteBackend {
    clock: Arc<std::sync::atomic::AtomicU64>,
}

impl LlmBackend for ExpireThenCompleteBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let clock = Arc::clone(&self.clock);
        let mut polled = false;
        Box::pin(std::future::poll_fn(move |cx| {
            if polled {
                return Poll::Ready(Ok(response_fixture("arrived after the deadline")));
            }
            polled = true;
            clock.store(180_001, Ordering::SeqCst);
            cx.waker().wake_by_ref();
            Poll::Pending
        }))
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

#[test]
fn expired_deadline_never_records_finished() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let (elapsed, deadline) = injected_deadline(1_000, 180_000);
    let mut ctx = ctx(&vault, &fixture, 10_000);
    ctx.deadline = Some(&deadline);
    let guard = guard_with_limit(10_000);
    let backend = ExpireThenCompleteBackend {
        clock: Arc::clone(&elapsed),
    };

    // The response ARRIVES, but only after the ceiling passed. Expiry is
    // checked before the completion poll, so the call loses the race — it
    // must never be recorded as a finished step.
    let error = block_on(call_as_step(&ctx, &backend, &guard, request_fixture()))
        .expect_err("expired call must never finish");
    assert!(matches!(error, DurableStepError::DeadlineHardCut));

    let step_hash = request_fixture().canonical_hash().expect("hash");
    assert!(
        step_index_lookup(&vault, fixture.attempt_id, &step_hash)?.is_none(),
        "no terminal step claim for an expired call"
    );
    let read = guard.read();
    assert_eq!(read.reserved_units, 0, "lease aborted");
    assert_eq!(read.used_units, 0, "no spend recorded");
    let runner = DreamerRunnerStore::new(&vault);
    let parked = runner
        .parked_attempt(fixture.attempt_id)?
        .expect("attempt parked");
    assert_eq!(parked.reason, crate::DREAMER_HARD_CUT_PARK_REASON);
    // The deadline hard-cut park must also store parked_at in Unix SECONDS:
    // now_ms=10_000 lands as 10, not 10_000 (#480-1).
    assert_eq!(
        parked.parked_at, 10,
        "deadline hard-cut park must store parked_at in seconds, not milliseconds"
    );
    Ok(())
}

#[test]
fn finalize_window_refuses_new_steps_serves_memoized() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let guard = guard_with_limit(10_000);

    // Memoize the step OUTSIDE any wake pass first.
    let backend = ScriptedBackend::new(vec![Ok(response_fixture("memoized answer"))]);
    let outside = ctx(&vault, &fixture, 10_000);
    let outcome = block_on(call_as_step(&outside, &backend, &guard, request_fixture()))
        .expect("first execution");
    let StepOutcome::Finished { legibility, .. } = outcome else {
        panic!("expected finished step");
    };
    assert!(legibility.is_none(), "no envelope outside a wake pass");

    // Inside the finalize window: memoized hit still served, WITH envelope.
    let (_elapsed, deadline) = injected_deadline(170_000, 180_000);
    let mut inside = ctx(&vault, &fixture, 11_000);
    inside.deadline = Some(&deadline);
    let backend = ScriptedBackend::new(Vec::new());
    let outcome = block_on(call_as_step(&inside, &backend, &guard, request_fixture()))
        .expect("memoized hit in finalize window");
    let StepOutcome::Finished {
        memoized,
        legibility,
        ..
    } = outcome
    else {
        panic!("expected finished step");
    };
    assert!(memoized);
    let envelope = legibility.expect("envelope inside wake pass");
    assert!(envelope.wrap_up, "94% elapsed is past the 80% notice");
    assert_eq!(envelope.finalize_by_ms, Some(10_000));
    assert_eq!(envelope.remaining_ms, 10_000);

    // A NEW step (different request) is refused fail-closed.
    let mut fresh = request_fixture();
    fresh.params.insert("novel".to_owned(), json!(true));
    let error = block_on(call_as_step(&inside, &backend, &guard, fresh))
        .expect_err("new steps are refused in the finalize window");
    assert!(matches!(error, DurableStepError::FinalizeRefused));
    Ok(())
}

#[test]
fn finished_outcome_carries_legibility_inside_wake_pass() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = step_fixture(&vault, 10)?;
    let (_elapsed, deadline) = injected_deadline(0, 180_000);
    let mut ctx = ctx(&vault, &fixture, 10_000);
    ctx.deadline = Some(&deadline);
    let backend = ScriptedBackend::new(vec![Ok(response_fixture("fresh answer"))]);
    let guard = guard_with_limit(10_000);

    let outcome =
        block_on(call_as_step(&ctx, &backend, &guard, request_fixture())).expect("fresh execution");
    let StepOutcome::Finished { legibility, .. } = outcome else {
        panic!("expected finished step");
    };
    let envelope = legibility.expect("envelope inside wake pass");
    assert_eq!(envelope.limit_units, 10_000);
    assert_eq!(envelope.remaining_units, 10_000 - 150);
    assert_eq!(envelope.remaining_ms, 180_000);
    assert!(!envelope.wrap_up);
    assert_eq!(envelope.finalize_by_ms, None);
    Ok(())
}
