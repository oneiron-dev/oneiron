use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use serde_json::json;

use crate::config::VaultConfig;
use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerJob, EnqueueDreamerJobOutcome};
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
    job_id: JobId,
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
    let status = match runner.enqueue(EnqueueDreamerJob {
        job_type: "consolidation-step-test".to_owned(),
        input: rmpv::Value::from("input"),
        parent_job: None,
        dedupe_key: None,
        run_id: Some("run-test".to_owned()),
        now,
    })? {
        EnqueueDreamerJobOutcome::Enqueued(status) | EnqueueDreamerJobOutcome::Existing(status) => {
            status
        }
    };

    Ok(StepFixture {
        job_id: status.job.id,
        actor: WriteActor::new(actor_entity, EdgeActorClass::Agent),
        subject,
    })
}

fn ctx<'a>(vault: &'a Vault, fixture: &StepFixture, now_ms: u64) -> DurableStepContext<'a> {
    DurableStepContext {
        vault,
        job_id: fixture.job_id,
        run_id: Some("run-test".to_owned()),
        envelope_actor: fixture.actor,
        subject: fixture.subject,
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
    let StepOutcome::Finished { response, memoized } = outcome else {
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
        fixture.job_id,
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
    assert!(step_index_lookup(&vault, fixture.job_id, &step_hash)?.is_some());
    assert!(step_state_read(&vault, fixture.job_id, &step_hash)?.is_none());
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
    assert_eq!(decoded.job_id, fixture.job_id);
    assert_eq!(decoded.step_hash, trap.step_hash);

    // The job is parked and the transition row is deleted.
    let runner = DreamerRunnerStore::new(&vault);
    assert!(runner.parked_job(fixture.job_id)?.is_some(), "job parked");
    assert!(step_state_read(&vault, fixture.job_id, &trap.step_hash)?.is_none());
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
    runner.park_job(crate::dreamer_runner::ParkDreamerJob {
        job_id: fixture.job_id,
        reason: "consent".to_owned(),
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

    // Consume validates and commits the consumed transition.
    let job_id = consume_trap_signal(&vault, &runner, &trap, 10_004)?;
    assert_eq!(job_id, fixture.job_id);
    let (_, head) = trap_head(&vault, &trap.trap_claim_id)?;
    assert_eq!(head.state, DreamerTrapState::Consumed);
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
    let job_id = consume_trap_signal(&vault, &runner, &trap, 10_003)?;
    assert_eq!(job_id, fixture.job_id);
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
    runner.park_job(crate::dreamer_runner::ParkDreamerJob {
        job_id: fixture.job_id,
        reason: "budget".to_owned(),
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
        job_id: fixture.job_id,
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
    // The trap is NOT consumed and the job stays parked.
    let (_, head) = trap_head(&vault, &trap.trap_claim_id)?;
    assert_ne!(head.state, DreamerTrapState::Consumed);
    assert!(
        runner.parked_job(fixture.job_id)?.is_some(),
        "job stays parked"
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
    let job_id = JobId::from_bytes(&[0x11_u8; 16])?;
    let step_claim = EncodedStepClaim {
        job_id,
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
    assert_eq!(decoded.job_id, job_id);
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
        job_id,
        step_hash: [0x55; 32],
        state: DreamerTrapState::Waiting,
        at: 10_001,
        note: "note".to_owned(),
    };
    let value = encode_trap_claim_value(&trap_claim);
    let decoded = decode_trap_claim_value(&value)?;
    assert_eq!(decoded.kind, DreamerTrapKind::Consent);
    assert_eq!(decoded.job_id, job_id);
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

    let claim_id = step_index_lookup(&vault, fixture.job_id, &step_hash)?.expect("memo index row");
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
