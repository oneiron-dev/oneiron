#![cfg(oneiron_test_support)]
//! FIX CLAIM-RECHECK-REPLY-PARTS (RULING RECHECK-REPLY-ERASE = A): the claim
//! re-check judge's request quotes a kept mail message's words, and the mail
//! is no owner of the judge's step, so the step's stored reply must not keep
//! the model's reasoning about those words (ARCH-0006a #ingest-ops: "derived
//! text must not echo deleted content"). The judge's step keeps its verdict
//! alone: Text parts without a provider signature, no Reasoning part, no
//! token scores. Every other step keeps its whole reply (ARCH-0026
//! #llm-backend-seam), which the control proves.
//!
//! Red on origin/main: the step's `dreamer.step` claim holds the whole reply,
//! the reasoning marker included. Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_source_recheck_reply_parts`

use std::future::Future;
use std::sync::{Arc, Mutex};

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm::decision::HeldLadder;
use oneiron::llm::{
    DREAMER_STEP_PREDICATE, DurableStepContext, ReasoningPartKind, Scope, StepOutcome, call_as_step,
};
use oneiron::model_decision::DecisionBandPolicy;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::claim_source_recheck as doors;
use oneiron::write_envelope::WriteActor;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ContentPart, DreamerAttemptExecution, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmCapability, LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, UnsupportedCapability, Vault, VaultConfig,
    WakeAttemptContext, WakePassDeadline,
};
use oneiron_testkit::{FixtureVault, fixture_cache};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const RUBRIC: &str = "the test rubric the judge reads the claim against its supports by";
const WORDING: &str = "Do the claim's supports, as they stand now, still carry the claim?";

/// Words only the model's reasoning carries.
const REASONING_MARKER: &str = "REASONING-MARKER the mail said the deadline is Friday";
/// The provider's signature over that reasoning.
const REASONING_SIGNATURE_MARKER: &str = "REASONING-SIGNATURE-MARKER";
/// The provider's signature over the verdict text.
const TEXT_SIGNATURE_MARKER: &str = "TEXT-SIGNATURE-MARKER";
/// A token the provider's log-probabilities name.
const TOKEN_SCORE_MARKER: &str = "TOKEN-SCORE-MARKER";

/// The ids the request's last user turn asks about, in order; none when the
/// turn carries no `questions` array.
fn asked_ids(request: &LlmRequest) -> Vec<String> {
    let Some(turn) = request
        .messages
        .iter()
        .rev()
        .find(|message| message.role == LlmMessageRole::User)
    else {
        return Vec::new();
    };
    let text: String = turn
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let Ok(turn) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    turn.get("questions")
        .and_then(serde_json::Value::as_array)
        .map(|questions| {
            questions
                .iter()
                .filter_map(|entry| entry.get("id")?.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A reply whose verdict is `text`, signed, beside a signed Reasoning part
/// and token scores that each carry their marker.
fn reasoned_reply(text: String) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![
                ContentPart::Reasoning {
                    text: REASONING_MARKER.to_owned(),
                    signature: Some(REASONING_SIGNATURE_MARKER.to_owned()),
                    reasoning_kind: ReasoningPartKind::default(),
                    data: None,
                },
                ContentPart::Text {
                    text,
                    signature: Some(TEXT_SIGNATURE_MARKER.to_owned()),
                },
            ],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 10,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 5,
                text: 3,
                reasoning: 2,
            },
            raw_provider: serde_json::Value::Null,
            call_metadata: None,
        },
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: Some(serde_json::json!({
            "content": [{"token": TOKEN_SCORE_MARKER, "logprob": -0.1, "top_logprobs": []}]
        })),
    }
}

/// The judge's backend: it answers each asked question `weakened` at 0.9,
/// with reasoning beside the verdict; a request that asks no question gets
/// `{}` with the same reasoning.
struct ReasoningJudge {
    requests: Mutex<usize>,
}

impl LlmBackend for ReasoningJudge {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let mut verdict = serde_json::Map::new();
        for id in asked_ids(&request) {
            verdict.insert(
                id,
                serde_json::json!({
                    "supported": 0.05,
                    "weakened": 0.9,
                    "unsupported": 0.05,
                }),
            );
        }
        *self.requests.lock().expect("requests mutex") += 1;
        let reply = reasoned_reply(serde_json::Value::Object(verdict).to_string());
        Box::pin(async move { Ok(reply) })
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

/// Drives an async call on a current-thread runtime. This crate's tokio
/// carries no `macros` feature, so `#[tokio::test]` is unavailable.
fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn now_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

/// Every filed `dreamer.step` claim's stored value, rendered as text: its
/// inline response JSON is in it.
fn step_claim_values(vault: &Vault) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut values = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_CLAIM)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.predicate == DREAMER_STEP_PREDICATE {
            values.push(body.value.to_string());
        }
    }
    Ok(values)
}

/// The markers `value` carries, by name.
fn markers_in(value: &str) -> Vec<&'static str> {
    [
        ("reasoning", "REASONING-MARKER"),
        ("reasoning signature", REASONING_SIGNATURE_MARKER),
        ("text signature", TEXT_SIGNATURE_MARKER),
        ("token score", TOKEN_SCORE_MARKER),
    ]
    .into_iter()
    .filter(|(_, marker)| value.contains(marker))
    .map(|(name, _)| name)
    .collect()
}

/// The re-check judge's stored step keeps its verdict and nothing the model
/// said or signed about the kept mail's words: no Reasoning part, no
/// signature, no token score. The verdict still lands on the ladder.
#[test]
fn a_recheck_judge_step_keeps_no_reasoning_part() -> TestResult {
    let directory = tempfile::tempdir()?;
    // As claim_source_recheck_decide.rs: the seed installs the mail pack and
    // syncs the source as the embedded owner, and the engine's MACHINE
    // writers are enrolled with host-held keys so the finding lands signed.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"claim source recheck reply parts host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.provision_engine_machine_identities(&issuer)?;
    let now_ms = now_ms()?;
    let seeded = doors::seed(&vault, now_ms)?;
    let backend = ReasoningJudge {
        requests: Mutex::new(0),
    };
    let guard = BudgetGuard::with_reserve_units(
        "claim-source-recheck-reply-parts",
        100_000,
        500,
        BudgetExhaustionPolicy::Suspend,
    );
    let model = ModelId::new("test/judge@r1")?;
    let deadline = WakePassDeadline::new(60_000);
    let ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "test",
        now_ms,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let held = HeldLadder::unstaffed();
    let before = step_claim_values(&vault)?.len();
    let execution = block_on(doors::run(
        &ctx,
        &seeded.attempt,
        &backend,
        &guard,
        &model,
        RUBRIC,
        held.ladder(),
        DecisionBandPolicy::default(),
        WORDING,
    ))?;
    assert!(
        matches!(execution, DreamerAttemptExecution::Completed { .. }),
        "the re-check completes, got {execution:?}"
    );
    assert!(
        *backend.requests.lock().expect("requests mutex") >= 1,
        "the judge was asked"
    );

    // The verdict, read from the Text part alone, still decides.
    let finding = doors::finding(&vault, seeded.claim)?;
    assert_eq!(
        finding
            .pointer("/recheck/verdict")
            .and_then(serde_json::Value::as_str),
        Some("weakened"),
        "the verdict is decided on the ladder: {finding}"
    );

    let values = step_claim_values(&vault)?;
    assert!(
        values.len() > before,
        "the judge's generation files its step claim"
    );
    for value in &values {
        assert!(
            value.contains("weakened"),
            "the judge's step keeps its verdict: {value}"
        );
        assert_eq!(
            markers_in(value),
            Vec::<&str>::new(),
            "the judge's step keeps nothing beside its verdict: {value}"
        );
    }
    Ok(())
}

fn person(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 10, end: 10 },
        10,
        b"human",
    )?;
    Ok(id)
}

/// The control (ARCH-0026 #llm-backend-seam: a stored Reasoning part records
/// what the provider returned): a step no `UncapturedSteps` guard holds keeps
/// its whole reply, the Reasoning part and the token scores included.
#[test]
fn an_ordinary_step_keeps_its_reasoning_part() -> TestResult {
    // As step_claim_audience.rs: a private copy of the testkit's empty
    // fixture vault.
    let copy = FixtureVault::empty(&fixture_cache!())?.copy()?;
    let vault = copy.open()?;
    let actor = person(&vault)?;
    let subject = person(&vault)?;
    let attempt = match DreamerRunnerStore::new(&vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: "reply-parts-control".to_owned(),
        input: rmpv::Value::from("input"),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-control".to_owned()),
        now: 10,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        other => panic!("unexpected enqueue outcome: {other:?}"),
    };
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id: attempt,
        run_id: Some("run-control".to_owned()),
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Agent),
        subject,
        deadline: None,
        now_ms: 10_000,
        spend_scope: None,
        wake_pass_bound: false,
    };
    let guard = BudgetGuard::with_reserve_units(
        "reply-parts-control",
        10_000,
        500,
        BudgetExhaustionPolicy::Suspend,
    );
    let request = LlmRequest {
        model: ModelId::new("test/model@r1")?,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Scope::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "an ordinary consolidation prompt".to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: std::collections::BTreeMap::new(),
        provider_options: std::collections::BTreeMap::new(),
        host_segments: None,
    };
    let backend = ReasoningJudge {
        requests: Mutex::new(0),
    };
    let outcome = block_on(call_as_step(&ctx, &backend, &guard, request))?;
    let StepOutcome::Finished { response, .. } = outcome else {
        panic!("the ordinary step finishes, got {outcome:?}");
    };
    assert!(
        response
            .message
            .content
            .iter()
            .any(|part| matches!(part, ContentPart::Reasoning { .. })),
        "the ordinary step's answer keeps its Reasoning part"
    );
    let values = step_claim_values(&vault)?;
    let [value] = values.as_slice() else {
        panic!("one step claim, found {}", values.len());
    };
    assert_eq!(
        markers_in(value),
        vec![
            "reasoning",
            "reasoning signature",
            "text signature",
            "token score"
        ],
        "the ordinary step keeps its whole reply: {value}"
    );
    Ok(())
}
