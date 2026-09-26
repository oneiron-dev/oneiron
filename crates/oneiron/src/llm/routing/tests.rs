use super::*;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::llm::{
    BudgetExhaustionPolicy, BudgetLease, CallClass, CallEnvelope, ContentPart, FinishReason,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmResponse, LlmStreamResult, LlmUsage,
    TierPrecedence,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use serde_json::json;
use std::sync::Mutex;

fn model(value: &str) -> ModelId {
    ModelId::new(value).unwrap()
}
fn policy() -> DescriptionPolicy {
    DescriptionPolicy {
        models: vec![
            ModelDescription {
                model: model("test/cheap@r1"),
                locality: ModelLocality::OnDevice,
                owner: Some(OwnerModelLine {
                    model: model("test/cheap@r1"),
                    text: "small fast tasks".into(),
                    expected_quality: 800_000,
                }),
                public_benchmark: Some("public cheap".into()),
                vendor: None,
                effort_ladder: vec![ReasoningEffort::Low, ReasoningEffort::High],
            },
            ModelDescription {
                model: model("test/strong@r1"),
                locality: ModelLocality::OwnServer,
                owner: Some(OwnerModelLine {
                    model: model("test/strong@r1"),
                    text: "deep tasks".into(),
                    expected_quality: 900_000,
                }),
                public_benchmark: None,
                vendor: None,
                effort_ladder: vec![ReasoningEffort::Low, ReasoningEffort::High],
            },
        ],
        contradiction_margin_millionths: 100_000,
        vault_effort: None,
        purpose_effort: BTreeMap::new(),
        global_effort: None,
    }
}
struct Judge(Mutex<Vec<(ModelId, String)>>);
impl Judge {
    fn new() -> Self {
        Self(Mutex::new(vec![]))
    }
    fn calls(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}
impl DescriptionJudge for Judge {
    fn judge(&self, task: &str, model: &ModelId, description: &str) -> DescriptionJudgment {
        self.0
            .lock()
            .unwrap()
            .push((model.clone(), description.into()));
        DescriptionJudgment {
            fitness: if model.name() == "cheap" && task == "quick" {
                90
            } else {
                50
            },
            reason: format!("judged {task}"),
        }
    }
}
fn tier() -> TierPrecedence {
    TierPrecedence {
        per_seat: None,
        vault_policy: Some(ModelTierRef("vault".into())),
        purpose_default: Some(ModelTierRef("purpose".into())),
        global_default: ModelTierRef("global".into()),
    }
}
fn request() -> LlmRequest {
    LlmRequest {
        model: model("test/unused@r1"),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: tier(),
            response_format: ResponseFormat::Json {
                schema: json!({"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}}}),
            },
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: "cached prefix".into(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "judge this".into(),
                }],
            },
        ],
        tools: vec![],
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}
#[test]
fn seat_birth_pins_model_and_effort_and_overrides_later_calls() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    vault.set_description_policy(&policy()).unwrap();
    let judge = Judge::new();
    let seat = vault
        .route_seat(
            SeatBirth {
                id: "seat-1",
                role: "writer",
                task: "quick",
                purpose: &CallPurpose::AnswerGen,
                settings: &SeatSettings::default(),
                tier: &tier(),
            },
            &judge,
        )
        .unwrap();
    assert_eq!(seat.model, model("test/cheap@r1"));
    assert_eq!(seat.effort, ReasoningEffort::Low);
    assert!(seat.receipt.contains("test/cheap@r1 with low effort"));
    let changed = vault
        .route_seat(
            SeatBirth {
                id: "seat-1",
                role: "other",
                task: "deep",
                purpose: &CallPurpose::AnswerGen,
                settings: &SeatSettings {
                    allowed_models: Some(vec![model("test/strong@r1")]),
                    effort: Some(ReasoningEffort::High),
                    inference_overrides: BTreeMap::new(),
                },
                tier: &tier(),
            },
            &judge,
        )
        .unwrap();
    assert_eq!(changed, seat);
    assert_eq!(vault.routed_seat("seat-1").unwrap(), Some(seat.clone()));
    let mut later_call = request();
    later_call.model = model("test/strong@r1");
    later_call.envelope.tier.per_seat = Some(ModelTierRef("call-attempt".into()));
    later_call
        .params
        .insert("reasoning_effort".into(), json!("high"));
    seat.bind(&mut later_call);
    assert_eq!(later_call.model, seat.model);
    assert_eq!(later_call.envelope.tier.resolved(), &seat.tier);
    assert_eq!(later_call.params["reasoning_effort"], json!("low"));
    let override_seat = vault
        .route_seat(
            SeatBirth {
                id: "seat-2",
                role: "writer",
                task: "quick",
                purpose: &CallPurpose::AnswerGen,
                settings: &SeatSettings {
                    allowed_models: Some(vec![model("test/cheap@r1")]),
                    effort: Some(ReasoningEffort::High),
                    inference_overrides: BTreeMap::from([("temperature".into(), json!(0.2))]),
                },
                tier: &tier(),
            },
            &judge,
        )
        .unwrap();
    assert_eq!(override_seat.effort, ReasoningEffort::High);
    assert!(override_seat.receipt.contains("high effort"));
    let mut next_call = request();
    next_call.params.insert("temperature".into(), json!(0.9));
    override_seat.bind(&mut next_call);
    assert_eq!(next_call.params["temperature"], json!(0.2));
}
#[test]
fn revision_and_contradiction_trigger_once_without_moving_owner_line() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let mut configured = policy();
    configured.models[1].model = model("test/strong@r2");
    configured.models[1].public_benchmark = None;
    vault.set_description_policy(&configured).unwrap();
    vault
        .record_model_measurement(MeasuredDescription {
            model: model("test/cheap@r1"),
            text: "vault evidence".into(),
            quality_millionths: 750_000,
        })
        .unwrap();
    let revisions = vault.check_description_drift().unwrap();
    assert_eq!(revisions.len(), 1);
    assert_eq!(revisions[0].trigger, ReaskTrigger::RevisionChanged);
    assert!(vault.check_description_drift().unwrap().is_empty());
    assert_eq!(
        vault.description_reask(&revisions[0].identity).unwrap(),
        Some(revisions[0].clone())
    );
    assert_eq!(revisions[0].observed_model, model("test/strong@r2"));
    configured.models[1].public_benchmark = Some("new public evidence".into());
    vault.set_description_policy(&configured).unwrap();
    assert!(vault.check_description_drift().unwrap().is_empty());
    let judge = Judge::new();
    vault
        .route_seat(
            SeatBirth {
                id: "rev",
                role: "worker",
                task: "deep",
                purpose: &CallPurpose::AnswerGen,
                settings: &SeatSettings {
                    allowed_models: Some(vec![model("test/strong@r2")]),
                    effort: None,
                    inference_overrides: BTreeMap::new(),
                },
                tier: &tier(),
            },
            &judge,
        )
        .unwrap();
    assert_eq!(judge.0.lock().unwrap()[0].1, "new public evidence");
    vault
        .record_model_measurement(MeasuredDescription {
            model: model("test/cheap@r1"),
            text: "vault evidence".into(),
            quality_millionths: 699_999,
        })
        .unwrap();
    let contradiction = vault.check_description_drift().unwrap();
    assert_eq!(contradiction.len(), 1);
    assert_eq!(
        contradiction[0].trigger,
        ReaskTrigger::MeasuredContradiction
    );
    assert_eq!(
        vault.description_reask(&contradiction[0].identity).unwrap(),
        Some(contradiction[0].clone())
    );
    vault
        .record_model_measurement(MeasuredDescription {
            model: model("test/cheap@r1"),
            text: "new vault evidence".into(),
            quality_millionths: 100_000,
        })
        .unwrap();
    assert!(vault.check_description_drift().unwrap().is_empty());
    assert_eq!(
        vault.description_policy().unwrap().unwrap().models[1]
            .owner
            .as_ref()
            .unwrap()
            .model,
        model("test/strong@r1")
    );
}

struct CapturingBackend(Mutex<Vec<LlmRequest>>);
impl LlmBackend for CapturingBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.0.lock().unwrap().push(request);
        Box::pin(async {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: "{\"ok\":true}".into(),
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            })
        })
    }
    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        panic!("not a stream")
    }
    fn supports(&self, _model: &ModelId, capability: super::super::LlmCapability) -> bool {
        capability == super::super::LlmCapability::JsonResponse
    }
}
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct Wake(std::thread::Thread);
    impl std::task::Wake for Wake {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(std::sync::Arc::new(Wake(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}
#[test]
fn verdict_calls_route_twice_without_prefix_or_generating_seat_mutation() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    vault.set_description_policy(&policy()).unwrap();
    let judge = Judge::new();
    let seat = vault
        .route_seat(
            SeatBirth {
                id: "writer",
                role: "writer",
                task: "deep",
                purpose: &CallPurpose::AnswerGen,
                settings: &SeatSettings {
                    allowed_models: Some(vec![model("test/strong@r1")]),
                    effort: None,
                    inference_overrides: BTreeMap::new(),
                },
                tier: &tier(),
            },
            &judge,
        )
        .unwrap();
    let before = judge.calls();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let at = TimeRange { start: 10, end: 10 };
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at, 10, b"actor")
        .unwrap();
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at, 10, b"subject")
        .unwrap();
    let runner = DreamerRunnerStore::new(&vault);
    let status = runner
        .enqueue(EnqueueDreamerAttempt {
            attempt_type: "verdict-test".into(),
            input: rmpv::Value::from("input"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("verdict-run".into()),
            now: 10,
        })
        .unwrap();
    let attempt_id = match status {
        EnqueueDreamerAttemptOutcome::Enqueued(s) | EnqueueDreamerAttemptOutcome::Existing(s) => {
            s.attempt.id
        }
    };
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id,
        run_id: Some("verdict-run".into()),
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Agent),
        subject,
        deadline: None,
        now_ms: 10_000,
    };
    let backend = CapturingBackend(Mutex::new(vec![]));
    let guard = BudgetGuard::with_reserve_units(
        "verdict-test",
        10_000,
        500,
        BudgetExhaustionPolicy::Suspend,
    );
    for (i, selected) in ["test/cheap@r1", "test/strong@r1"].iter().enumerate() {
        let mut call = request();
        call.messages[1].content = vec![ContentPart::Text {
            text: format!("question {i}"),
        }];
        let settings = SeatSettings {
            allowed_models: Some(vec![model(selected)]),
            effort: None,
            inference_overrides: BTreeMap::new(),
        };
        let outcome = block_on(vault.call_routed_verdict(
            "quick",
            &judge,
            &settings,
            call,
            VerdictExecution {
                context: &ctx,
                backend: &backend,
                guard: &guard,
            },
        ))
        .unwrap();
        assert!(matches!(outcome, StepOutcome::Finished { .. }));
    }
    assert_eq!(judge.calls(), before + 2);
    let calls = backend.0.lock().unwrap();
    assert_eq!(calls.len(), 2);
    for (call, expected) in calls.iter().zip(["test/cheap@r1", "test/strong@r1"]) {
        assert_eq!(call.model, model(expected));
        assert_eq!(call.messages.len(), 1);
        assert_eq!(call.messages[0].role, LlmMessageRole::User);
    }
    assert_eq!(vault.routed_seat("writer").unwrap(), Some(seat));
}
