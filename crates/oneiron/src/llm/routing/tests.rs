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
                wire: ModelWireFormat::OpenaiCompat,
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
                wire: ModelWireFormat::OpenaiCompat,
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
    fn judge(
        &self,
        task: &str,
        model: &ModelId,
        description: &str,
        _effort: ReasoningEffort,
    ) -> DescriptionJudgment {
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
    seat.bind(&mut later_call).unwrap();
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
    override_seat.bind(&mut next_call).unwrap();
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
    assert_eq!(vault.pending_description_reasks().unwrap(), revisions);
    vault
        .acknowledge_description_reask(&revisions[0].identity)
        .unwrap();
    assert!(vault.pending_description_reasks().unwrap().is_empty());
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
fn verdict_calls_route_independently_without_prefix_or_generating_seat_mutation() {
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
    for reserved in ["reasoning_effort", "output_config"] {
        let settings = SeatSettings {
            allowed_models: None,
            effort: None,
            inference_overrides: BTreeMap::from([(reserved.into(), json!("invalid"))]),
        };
        assert!(
            block_on(vault.call_routed_verdict(
                "quick",
                &judge,
                &settings,
                request(),
                VerdictPayload {
                    instructions: Some("current".into()),
                    input: vec![ContentPart::Text {
                        text: "question".into()
                    }]
                },
                VerdictExecution {
                    context: &ctx,
                    backend: &backend,
                    guard: &guard
                }
            ))
            .is_err()
        );
    }
    assert!(backend.0.lock().unwrap().is_empty());
    let before = judge.calls();
    for (i, selected) in ["test/cheap@r1", "test/strong@r1"].iter().enumerate() {
        let mut call = request();
        call.messages.extend([
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "old user turn".into(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "old assistant turn".into(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "another old user turn".into(),
                }],
            },
        ]);
        call.params.insert("temperature".into(), json!(0.9));
        let settings = SeatSettings {
            allowed_models: Some(vec![model(selected)]),
            effort: None,
            inference_overrides: BTreeMap::from([("temperature".into(), json!(0.2))]),
        };
        let outcome = block_on(vault.call_routed_verdict(
            "quick",
            &judge,
            &settings,
            call,
            VerdictPayload {
                instructions: Some("current verdict instruction".into()),
                input: vec![ContentPart::Text {
                    text: format!("question {i}"),
                }],
            },
            VerdictExecution {
                context: &ctx,
                backend: &backend,
                guard: &guard,
            },
        ))
        .unwrap();
        assert!(matches!(outcome, StepOutcome::Finished { .. }));
    }
    let mut updated = policy();
    updated.models[0].effort_ladder = vec![ReasoningEffort::Low];
    vault.set_description_policy(&updated).unwrap();
    let high = SeatSettings {
        allowed_models: None,
        effort: Some(ReasoningEffort::High),
        inference_overrides: BTreeMap::from([("temperature".into(), json!(0.2))]),
    };
    assert!(matches!(
        block_on(vault.call_routed_verdict(
            "quick",
            &judge,
            &high,
            request(),
            VerdictPayload {
                instructions: Some("current verdict instruction".into()),
                input: vec![ContentPart::Text {
                    text: "high-effort question".into()
                }]
            },
            VerdictExecution {
                context: &ctx,
                backend: &backend,
                guard: &guard
            }
        ))
        .unwrap(),
        StepOutcome::Finished { .. }
    ));
    assert_eq!(judge.calls(), before + 3);
    let calls = backend.0.lock().unwrap();
    assert_eq!(calls.len(), 3);
    for (call, expected) in calls
        .iter()
        .zip(["test/cheap@r1", "test/strong@r1", "test/strong@r1"])
    {
        assert_eq!(call.model, model(expected));
        assert_eq!(call.messages.len(), 2);
        assert_eq!(call.messages[0].role, LlmMessageRole::System);
        assert_eq!(
            call.messages[0].content,
            vec![ContentPart::Text {
                text: "current verdict instruction".into()
            }]
        );
        assert_eq!(call.messages[1].role, LlmMessageRole::User);
        assert_eq!(call.params["temperature"], json!(0.2));
    }
    assert_eq!(calls[2].params["reasoning_effort"], json!("high"));
    assert_eq!(vault.routed_seat("writer").unwrap(), Some(seat));
}

#[test]
fn persisted_reask_is_recoverable_after_restart_until_acknowledged() {
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let mut configured = policy();
    configured.models[1].model = model("test/strong@r2");
    vault.set_description_policy(&configured).unwrap();
    let original = vault.check_description_drift().unwrap();
    assert_eq!(original.len(), 1);
    drop(vault); // simulate a crash before the host has queued the owner ask
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    assert!(reopened.check_description_drift().unwrap().is_empty());
    assert_eq!(reopened.pending_description_reasks().unwrap(), original);
    reopened
        .acknowledge_description_reask(&original[0].identity)
        .unwrap();
    assert!(reopened.pending_description_reasks().unwrap().is_empty());
    assert!(reopened.check_description_drift().unwrap().is_empty());
    assert!(
        reopened
            .description_reask(&original[0].identity)
            .unwrap()
            .unwrap()
            .acknowledged
    );
}

#[test]
fn effort_constraint_filters_before_judgment_and_is_part_of_judge_input() {
    struct Fitness(Mutex<Vec<(ModelId, ReasoningEffort)>>);
    impl DescriptionJudge for Fitness {
        fn judge(
            &self,
            _task: &str,
            model: &ModelId,
            _line: &str,
            effort: ReasoningEffort,
        ) -> DescriptionJudgment {
            self.0.lock().unwrap().push((model.clone(), effort));
            DescriptionJudgment {
                fitness: if model.name() == "cheap" { 100 } else { 90 },
                reason: "fit".into(),
            }
        }
    }
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let mut configured = policy();
    configured.models[0].effort_ladder = vec![ReasoningEffort::Low];
    vault.set_description_policy(&configured).unwrap();
    let judge = Fitness(Mutex::new(vec![]));
    let settings = SeatSettings {
        allowed_models: None,
        effort: Some(ReasoningEffort::High),
        inference_overrides: BTreeMap::new(),
    };
    let seat = vault
        .route_seat(
            SeatBirth {
                id: "effort-filter",
                role: "writer",
                task: "quick",
                purpose: &CallPurpose::AnswerGen,
                settings: &settings,
                tier: &tier(),
            },
            &judge,
        )
        .unwrap();
    assert_eq!(seat.model, model("test/strong@r1"));
    assert_eq!(seat.effort, ReasoningEffort::High);
    assert_eq!(
        *judge.0.lock().unwrap(),
        vec![(model("test/strong@r1"), ReasoningEffort::High)]
    );
    let measurement = BTreeMap::new();
    let (candidate, judgment, effort) = resolve(
        &configured,
        &measurement,
        &settings,
        &CallPurpose::AutoCheck,
        "quick",
        &judge,
    )
    .unwrap();
    assert_eq!(candidate.model, model("test/strong@r1"));
    assert_eq!(judgment.fitness, 90);
    assert_eq!(effort, ReasoningEffort::High);
    assert_eq!(judge.0.lock().unwrap().len(), 2);
}

#[test]
fn verdict_controls_reject_shadowing_provider_options_and_reserved_overrides() {
    let mut request = request();
    request.provider_options.insert(
        "openai".into(),
        json!({"temperature": 0.9, "reasoning_effort": "high"}),
    );
    let original = request.clone();
    assert!(
        apply_controls(
            &mut request,
            ModelWireFormat::OpenaiCompat,
            ReasoningEffort::Low,
            &BTreeMap::from([("temperature".into(), json!(0.2))])
        )
        .is_err()
    );
    assert_eq!(request, original);
    for reserved in [
        "reasoning_effort",
        "reasoning",
        "thinking",
        "model",
        "output_config",
    ] {
        assert!(
            apply_controls(
                &mut request,
                ModelWireFormat::OpenaiCompat,
                ReasoningEffort::Low,
                &BTreeMap::from([(reserved.into(), json!("override"))])
            )
            .is_err()
        );
    }
}
