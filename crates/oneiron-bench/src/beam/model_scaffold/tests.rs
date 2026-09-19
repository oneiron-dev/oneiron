use super::*;
use crate::beam::{
    judge::AnswerPromptPin,
    llm_judge::JudgeBenchmark,
    model::JudgeMetadata,
    model_usage::{ModelPrice, PriceTable},
};
use oneiron::{
    BudgetLease, ContentPart, FinishReason, LlmBackend, LlmGenerateFuture, LlmInputUsage,
    LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage,
};
struct FixtureBackend;
impl LlmBackend for FixtureBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let text = match request.envelope.purpose {
                CallPurpose::Eval => "1",
                CallPurpose::ToolRouting => "contract launch code",
                _ => "tulip",
            };
            if request.envelope.purpose == CallPurpose::AnswerGen {
                let input = match &request.messages[1].content[0] {
                    ContentPart::Text { text } => text,
                    _ => panic!("text"),
                };
                let fields: serde_json::Value = serde_json::from_str(input).unwrap();
                assert_eq!(fields.as_object().unwrap().len(), 2);
                assert!(fields.get("gold").is_none());
                assert!(fields.get("arm").is_none());
            }
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text { text: text.into() }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage {
                        total: 100,
                        ..Default::default()
                    },
                    output: LlmOutputUsage {
                        total: 3,
                        text: 3,
                        reasoning: 0,
                    },
                    raw_provider: serde_json::json!({"prompt_tokens":100,"completion_tokens":3}),
                },
                finish_reason: FinishReason::Stop,
            })
        })
    }
    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::FatalLlmError::InvalidRequest.into())
    }
}
#[test]
fn measured_shared_scaffold_has_real_costs_solo_rows_and_no_chat_lift() {
    let dir = tempfile::tempdir().unwrap();
    let mut corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/beam_128k_contract.run.jsonl"
    ))
    .unwrap();
    corpus["corpus"][0]["metadata"]["stated_claim_predicate"] = serde_json::json!("status.fixture");
    corpus["gold"]["labels"]["wedge_bucket"] = serde_json::json!("temporal");
    std::fs::write(dir.path().join("run.jsonl"), corpus.to_string()).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/beam_128k_contract.run.json"
    ))
    .unwrap();
    manifest["dataset"]["path"] = serde_json::json!("run.jsonl");
    let manifest_path = dir.path().join("run.json");
    std::fs::write(&manifest_path, manifest.to_string()).unwrap();
    let backbone = ModelPin {
        model_id: "openai/gpt-4.1@2025-04-14".parse().unwrap(),
        provider_model: "gpt-4.1-2025-04-14".into(),
        max_tokens: 256,
        temperature: 0.0,
    };
    let cheap = ModelPin {
        model_id: "openai/gpt-4.1-nano@2025-04-14".parse().unwrap(),
        provider_model: "gpt-4.1-nano-2025-04-14".into(),
        ..backbone.clone()
    };
    let judge_model = ModelPin {
        model_id: "openai/gpt-4.1-mini@2025-04-14".parse().unwrap(),
        provider_model: "gpt-4.1-mini-2025-04-14".into(),
        max_tokens: 128,
        temperature: 0.0,
    };
    let price = ModelPrice {
        input_per_million: 2.0,
        output_per_million: 8.0,
        cache_read_per_million: 0.5,
        cache_write_per_million: 2.0,
    };
    let prices = PriceTable {
        revision: "fixture-v1".into(),
        source: "fixture://prices".into(),
        models: [&backbone, &cheap, &judge_model]
            .into_iter()
            .map(|pin| (pin.model_id.clone(), price.clone()))
            .collect(),
    };
    let prompt = "Answer only from the supplied evidence.";
    let mut plan = ModelRunPlan {
        retrieval_manifest: manifest_path,
        temporal_now: 1_800_000_000,
        host: HostConfig {
            endpoint: "http://127.0.0.1".into(),
            api_key_env: None,
            token_budget: 1_000_000,
            prices: prices.clone(),
        },
        judge: JudgeConfig {
            benchmark: JudgeBenchmark::Beam,
            model: judge_model.clone(),
            card: JudgeMetadata {
                judge_id: "gpt-4.1-mini".into(),
                version: "2025-04-14".into(),
                notes: "fixture".into(),
                answer_prompt: Some(AnswerPromptPin::from_exact_text(prompt)),
                vote_count: 3,
            },
        },
        answer_prompt: prompt.into(),
        answerers: [
            ArmKind::Deterministic,
            ArmKind::Agentic,
            ArmKind::BackboneSolo,
            ArmKind::Chat,
        ]
        .into_iter()
        .map(|arm| AnswererArm {
            arm,
            model: if arm == ArmKind::Chat {
                cheap.clone()
            } else {
                backbone.clone()
            },
            cheap_chat: arm == ArmKind::Chat,
        })
        .collect(),
        efforts: vec![
            Effort {
                name: "light".into(),
                token_budget: 1024,
                retrieval_steps: 1,
            },
            Effort {
                name: "medium".into(),
                token_budget: 2048,
                retrieval_steps: 2,
            },
        ],
        amortized_question_count: 1,
        chroma: None,
    };
    let session = ModelSession::with_backend(
        Box::new(FixtureBackend),
        prices,
        &[backbone, cheap, judge_model],
        1_000_000,
    )
    .unwrap();
    let report = run_with_session(&plan, &session).unwrap();
    assert!(report.ablation_unavailable.is_empty());
    assert!(
        report
            .access_factor_observations
            .iter()
            .any(|row| row.baseline < row.ablated)
    );
    assert_eq!(report.ablation_rows.len(), 4);
    assert!(
        report
            .ablation_rows
            .iter()
            .any(|row| row.ablation.as_deref() == Some("ablation-2:access-factor-neutral"))
    );
    assert_eq!(report.rows.len(), 8);
    assert_eq!(report.chat_cost_accuracy_points.len(), 2);
    assert!(!report.frontier.is_empty());
    assert!(report.offline_total.input_tokens > 0);
    assert!(report.offline_total.elapsed_us > 0);
    assert_eq!(report.amortized_question_count, 1);
    for row in &report.rows {
        assert!(row.query_cost.input_tokens > 0 && row.query_cost.cost_usd > 0.0);
        assert!(row.judge_overhead.cost_usd > 0.0);
    }
    let det = report
        .points
        .iter()
        .find(|p| p.arm == ArmKind::Deterministic)
        .unwrap();
    let chat = &report.chat_cost_accuracy_points[0];
    assert!(agency_lift(det, chat).is_err());
    let mut agent = report
        .points
        .iter()
        .find(|point| point.arm == ArmKind::Agentic && point.effort == det.effort)
        .unwrap()
        .clone();
    agent.answerer_params_sha256 = "different parameters".into();
    assert!(agency_lift(det, &agent).is_err());
    let saved = plan.answerers[3].model.clone();
    plan.answerers[3].model = plan.judge.model.clone();
    assert!(plan.validate().is_err());
    plan.answerers[3].model = saved;
    plan.answerers[1].model.model_id = "other/answerer@v1".parse().unwrap();
    assert!(plan.validate().is_err());
}

#[test]
fn shipped_measured_plan_pins_answerer_judge_and_example_prices() {
    let plan: ModelRunPlan =
        serde_json::from_str(include_str!("../../../fixtures/beam_measure.example.json")).unwrap();
    plan.validate().unwrap();
    assert_eq!(plan.host.prices.revision, "example-not-current-tariff");
}
