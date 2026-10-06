use super::*;
use crate::beam::{
    judge::AnswerPromptPin,
    model_usage::{ModelPrice, PriceTable},
    report_model::TokenAccountingSource,
};
use oneiron::{
    BudgetLease, ContentPart, FinishReason, LlmBackend, LlmGenerateFuture, LlmInputUsage,
    LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
struct CountingJudge {
    calls: Arc<AtomicUsize>,
    fail_first: bool,
}
impl LlmBackend for CountingJudge {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            assert_eq!(request.envelope.purpose, CallPurpose::Eval);
            assert_eq!(request.model.as_str(), BEAM_JUDGE);
            assert!(
                matches!(&request.messages[0].content[0], ContentPart::Text { text } if text == "Fixture scoring policy.")
            );
            let ContentPart::Text { text } = &request.messages[1].content[0] else {
                panic!("expected judge evidence");
            };
            let evidence: serde_json::Value = serde_json::from_str(text).unwrap();
            let fields = evidence.as_object().unwrap();
            assert_eq!(fields.len(), 3);
            for field in ["question", "candidate_answer", "gold_answer"] {
                assert!(fields[field].is_string());
            }
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_first && n == 0 {
                return Err(oneiron::FatalLlmError::InvalidRequest.into());
            }
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: if n == 2 { "0" } else { "0.5" }.into(),
                    }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage {
                        total: 100,
                        ..Default::default()
                    },
                    output: LlmOutputUsage {
                        total: 2,
                        text: 2,
                        reasoning: 0,
                    },
                    raw_provider: serde_json::json!({"prompt_tokens":100,"completion_tokens":2}),
                },
                finish_reason: FinishReason::Stop,
            })
        })
    }
    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::FatalLlmError::InvalidRequest.into())
    }
}
fn config() -> JudgeConfig {
    JudgeConfig {
        benchmark: JudgeBenchmark::Beam,
        instruction: AnswerPromptPin::from_exact_text("Fixture scoring policy."),
        model: ModelPin {
            model_id: BEAM_JUDGE.parse().unwrap(),
            provider_model: "gpt-4.1-mini-2025-04-14".into(),
            max_tokens: 128,
            temperature: 0.0,
        },
        card: JudgeMetadata {
            judge_id: "gpt-4.1-mini".into(),
            version: "2025-04-14".into(),
            notes: "replicate-paper pinned judge".into(),
            answer_prompt: Some(AnswerPromptPin::from_exact_text(
                "Answer from the evidence.",
            )),
            vote_count: 3,
        },
    }
}
fn prices() -> PriceTable {
    PriceTable {
        revision: "2025-04-14".into(),
        source: "fixture://provider-price-table".into(),
        models: BTreeMap::from([(
            BEAM_JUDGE.parse().unwrap(),
            ModelPrice {
                input_per_million: 0.4,
                output_per_million: 1.6,
                cache_read_per_million: 0.1,
                cache_write_per_million: 0.4,
            },
        )]),
    }
}
#[test]
fn production_judge_issues_three_calls_prices_usage_and_rejects_prompt_before_calls() {
    let config = config();
    let calls = Arc::new(AtomicUsize::new(0));
    let session = ModelSession::with_backend(
        Box::new(CountingJudge {
            calls: calls.clone(),
            fail_first: false,
        }),
        prices(),
        std::slice::from_ref(&config.model),
        1_000_000,
    )
    .unwrap();
    let item = JudgeItem {
        question: "What color?".into(),
        candidate_answer: "blue".into(),
        gold_answer: "blue and green".into(),
        ability: "temporal".into(),
        wedge_bucket: WedgeBucket::Temporal,
    };
    assert!(matches!(
        score_item(&session, &config, "wrong prompt", &item),
        Err(BeamError::JudgeCardInvalid { .. })
    ));
    for instruction in [
        AnswerPromptPin::from_exact_text(""),
        AnswerPromptPin {
            content: "tampered policy".into(),
            sha256: config.instruction.sha256.clone(),
        },
    ] {
        let mut wrong = config.clone();
        wrong.instruction = instruction;
        assert!(matches!(
            score_item(&session, &wrong, "Answer from the evidence.", &item),
            Err(BeamError::JudgeCardInvalid { .. })
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let report = score_item(&session, &config, "Answer from the evidence.", &item).unwrap();
    // BEAM is judged twice (ruling 1a): replicate pass, then fixed pass.
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    assert_eq!(report.judge.instruction, config.instruction);
    // Votes 0.5, 0.5, 0 in the replicate pass; 0.5 x3 in the fixed pass.
    assert_eq!(report.replicate_winning_tally, Some(2));
    assert_eq!(report.replicate_verdict, Some(0.5));
    assert_eq!(report.winning_tally, 3);
    assert_eq!(report.verdict, 0.5);
    let columns = report.score.beam.as_ref().unwrap();
    assert_eq!(columns.aggregate.replicate, 0.0, "int(0.5) at 3e12035");
    assert_eq!(columns.aggregate.fixed, 0.5);
    assert_eq!(report.judge_cost.input_tokens, 600);
    assert_eq!(
        report.judge_cost.token_source,
        TokenAccountingSource::ProviderUsage
    );
    assert!(report.judge_cost.cost_usd > 0.0);
    let zero = LlmUsage {
        raw_provider: serde_json::json!({"prompt_tokens":0,"completion_tokens":0}),
        ..LlmUsage::zero()
    };
    assert_eq!(
        prices()
            .cost(&config.model.model_id, &zero, 0)
            .unwrap()
            .cost_usd,
        0.0
    );
    let mut wrong = config.clone();
    wrong.model.model_id = "openai/gpt-4.1-mini@latest".parse().unwrap();
    assert!(wrong.validate("Answer from the evidence.").is_err());
    let mut lme = config;
    lme.benchmark = JudgeBenchmark::LongMemEvalS;
    lme.model.model_id = LME_JUDGE.parse().unwrap();
    lme.model.provider_model = "gpt-4o-2024-08-06".into();
    lme.card.judge_id = "gpt-4o".into();
    lme.card.version = "2024-08-06".into();
    lme.validate("Answer from the evidence.").unwrap();
}
#[test]
fn failed_vote_does_not_short_circuit_other_judge_calls() {
    let config = config();
    let calls = Arc::new(AtomicUsize::new(0));
    let session = ModelSession::with_backend(
        Box::new(CountingJudge {
            calls: calls.clone(),
            fail_first: true,
        }),
        prices(),
        std::slice::from_ref(&config.model),
        1_000_000,
    )
    .unwrap();
    let item = JudgeItem {
        question: "q".into(),
        candidate_answer: "a".into(),
        gold_answer: "g".into(),
        ability: "temporal".into(),
        wedge_bucket: WedgeBucket::Temporal,
    };
    assert!(score_item(&session, &config, "Answer from the evidence.", &item).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}
/// Records the question slot the judge saw on every call.
struct QuestionRecorder {
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}
impl LlmBackend for QuestionRecorder {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let ContentPart::Text { text } = &request.messages[1].content[0] else {
                panic!("expected judge evidence");
            };
            let evidence: serde_json::Value = serde_json::from_str(text).unwrap();
            let question = evidence["question"].as_str().unwrap().to_owned();
            // Without the question the judge can only half-credit this answer.
            let verdict = if question == "<question>" { "0.5" } else { "1" };
            self.seen.lock().unwrap().push(question);
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: verdict.into(),
                    }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage {
                        total: 100,
                        ..Default::default()
                    },
                    output: LlmOutputUsage {
                        total: 2,
                        text: 2,
                        reasoning: 0,
                    },
                    raw_provider: serde_json::json!({"prompt_tokens":100,"completion_tokens":2}),
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
fn beam_replicate_pass_sees_the_placeholder_and_fixed_pass_sees_the_question() {
    let config = config();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let session = ModelSession::with_backend(
        Box::new(QuestionRecorder { seen: seen.clone() }),
        prices(),
        std::slice::from_ref(&config.model),
        1_000_000,
    )
    .unwrap();
    let item = JudgeItem {
        question: "When did the launch move?".into(),
        candidate_answer: "In May, after the review.".into(),
        gold_answer: "May".into(),
        ability: "temporal_reasoning".into(),
        wedge_bucket: WedgeBucket::Temporal,
    };
    let report = score_item(&session, &config, "Answer from the evidence.", &item).unwrap();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            "<question>",
            "<question>",
            "<question>",
            "When did the launch move?",
            "When did the launch move?",
            "When did the launch move?",
        ]
    );
    assert_eq!(report.replicate_verdict, Some(0.5));
    assert_eq!(report.verdict, 1.0);
    let columns = report.score.beam.unwrap();
    assert_eq!(columns.aggregate.replicate, 0.0);
    assert_eq!(columns.aggregate.fixed, 1.0);
}
#[test]
fn longmemeval_judge_runs_one_pass() {
    let mut config = config();
    config.benchmark = JudgeBenchmark::LongMemEvalS;
    config.model.model_id = LME_JUDGE.parse().unwrap();
    config.model.provider_model = "gpt-4o-2024-08-06".into();
    config.card.judge_id = "gpt-4o".into();
    config.card.version = "2024-08-06".into();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut table = prices();
    table.models = BTreeMap::from([(
        LME_JUDGE.parse().unwrap(),
        ModelPrice {
            input_per_million: 2.5,
            output_per_million: 10.0,
            cache_read_per_million: 1.25,
            cache_write_per_million: 2.5,
        },
    )]);
    let session = ModelSession::with_backend(
        Box::new(QuestionRecorder { seen: seen.clone() }),
        table,
        std::slice::from_ref(&config.model),
        1_000_000,
    )
    .unwrap();
    let item = JudgeItem {
        question: "Where?".into(),
        candidate_answer: "Kyoto".into(),
        gold_answer: "Kyoto".into(),
        ability: "information_extraction".into(),
        wedge_bucket: WedgeBucket::Temporal,
    };
    let report = score_item(&session, &config, "Answer from the evidence.", &item).unwrap();
    assert_eq!(seen.lock().unwrap().len(), 3);
    assert_eq!(report.replicate_verdict, None);
}
