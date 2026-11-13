//! ARCH-0042 `beam:D9`: the `beam-replicate@3e12035` column comes from its own
//! judge pass, which shows the judge the literal placeholder question under
//! the upstream prompt, and int-casts that pass's verdicts. It never relabels
//! the fixed pass. Configs are built from JSON, so this file also builds on a
//! tree without the replicate pin.
use super::{
    BeamError,
    judge::AnswerPromptPin,
    llm_host::{ModelPin, ModelSession},
    llm_judge::{JudgeBenchmark, JudgeConfig, JudgeItem, score_item},
    model::JudgeMetadata,
    model_usage::{ModelPrice, PriceTable},
    nuggets::{self, WedgeBucket},
};
use oneiron::{
    BudgetLease, ContentPart, FinishReason, LlmBackend, LlmGenerateFuture, LlmInputUsage,
    LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const FIXED_POLICY: &str = "Fixture scoring policy.";
const REPLICATE_POLICY: &str = "Fixture upstream 3e12035 scoring policy.";
const ANSWER_PROMPT: &str = "Answer from the evidence.";
const QUESTION: &str = "What color?";
const PLACEHOLDER: &str = "<question>";

/// Records each call's instruction and question. The real question earns
/// half credit and the placeholder full credit, so a replicate column of 1
/// can only come from the placeholder pass's own verdicts.
struct ScriptedJudge {
    calls: Arc<Mutex<Vec<(String, String)>>>,
}
impl LlmBackend for ScriptedJudge {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let ContentPart::Text {
                text: instruction, ..
            } = &request.messages[0].content[0]
            else {
                panic!("expected the judge instruction");
            };
            let ContentPart::Text { text: evidence, .. } = &request.messages[1].content[0] else {
                panic!("expected judge evidence");
            };
            let evidence: serde_json::Value = serde_json::from_str(evidence).unwrap();
            let question = evidence["question"].as_str().unwrap().to_owned();
            let verdict = if question == PLACEHOLDER { "1" } else { "0.5" };
            self.calls
                .lock()
                .unwrap()
                .push((instruction.clone(), question));
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: verdict.into(),
                        signature: None,
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
                    call_metadata: None,
                },
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }
    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::FatalLlmError::InvalidRequest.into())
    }
}

fn judge_pin(benchmark: JudgeBenchmark) -> ModelPin {
    let (model_id, provider_model) = match benchmark {
        JudgeBenchmark::Beam => ("openai/gpt-4.1-mini@2025-04-14", "gpt-4.1-mini-2025-04-14"),
        JudgeBenchmark::LongMemEvalS => ("openai/gpt-4o@2024-08-06", "gpt-4o-2024-08-06"),
    };
    ModelPin {
        model_id: model_id.parse().unwrap(),
        provider_model: provider_model.into(),
        max_tokens: 128,
        temperature: 0.0,
    }
}

/// A judge config as a plan file carries it; `replicate` adds the pin.
fn config_json(benchmark: JudgeBenchmark, replicate: Option<AnswerPromptPin>) -> serde_json::Value {
    let model = judge_pin(benchmark);
    let card = JudgeMetadata {
        judge_id: model.model_id.name().into(),
        version: model.model_id.revision().into(),
        notes: "fixture judge".into(),
        answer_prompt: Some(AnswerPromptPin::from_exact_text(ANSWER_PROMPT)),
        vote_count: 3,
    };
    let instruction = AnswerPromptPin::from_exact_text(FIXED_POLICY);
    let mut config = serde_json::json!({
        "benchmark": benchmark,
        "instruction": instruction,
        "card": card,
        "model": model,
    });
    if let Some(pin) = replicate {
        config["replicate_instruction"] = serde_json::to_value(pin).unwrap();
    }
    config
}

fn session(benchmark: JudgeBenchmark) -> (ModelSession, Arc<Mutex<Vec<(String, String)>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let model = judge_pin(benchmark);
    let prices = PriceTable {
        revision: "fixture".into(),
        source: "fixture://provider-price-table".into(),
        models: BTreeMap::from([(
            model.model_id.clone(),
            ModelPrice {
                input_per_million: 0.4,
                output_per_million: 1.6,
                cache_read_per_million: 0.1,
                cache_write_per_million: 0.4,
            },
        )]),
    };
    let session = ModelSession::with_backend(
        Box::new(ScriptedJudge {
            calls: calls.clone(),
        }),
        prices,
        std::slice::from_ref(&model),
        1_000_000,
    )
    .unwrap();
    (session, calls)
}

fn item() -> JudgeItem {
    JudgeItem {
        question: QUESTION.into(),
        candidate_answer: "blue".into(),
        gold_answer: "blue and green".into(),
        ability: "temporal".into(),
        wedge_bucket: WedgeBucket::Temporal,
    }
}

#[test]
fn a_beam_judgment_runs_a_separate_placeholder_question_pass_and_int_casts_it() {
    let (session, calls) = session(JudgeBenchmark::Beam);
    let config: JudgeConfig = serde_json::from_value(config_json(
        JudgeBenchmark::Beam,
        Some(AnswerPromptPin::from_exact_text(REPLICATE_POLICY)),
    ))
    .expect("a BEAM judge config takes the replicate pass's pinned prompt");

    let mut tampered = config_json(
        JudgeBenchmark::Beam,
        Some(AnswerPromptPin::from_exact_text(REPLICATE_POLICY)),
    );
    tampered["replicate_instruction"]["content"] = "tampered upstream policy".into();
    let tampered: JudgeConfig = serde_json::from_value(tampered).unwrap();
    assert!(
        matches!(
            score_item(&session, &tampered, ANSWER_PROMPT, &item()),
            Err(BeamError::JudgeCardInvalid { .. })
        ),
        "a replicate pin whose content does not match its sha256 is refused"
    );
    assert!(
        calls.lock().unwrap().is_empty(),
        "a refused replicate pin makes no call"
    );

    let report = score_item(&session, &config, ANSWER_PROMPT, &item())
        .expect("a BEAM judgment with a replicate pin scores");
    let calls = calls.lock().unwrap().clone();
    assert_eq!(
        calls.len(),
        6,
        "a BEAM judgment with a replicate pin runs two three-call passes: {calls:?}"
    );
    assert!(
        calls[..3]
            .iter()
            .all(|(instruction, question)| instruction == FIXED_POLICY && question == QUESTION),
        "the beam-fixed pass shows its prompt the real question: {calls:?}"
    );
    assert!(
        calls[3..]
            .iter()
            .all(|(instruction, question)| instruction == REPLICATE_POLICY
                && question == PLACEHOLDER),
        "the replicate pass shows the upstream prompt the literal placeholder question: {calls:?}"
    );
    assert_eq!(
        session.receipts().len(),
        6,
        "every call of both passes is receipted"
    );

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["verdict"], 0.5);
    assert_eq!(
        json["replicate_verdict"], 1.0,
        "the replicate verdict is the placeholder pass's own majority"
    );
    let aggregate = &json["score"]["beam"]["aggregate"];
    assert_eq!(aggregate["fixedFloatClamped"], 0.5);
    assert_eq!(aggregate["officialIntCast"], 0.0);
    assert_eq!(
        aggregate["replicateIntCast"], 1.0,
        "beam-replicate@3e12035 int-casts its own pass's verdicts, not the fixed pass's"
    );
}

#[test]
fn a_judge_for_another_benchmark_refuses_a_replicate_pin_before_any_call() {
    let (session, calls) = session(JudgeBenchmark::LongMemEvalS);
    let plain: JudgeConfig =
        serde_json::from_value(config_json(JudgeBenchmark::LongMemEvalS, None)).unwrap();
    plain
        .validate(ANSWER_PROMPT)
        .expect("FIXTURE: the LongMemEval-S judge without a replicate pin is valid");

    let config: JudgeConfig = serde_json::from_value(config_json(
        JudgeBenchmark::LongMemEvalS,
        Some(AnswerPromptPin::from_exact_text(REPLICATE_POLICY)),
    ))
    .expect("a judge config takes a replicate pin, and validation judges it");
    assert!(
        matches!(
            score_item(&session, &config, ANSWER_PROMPT, &item()),
            Err(BeamError::JudgeCardInvalid { .. })
        ),
        "the beam-replicate@3e12035 pass is a BEAM column: a LongMemEval-S judge refuses its pin"
    );
    assert!(
        calls.lock().unwrap().is_empty(),
        "the refusal comes before any call"
    );
}

#[test]
fn a_proof_number_without_replicate_verdicts_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let judgments: Vec<_> = [
        WedgeBucket::Temporal,
        WedgeBucket::Contradiction,
        WedgeBucket::EventOrdering,
        WedgeBucket::KnowledgeUpdate,
    ]
    .into_iter()
    .map(|bucket| {
        serde_json::json!({
            "ability": format!("{bucket:?}"),
            "wedge_bucket": bucket,
            "value": 0.5,
        })
    })
    .collect();
    let replay = dir.path().join("replay.json");
    std::fs::write(
        &replay,
        serde_json::to_vec(&serde_json::json!({
            "dataset": "beam-replicate-proof",
            "judgments": judgments,
            "output_dir": dir.path().join("out"),
        }))
        .unwrap(),
    )
    .unwrap();
    match nuggets::run(&replay) {
        Err(BeamError::Comparability { reason }) => assert!(
            reason.contains("beam-replicate@3e12035"),
            "a proof number without the beam-replicate@3e12035 column is refused for that column; refused instead for: {reason}"
        ),
        Err(other) => panic!(
            "a proof number without replicate verdicts is refused as not comparable: {other:?}"
        ),
        Ok(_) => panic!("a proof number without the beam-replicate@3e12035 column is refused"),
    }
}

#[test]
fn a_judge_without_a_replicate_pin_runs_one_pass_as_before() {
    let (session, calls) = session(JudgeBenchmark::Beam);
    let config: JudgeConfig =
        serde_json::from_value(config_json(JudgeBenchmark::Beam, None)).unwrap();
    let report = score_item(&session, &config, ANSWER_PROMPT, &item()).unwrap();
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(
        calls
            .iter()
            .all(|(instruction, question)| instruction == FIXED_POLICY && question == QUESTION),
        "{calls:?}"
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["verdict"], 0.5);
    assert!(json.get("replicate_verdict").is_none(), "{json}");
    let aggregate = &json["score"]["beam"]["aggregate"];
    assert_eq!(aggregate["fixedFloatClamped"], 0.5);
    assert_eq!(aggregate["officialIntCast"], 0.0);
    assert!(aggregate.get("replicateIntCast").is_none(), "{aggregate}");
}
