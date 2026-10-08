//! Every provider kind against a local fake server, the ladder's fallback
//! and receipt, and one config edit swapping a seat's model.
use std::collections::BTreeMap;

use futures_util::StreamExt;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    LlmMessage, LlmMessageRole, LlmRequest, LlmStreamEvent, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence,
};
use serde_json::{Value, json};

use super::*;
use crate::fake_llm::{FakeLlm, Reply};

fn config(toml_text: &str) -> ModelsConfig {
    let file: crate::config::models::ModelsFile = toml::from_str(toml_text).unwrap();
    file.resolve(None).unwrap()
}

fn request(model: &ModelId, text: &str) -> LlmRequest {
    LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("answer".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text: text.into() }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

fn text_of(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

async fn generate(seat: &Seat, text: &str) -> oneiron::LlmResponse {
    let guard = BudgetGuard::new("models-test", 100_000, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit().unwrap().lease;
    seat.backend
        .generate(request(&seat.model, text), &lease)
        .await
        .unwrap()
}

async fn stream(seat: &Seat, text: &str) -> (Vec<String>, oneiron::LlmUsage, String) {
    let guard = BudgetGuard::new("models-test", 100_000, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit().unwrap().lease;
    let mut events = seat
        .backend
        .stream(request(&seat.model, text), &lease)
        .unwrap();
    let mut deltas = Vec::new();
    while let Some(event) = events.next().await {
        match event.unwrap() {
            LlmStreamEvent::TextDelta { text, .. } => deltas.push(text),
            LlmStreamEvent::Done { message, usage, .. } => {
                return (deltas, usage, text_of(&message));
            }
            _ => {}
        }
    }
    panic!("stream ended without Done");
}

fn header(seen: &crate::fake_llm::Seen, name: &str) -> Option<String> {
    seen.headers.get(name).cloned()
}

#[tokio::test]
async fn openai_compatible_provider_generates_and_streams_through_a_seat() {
    let fake = FakeLlm::start(
        vec![
            Reply::Text {
                text: "hello there".into(),
                // The proxy answers under its own spelling of the model.
                model: "gpt-6.1-sol".into(),
            },
            Reply::Deltas {
                deltas: vec!["str".into(), "eam".into(), "ed".into()],
                model: "gpt-6.1-sol".into(),
            },
        ],
        None,
    )
    .await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "default = \"cpa:olety7/gpt-6.1-sol\"\n[providers.cpa]\nkind = \"openai-compat\"\nbase_url = \"{}\"\nkey_env = \"HOME\"\n",
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
    let response = generate(seat, "hi").await;
    assert_eq!(text_of(&response.message), "hello there");
    // Recorded, never rejected: the reply's own model id rides the receipt.
    assert_eq!(
        response.usage.raw_provider["reported_model"],
        json!("gpt-6.1-sol")
    );
    assert_eq!(
        response.usage.raw_provider["requested_model"],
        json!("olety7/gpt-6.1-sol")
    );
    assert_eq!(response.usage.raw_provider["provider"], json!("cpa"));
    let (deltas, usage, text) = stream(seat, "again").await;
    assert_eq!(deltas, ["str", "eam", "ed"]);
    assert_eq!(text, "streamed");
    assert_eq!(usage.raw_provider["reported_model"], json!("gpt-6.1-sol"));
    let seen = fake.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].path, "/v1/chat/completions");
    assert_eq!(seen[0].body["model"], json!("olety7/gpt-6.1-sol"));
    assert_eq!(seen[1].body["stream"], json!(true));
    let home = std::env::var("HOME").unwrap();
    assert_eq!(
        header(&seen[0], "authorization"),
        Some(format!("Bearer {home}"))
    );
}

#[tokio::test]
async fn anthropic_compatible_provider_generates_and_streams_through_a_seat() {
    let fake = FakeLlm::start(
        vec![
            Reply::text("from messages"),
            Reply::Deltas {
                deltas: vec!["a".into(), "b".into()],
                model: "claude-family-latest".into(),
            },
        ],
        None,
    )
    .await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "default = \"claude:proxy/claude-family-latest\"\n[providers.claude]\nkind = \"anthropic-compat\"\nbase_url = \"{}\"\nkey_env = \"HOME\"\nmax_output_tokens = 900\n",
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::DreamerCurrent).expect("seat");
    assert_eq!(seat.locality, ModelLocality::ThirdParty);
    let response = generate(seat, "hi").await;
    assert_eq!(text_of(&response.message), "from messages");
    let (deltas, usage, text) = stream(seat, "again").await;
    assert_eq!(deltas, ["a", "b"]);
    assert_eq!(text, "ab");
    assert_eq!(
        usage.raw_provider["reported_model"],
        json!("claude-family-latest")
    );
    let seen = fake.seen();
    assert_eq!(seen[0].path, "/v1/messages");
    assert_eq!(seen[0].body["model"], json!("proxy/claude-family-latest"));
    assert_eq!(seen[0].body["max_tokens"], json!(900));
    assert!(header(&seen[0], "anthropic-version").is_some());
    let home = std::env::var("HOME").unwrap();
    assert_eq!(header(&seen[0], "x-api-key"), Some(home));
    assert_eq!(header(&seen[0], "authorization"), None);
}

#[tokio::test]
async fn local_openai_compatible_server_takes_a_v1_base_and_no_key() {
    let fake = FakeLlm::start(vec![Reply::text("local answer")], None).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "local = \"llama:qwen3:8b\"\n[providers.llama]\nkind = \"local-openai-compat\"\nbase_url = \"{}/v1\"\n",
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::LocalReasoner).expect("local seat");
    assert_eq!(seat.locality, ModelLocality::OwnServer);
    assert_eq!(text_of(&generate(seat, "hi").await.message), "local answer");
    let seen = fake.seen();
    assert_eq!(seen[0].path, "/v1/chat/completions");
    assert_eq!(seen[0].body["model"], json!("qwen3:8b"));
    assert_eq!(header(&seen[0], "authorization"), None);
}

#[tokio::test]
async fn a_failing_rung_hands_the_call_to_the_next_with_its_prompt() {
    let down = FakeLlm::start(vec![], Some(Reply::Status(503))).await;
    let up = FakeLlm::start(vec![], Some(Reply::text("rescued"))).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        r#"
[providers.first]
kind = "local-openai-compat"
base_url = "{}"
[providers.second]
kind = "openai-compat"
base_url = "{}"
[roles.checker]
rungs = [
  {{ model = "first:small", prompt = "first rung rules" }},
  {{ model = "second:big", prompt = "second rung rules" }},
]
"#,
        down.base_url, up.base_url
    ))));
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    // The widest rung bounds where the seat's data may go.
    assert_eq!(seat.locality, ModelLocality::ThirdParty);
    let response = generate(seat, "check this").await;
    assert_eq!(text_of(&response.message), "rescued");
    assert_eq!(response.usage.raw_provider["rung"], json!(1));
    let (_, usage, text) = stream(seat, "and stream").await;
    assert_eq!(text, "rescued");
    assert_eq!(usage.raw_provider["rung"], json!(1));
    let first = &up.seen()[0].body["messages"][0];
    assert_eq!(first["role"], json!("system"));
    assert_eq!(first["content"], json!("second rung rules"));
    assert_eq!(
        down.seen().len(),
        2,
        "the failing rung was tried first each time"
    );
    assert_eq!(
        down.seen()[0].body["messages"][0]["content"],
        json!("first rung rules")
    );
}

#[tokio::test]
async fn an_unset_key_variable_takes_the_provider_out_and_says_why() {
    let runtime = ModelRuntime::build(Some(&config(
        "default = \"cloud:m\"\n[providers.cloud]\nkind = \"openai-compat\"\nbase_url = \"https://h\"\nkey_env = \"ONEIRON_TEST_KEY_THAT_IS_NEVER_SET\"\n",
    )));
    assert!(runtime.seat(ModelRole::GenerativeReasoner).is_none());
    let status = serde_json::to_value(runtime.status()).unwrap();
    assert_eq!(status["providers"][0]["state"], json!("unavailable"));
    assert!(
        status["providers"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("ONEIRON_TEST_KEY_THAT_IS_NEVER_SET")
    );
    let seat = status["seats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|seat| seat["role"] == json!("generative_reasoner"))
        .unwrap();
    assert_eq!(seat["state"], json!("unavailable"));
    assert_eq!(seat["rungs"][0]["available"], json!(false));
}

#[tokio::test]
async fn one_config_edit_swaps_the_seat_model_with_the_same_calling_code() {
    let openai = FakeLlm::start(vec![], Some(Reply::text("openai side"))).await;
    let anthropic = FakeLlm::start(vec![], Some(Reply::text("anthropic side"))).await;
    let providers = format!(
        "[providers.a]\nkind = \"openai-compat\"\nbase_url = \"{}\"\n[providers.b]\nkind = \"anthropic-compat\"\nbase_url = \"{}\"\n",
        openai.base_url, anthropic.base_url
    );
    let mut answers = Vec::new();
    for default in ["a:model-one", "b:model-two"] {
        let runtime = ModelRuntime::build(Some(&config(&format!(
            "default = \"{default}\"\n{providers}"
        ))));
        let seat = runtime.seat(ModelRole::DreamerCurrent).unwrap();
        answers.push(text_of(&generate(seat, "same call").await.message));
    }
    assert_eq!(answers, ["openai side", "anthropic side"]);
}

#[tokio::test]
async fn the_router_serves_seats_and_configured_models_by_id() {
    let fake = FakeLlm::start(vec![], Some(Reply::text("routed"))).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "default = \"p:m\"\n[providers.p]\nkind = \"openai-compat\"\nbase_url = \"{}\"\n",
        fake.base_url
    ))));
    let router = runtime.router().expect("router");
    let seat = runtime.seat(ModelRole::Checker).unwrap();
    let direct = ModelId::new("p/m@live").unwrap();
    assert_eq!(router.locality(&direct), Some(ModelLocality::ThirdParty));
    assert_eq!(
        router.locality(&seat.model),
        Some(ModelLocality::ThirdParty)
    );
    assert_eq!(
        router.locality(&ModelId::new("p/other@live").unwrap()),
        None
    );
    let guard = BudgetGuard::new("router", 100_000, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit().unwrap().lease;
    for model in [&direct, &seat.model] {
        let response = router.generate(request(model, "hi"), &lease).await.unwrap();
        assert_eq!(text_of(&response.message), "routed");
    }
    assert!(
        router
            .generate(request(&ModelId::new("x/y@z").unwrap(), "hi"), &lease)
            .await
            .is_err()
    );
}

#[test]
fn no_models_section_builds_no_seat() {
    let runtime = ModelRuntime::build(None);
    assert!(runtime.router().is_none());
    assert!(runtime.seat(ModelRole::DreamerCurrent).is_none());
    let status: Value = serde_json::to_value(runtime.status()).unwrap();
    assert_eq!(status["configured"], json!(false));
}

#[test]
fn sse_events_decode_across_reads_and_every_line_end() {
    use super::sse::SseDecoder;
    let datas = |events: Vec<super::sse::SseEvent>| -> Vec<String> {
        events.into_iter().map(|event| event.data).collect()
    };
    // LF framing, an event split across reads, and a leading BOM.
    let mut decoder = SseDecoder::default();
    assert!(decoder.push(b"\xEF\xBB").is_empty());
    let first = decoder.push(b"\xBF\nevent: a\ndata: {\"x\":1}\n\ndata: par");
    assert_eq!(first[0].event.as_deref(), Some("a"));
    assert_eq!(datas(first), [r#"{"x":1}"#]);
    // A CRLF pair split across two reads, and a comment.
    assert!(decoder.push(b"tial\r").is_empty());
    assert_eq!(datas(decoder.push(b"\n\r\n: comment\n\n")), ["partial"]);
    // Lone-CR framing. A CR ending a read may still pair with an LF, so the
    // event it closes waits for the next byte.
    assert_eq!(datas(decoder.push(b"data: one\r\rdata: two\r\r")), ["one"]);
    // Multi-line data, and a last event the stream ends without closing.
    assert_eq!(
        datas(decoder.push(b"data: a\ndata: b\n\ndata: tail")),
        ["two", "a\nb"]
    );
    assert_eq!(datas(decoder.finish()), ["tail"]);
}
