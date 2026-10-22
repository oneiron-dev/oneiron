//! Every provider kind against a local fake server, the ladder's fallback
//! and receipt, and one config edit swapping a seat's model.
use std::collections::BTreeMap;

use futures_util::StreamExt;
use oneiron::llm::run_admission::{
    BudgetLine, DeclaredTeachers, LeaseUnit, MemoryReceipts, RunDeclaration, RunDenied, RunEvent,
    RunReceipt,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    LlmMessage, LlmMessageRole, LlmRequest, LlmStreamEvent, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence,
};
use serde_json::json;

use super::*;
use crate::fake_llm::{FakeLlm, Reply};

/// A run that declares nothing, on a line wide enough for any call here.
pub(super) fn test_run() -> RunAdmission {
    undeclared_run(
        "models-test",
        BudgetGuard::new("models-test", 100_000, BudgetExhaustionPolicy::Suspend),
        Arc::new(MemoryReceipts::default()),
    )
}

/// Each row's event name, in order.
fn events(rows: &[RunReceipt]) -> Vec<&'static str> {
    rows.iter()
        .map(|row| match row.event {
            RunEvent::Admitted(_) => "admitted",
            RunEvent::Denied { .. } => "denied",
            RunEvent::Dispatched { .. } => "dispatched",
            RunEvent::Settled { .. } => "settled",
            RunEvent::Revised { .. } => "revised",
        })
        .collect()
}

pub(super) fn config(toml_text: &str) -> ModelsConfig {
    let file: crate::config::models::ModelsFile = toml::from_str(toml_text).unwrap();
    file.resolve(None).unwrap()
}

pub(super) fn request(model: &ModelId, text: &str) -> LlmRequest {
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
        host_segments: None,
    }
}

pub(super) fn text_of(message: &LlmMessage) -> String {
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
    let run = test_run();
    seat.ladder
        .generate(&run, request(&seat.model, text), None)
        .await
        .unwrap()
}

async fn stream(seat: &Seat, text: &str) -> (Vec<String>, oneiron::LlmUsage, String) {
    let run = test_run();
    let mut events = seat
        .ladder
        .stream(&run, request(&seat.model, text), None)
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
async fn a_call_that_picks_its_own_model_or_route_never_reaches_the_provider() {
    let fake = FakeLlm::start(Vec::new(), None).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "default = \"cpa:olety7/gpt-6.1-sol\"\n[providers.cpa]\nkind = \"openai-compat\"\nbase_url = \"{}\"\nkey_env = \"HOME\"\n",
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
    let run = test_run();
    let mut fallback_list = request(&seat.model, "hi");
    fallback_list
        .provider_options
        .insert("openai".into(), json!({ "models": ["other/model"] }));
    let mut routed = request(&seat.model, "hi");
    routed
        .params
        .insert("provider".into(), json!({ "order": ["other"] }));
    for swapped in [fallback_list, routed] {
        assert!(
            seat.ladder
                .generate(&run, swapped.clone(), None)
                .await
                .is_err()
        );
        // The run refuses the selector at admission, before a stream exists.
        assert!(seat.ladder.stream(&run, swapped, None).is_err());
    }
    assert!(fake.seen().is_empty());
}

/// Astra R6 and R7 for chat turns and workflow steps, #1338's code-mode rule,
/// now through the run's gate: an answer after a failed rung pays for that
/// rung too, and a reply that reports no usage pays the reservation, never
/// nothing. Each rung that went out is admitted, dispatched and settled on
/// its own permit, and the receipts say so.
#[tokio::test]
async fn an_answer_pays_for_the_rungs_that_failed_before_it_and_never_nothing() {
    let failing = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let no_usage = Reply::NoUsage {
        deltas: vec!["ok".into()],
        model: "big".into(),
    };
    let answering = FakeLlm::start(vec![Reply::text("ok"), no_usage], None).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        r#"
[providers.first]
kind = "local-openai-compat"
base_url = "{}"
[providers.second]
kind = "local-openai-compat"
base_url = "{}"
[roles.generative_reasoner]
rungs = [{{ model = "first:small" }}, {{ model = "second:big" }}]
"#,
        failing.base_url, answering.base_url
    ))));
    let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
    let floor = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
    let guard = BudgetGuard::new("models-test", 100 * floor, BudgetExhaustionPolicy::Suspend);
    let receipts = Arc::new(MemoryReceipts::default());
    let mut charges = Vec::new();
    for _ in 0..2 {
        let run = undeclared_run("models-test", guard.clone(), receipts.clone());
        let before = guard.read().used_units;
        let response = seat
            .ladder
            .generate(&run, request(&seat.model, "hi"), None)
            .await
            .expect("the second rung answers");
        // The receipt still counts the rung that failed before the answer.
        assert_eq!(response.usage.raw_provider["failed_rungs"], json!(1));
        charges.push(guard.read().used_units - before);
    }
    // 11 + 7 tokens and one failed rung; then no usage and one failed rung.
    assert_eq!(charges, [18 + floor, 2 * floor]);
    let rows = receipts.rows();
    let call = ["admitted", "dispatched", "settled"];
    assert_eq!(events(&rows), [call, call, call, call].concat());
    let settled: Vec<u64> = rows
        .iter()
        .filter_map(|row| match row.event {
            RunEvent::Settled { units, .. } => Some(units),
            _ => None,
        })
        .collect();
    assert_eq!(settled, [floor, 18, floor, floor]);
    assert_eq!(
        guard.read().reserved_units,
        0,
        "every permit settled, none leaked"
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

/// Astra #1304 P2: a configured output ceiling never reached an
/// OpenAI-compatible wire, so the provider generated to its own default.
#[tokio::test]
async fn the_configured_output_ceiling_reaches_every_openai_compatible_call() {
    let fake = FakeLlm::start(vec![], Some(Reply::text("bounded"))).await;
    let endpoints = [
        ("openai-compat", "", "max_tokens"),
        ("local-openai-compat", "", "max_tokens"),
        (
            "openai-compat",
            "output_limit_field = \"max_completion_tokens\"\n",
            "max_completion_tokens",
        ),
    ];
    for (kind, field_line, field) in endpoints {
        let before = fake.seen().len();
        let runtime = ModelRuntime::build(Some(&config(&format!(
            "default = \"p:m\"\n[providers.p]\nkind = \"{kind}\"\nbase_url = \"{}\"\nmax_output_tokens = 64\n{field_line}",
            fake.base_url
        ))));
        let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
        // A workflow step generates; a chat turn streams.
        generate(seat, "step").await;
        stream(seat, "turn").await;
        // A caller asking for more is held to the ceiling.
        let run = test_run();
        let mut wide = request(&seat.model, "wide");
        wide.params.insert("max_tokens".into(), json!(4_096));
        seat.ladder.generate(&run, wide, None).await.unwrap();
        // Sol R2 #1304: a limit spelled as a float or a string was left on
        // the wire beside the ceiling, and a lenient endpoint read it.
        let mut loose = request(&seat.model, "loose");
        loose
            .params
            .insert("max_completion_tokens".into(), json!(4_096.0));
        loose.params.insert("max_tokens".into(), json!("4096"));
        seat.ladder.generate(&run, loose, None).await.unwrap();
        let seen = fake.seen();
        assert_eq!(seen.len(), before + 4);
        for call in &seen[before..] {
            assert_eq!(call.body[field], json!(64), "{}", call.body);
            let other = if field == "max_tokens" {
                "max_completion_tokens"
            } else {
                "max_tokens"
            };
            assert!(call.body.get(other).is_none(), "{}", call.body);
        }
    }
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
async fn a_reply_without_usage_still_names_the_model_that_served_it() {
    let served = || Reply::NoUsage {
        deltas: vec!["one ".into(), "two".into()],
        model: "served-under-another-name".into(),
    };
    let fake = FakeLlm::start(vec![served(), served()], None).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "local = \"llama:qwen3:8b\"\n[providers.llama]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n",
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::LocalReasoner).expect("local seat");
    // `"usage": null` on a plain reply.
    let response = generate(seat, "hi").await;
    assert_eq!(text_of(&response.message), "one two");
    assert_eq!(
        response.usage.raw_provider["reported_model"],
        json!("served-under-another-name")
    );
    // A finished stream that never sends a usage chunk.
    let (deltas, usage, text) = stream(seat, "again").await;
    assert_eq!(deltas, ["one ", "two"]);
    assert_eq!(text, "one two");
    assert_eq!(usage.input.total, 0);
    assert_eq!(
        usage.raw_provider["reported_model"],
        json!("served-under-another-name")
    );
}

/// Greptile #1304 P2: an Anthropic-compatible reply without usage, plain or
/// streamed, lost the model that served it.
#[tokio::test]
async fn an_anthropic_reply_without_usage_still_names_the_model_that_served_it() {
    let served = || Reply::NoUsage {
        deltas: vec!["one ".into(), "two".into()],
        model: "served-under-another-name".into(),
    };
    let fake = FakeLlm::start(vec![served(), served()], None).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "default = \"claude:proxy/claude-family-latest\"\n[providers.claude]\nkind = \"anthropic-compat\"\nbase_url = \"{}\"\n",
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
    // `"usage": null` on a plain reply.
    let response = generate(seat, "hi").await;
    assert_eq!(text_of(&response.message), "one two");
    assert_eq!(
        response.usage.raw_provider["reported_model"],
        json!("served-under-another-name")
    );
    // A stream whose `message_start` carries no usage.
    let (deltas, usage, text) = stream(seat, "again").await;
    assert_eq!(deltas, ["one ", "two"]);
    assert_eq!(text, "one two");
    assert_eq!(
        usage.raw_provider["reported_model"],
        json!("served-under-another-name")
    );
}

/// Greptile #1304 P2: one streamed event had no size bound, so a provider
/// that never ended it grew the decoder's buffer (and its rescans) without
/// limit.
#[tokio::test]
async fn a_streamed_event_past_the_bound_is_refused_not_buffered() {
    let fake = FakeLlm::start(
        vec![Reply::Deltas {
            deltas: vec!["x".repeat(super::sse::MAX_EVENT_BYTES)],
            model: "fake-model".into(),
        }],
        None,
    )
    .await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "local = \"llama:qwen3:8b\"\n[providers.llama]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n",
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::LocalReasoner).expect("local seat");
    let run = test_run();
    let mut events = seat
        .ladder
        .stream(&run, request(&seat.model, "hi"), None)
        .unwrap();
    let mut refused = false;
    while let Some(event) = events.next().await {
        if event.is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused, "an event past the bound was buffered and decoded");
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

/// Review repro (Astra R10, #1338): a call that fails is charged for the
/// provider calls it made, one reservation each. Without a manifest the
/// seat's ladder tries every rung; with one pinning a rung's model, the call
/// goes to that model alone.
#[tokio::test]
async fn a_failed_call_pays_for_each_provider_call_it_made() {
    let fake = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        r#"
[providers.local]
kind = "local-openai-compat"
base_url = "{}"
[roles.generative_reasoner]
rungs = [
  {{ model = "local:first" }},
  {{ model = "local:second" }},
  {{ model = "local:third" }},
]
"#,
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
    let (_dir, vault) = crate::ai_host::test_support::rooted_vault();
    let guard = BudgetGuard::new("models-test", 100_000, BudgetExhaustionPolicy::Suspend);
    let mut made = Vec::new();
    for pinned in [false, true] {
        if pinned {
            crate::ai_host::test_support::pin_every_role(
                &vault,
                "local/second@live",
                ModelLocality::OwnServer,
            );
        }
        let route = runtime
            .route_role(&vault, ModelRole::GenerativeReasoner, seat)
            .unwrap();
        let before = (fake.seen().len(), guard.read().used_units);
        let run = undeclared_run(
            "models-test",
            guard.clone(),
            Arc::new(MemoryReceipts::default()),
        );
        route
            .ladder
            .generate(&run, request(&route.model, "hi"), None)
            .await
            .expect_err("every provider call fails");
        made.push((
            route.ladder.rungs(),
            fake.seen().len() - before.0,
            guard.read().used_units - before.1,
        ));
    }
    let reserve = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
    assert_eq!(made, [(3, 3, 3 * reserve), (1, 1, reserve)]);
}

/// Once a rung has spoken, its stream is the answer, cut or whole: one that
/// ends or breaks after its first event is reported cut, and never hands the
/// call to the next rung.
#[tokio::test]
async fn a_rung_that_has_spoken_keeps_the_call_when_its_stream_breaks() {
    let delta = json!({"model": "m", "choices": [{"index": 0, "delta": {"content": "partial"}, "finish_reason": null}]});
    for broken in [
        format!("data: {delta}\n\n"),
        format!("data: {delta}\n\ndata: {{not json\n\n"),
    ] {
        let first = FakeLlm::start(vec![], Some(Reply::Raw(broken.clone()))).await;
        let second = FakeLlm::start(vec![], Some(Reply::text("switched"))).await;
        let runtime = ModelRuntime::build(Some(&config(&format!(
            "[providers.first]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n[providers.second]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n[roles.checker]\nrungs = [{{ model = \"first:small\" }}, {{ model = \"second:big\" }}]\n",
            first.base_url, second.base_url
        ))));
        let seat = runtime.seat(ModelRole::Checker).expect("seat");
        let run = test_run();
        let mut events = seat
            .ladder
            .stream(&run, request(&seat.model, "hi"), None)
            .unwrap();
        let mut deltas = Vec::new();
        let mut cut = false;
        while let Some(event) = events.next().await {
            match event {
                Ok(LlmStreamEvent::TextDelta { text, .. }) => deltas.push(text),
                Ok(LlmStreamEvent::Done { .. }) => panic!("{broken:?}: a broken stream finished"),
                Ok(_) => {}
                Err(_) => cut = true,
            }
        }
        assert_eq!(deltas, ["partial"], "{broken:?}");
        assert!(cut, "{broken:?}: a broken stream ended as if whole");
        assert!(
            second.seen().is_empty(),
            "{broken:?}: the call switched rungs after the first had spoken"
        );
    }
}

/// Greptile #1304 P2 (follow-up): a provider's whole reply body was read
/// into memory before it was parsed, so a broken provider or proxy could
/// fill the server's memory with one reply. A JSON reply, and a streamed
/// call's error body, are refused past the bound, and the rest goes unread.
#[tokio::test]
async fn an_oversized_provider_body_is_refused_before_it_is_read_whole() {
    use super::http::{HttpFailure, KeyStyle, MAX_REPLY_BYTES, ProviderHttp};
    let whole = 8 * MAX_REPLY_BYTES;
    let fake = FakeLlm::start(
        vec![
            Reply::Oversized {
                status: 200,
                bytes: whole,
            },
            Reply::Oversized {
                status: 502,
                bytes: whole,
            },
        ],
        None,
    )
    .await;
    let models = config(&format!(
        "[providers.p]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n",
        fake.base_url
    ));
    let http = ProviderHttp::new(&models.providers["p"], KeyStyle::Bearer).unwrap();
    let (path, headers, body) = ("/v1/chat/completions", BTreeMap::new(), json!({}));

    let reply = http.post_json(path, &headers, &body).await;
    assert_eq!(reply.err(), Some(HttpFailure::BodyTooLarge));
    assert!(
        fake.sent_before_close().await < whole,
        "the JSON reply was read whole"
    );

    let mut events = Box::pin(http.post_sse(path, &headers, &body));
    assert!(matches!(
        events.next().await,
        Some(Err(HttpFailure::BodyTooLarge))
    ));
    drop(events);
    assert!(
        fake.sent_before_close().await < whole,
        "the error body was read whole"
    );
}

/// Greptile #1304 P2 (re-review): a manifest that selects a later rung got
/// that rung alone, numbered 0, so its receipt named the first rung. A rung
/// after an unavailable one was numbered the same way. The receipt's `rung`
/// is the rung's place in the configured ladder, as status lists it.
#[tokio::test]
async fn a_receipt_names_the_selected_rungs_place_in_the_configured_ladder() {
    let fake = FakeLlm::start(vec![], Some(Reply::text("answered"))).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        r#"
[providers.gone]
kind = "openai-compat"
base_url = "https://h"
key_env = "ONEIRON_TEST_KEY_THAT_IS_NEVER_SET"
[providers.local]
kind = "local-openai-compat"
base_url = "{}"
[roles.generative_reasoner]
rungs = [
  {{ model = "gone:m" }},
  {{ model = "local:first" }},
  {{ model = "local:second" }},
]
"#,
        fake.base_url
    ))));
    let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
    // Rung 0 has no key, so rung 1 answers the ladder.
    assert_eq!(
        generate(seat, "hi").await.usage.raw_provider["rung"],
        json!(1)
    );
    assert_eq!(stream(seat, "hi").await.1.raw_provider["rung"], json!(1));

    let (_dir, vault) = crate::ai_host::test_support::rooted_vault();
    crate::ai_host::test_support::pin_every_role(
        &vault,
        "local/second@live",
        ModelLocality::OwnServer,
    );
    let route = runtime
        .route_role(&vault, ModelRole::GenerativeReasoner, seat)
        .unwrap();
    let run = test_run();
    let response = route
        .ladder
        .generate(&run, request(&route.model, "hi"), None)
        .await
        .unwrap();
    assert_eq!(response.usage.raw_provider["rung"], json!(2));
    assert_eq!(
        response.usage.raw_provider["requested_model"],
        json!("second")
    );
    let mut events = route
        .ladder
        .stream(&run, request(&route.model, "hi"), None)
        .unwrap();
    let mut rung = None;
    while let Some(event) = events.next().await {
        if let LlmStreamEvent::Done { usage, .. } = event.unwrap() {
            rung = Some(usage.raw_provider["rung"].clone());
        }
    }
    assert_eq!(rung, Some(json!(2)));
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
    let run = test_run();
    for model in [&direct, &seat.model] {
        let (_, ladder) = router.served(model).expect("served");
        let response = ladder
            .generate(&run, request(model, "hi"), None)
            .await
            .unwrap();
        assert_eq!(text_of(&response.message), "routed");
    }
    assert!(router.served(&ModelId::new("x/y@z").unwrap()).is_none());
}

/// The host-side constructor for a declared run: it calls only its declared
/// teachers, and a `key_env` key, held at T1 in this process, serves it only
/// for an offer the owner allowed, its receipt saying the run's rules do not
/// hold there. A refused call is never sent.
#[tokio::test]
async fn a_declared_run_calls_only_its_teachers_and_a_t1_key_only_when_allowed() {
    let keyed = FakeLlm::start(vec![], Some(Reply::text("keyed"))).await;
    let own = FakeLlm::start(vec![], Some(Reply::text("own"))).await;
    let receipts = Arc::new(MemoryReceipts::default());
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "default = \"keyed:teacher\"\n[providers.keyed]\nkind = \"openai-compat\"\nbase_url = \"{}\"\nkey_env = \"HOME\"\n[providers.own]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n[roles.checker]\nrungs = [{{ model = \"own:small\" }}]\n",
        keyed.base_url, own.base_url
    ))))
    .with_receipts(receipts.clone());
    let keyed_id = ModelId::new("keyed/teacher@live").unwrap();
    let own_id = ModelId::new("own/small@live").unwrap();
    let declared = |teachers: &[&ModelId]| {
        RunDeclaration::declared(BudgetLine {
            limit_units: 100_000,
            reserve_units: 1_000,
            unit: LeaseUnit::tokens(),
        })
        .with_teachers(
            DeclaredTeachers::new(
                teachers.iter().map(|model| (*model).clone()),
                [],
                "student",
                "distillation",
            )
            .unwrap(),
        )
    };
    let denied = |rows: Vec<RunReceipt>| -> Vec<RunDenied> {
        rows.into_iter()
            .filter_map(|row| match row.event {
                RunEvent::Denied { reason, .. } => Some(reason),
                _ => None,
            })
            .collect()
    };

    // An undeclared teacher, and a declared one at T1 the owner never allowed.
    let run = runtime.declared_run("distill-1", declared(&[&own_id]), None);
    assert!(
        run.generate(keyed_id.as_str(), request(&keyed_id, "hi"))
            .await
            .is_err()
    );
    let run = runtime.declared_run("distill-2", declared(&[&keyed_id]), None);
    assert!(
        run.generate(keyed_id.as_str(), request(&keyed_id, "hi"))
            .await
            .is_err()
    );
    assert!(keyed.seen().is_empty(), "a refused call went out");
    assert!(matches!(
        denied(receipts.rows()).as_slice(),
        [RunDenied::UndeclaredTeacher { .. }, RunDenied::KeyAtT1]
    ));

    // A declared teacher no offer here serves, and a selector the run cannot
    // resolve: each is refused before admission, and each has its row. A
    // caller may pass any text as the selector, so the unresolved one's row
    // keeps none of it, only its length (Astra on #1382).
    let missing = ModelId::new("missing/teacher@v1").unwrap();
    let unresolved = "Bearer sk-test-sentinel-0000";
    let run = runtime.declared_run("distill-1b", declared(&[&missing]), None);
    for selector in [missing.as_str(), unresolved] {
        assert!(
            run.generate(selector, request(&missing, "hi"))
                .await
                .is_err()
        );
    }
    assert!(matches!(
        &denied(receipts.rows())[2..],
        [RunDenied::NoOffer { model }, RunDenied::UnknownSelector { len }]
            if *model == missing && *len == unresolved.len()
    ));
    for row in receipts.rows() {
        let row = serde_json::to_string(&row).unwrap();
        assert!(!row.contains("sk-test-sentinel"), "{row}");
    }
    assert_eq!(run.admission().read().reserved_units, 0);

    // A keyless declared teacher holds the run's rules.
    let run = runtime.declared_run("distill-3", declared(&[&own_id]), None);
    let answer = run
        .generate(own_id.as_str(), request(&own_id, "hi"))
        .await
        .unwrap();
    assert_eq!(text_of(&answer.message), "own");
    // The owner allows the T1 offer: it is served, and its receipt says the
    // run's rules do not hold for it.
    let allowed = declared(&[&keyed_id]).with_custody_override(keyed_id.as_str());
    let run = runtime.declared_run("distill-4", allowed, None);
    let answer = run
        .generate(keyed_id.as_str(), request(&keyed_id, "hi"))
        .await
        .unwrap();
    assert_eq!(text_of(&answer.message), "keyed");
    assert_eq!((own.seen().len(), keyed.seen().len()), (1, 1));
    let enforced: Vec<(String, bool)> = receipts
        .rows()
        .into_iter()
        .filter_map(|row| match row.event {
            RunEvent::Admitted(facts) => Some((facts.subject, facts.rules_enforced)),
            _ => None,
        })
        .collect();
    assert_eq!(
        enforced,
        [
            (own_id.as_str().to_owned(), true),
            (keyed_id.as_str().to_owned(), false)
        ]
    );
}

/// Owner ruling 2026-10-14 (fix 6), Astra and Sol on #1421: the default
/// receipt sink logs ids, counts and codes. A declared run's name and its
/// teachers' purpose are text the host wrote, and every lease id the run's
/// meter issues begins with the run's name, so an admitted, dispatched,
/// settled and refused call logs none of it.
#[tokio::test]
async fn a_declared_runs_receipt_log_carries_no_run_text() {
    const SENTINEL: &str = "sentinel-world-text-3d8e";
    let own = FakeLlm::start(vec![], Some(Reply::text("own"))).await;
    let runtime = ModelRuntime::build(Some(&config(&format!(
        "default = \"own:small\"\n[providers.own]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n[roles.checker]\nrungs = [{{ model = \"own:small\" }}, {{ model = \"own:other\" }}]\n",
        own.base_url
    ))));
    let own_id = ModelId::new("own/small@live").unwrap();
    // Served here, so the refusal is the run's: it did not declare this teacher.
    let undeclared = ModelId::new("own/other@live").unwrap();
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: 100_000,
        reserve_units: 1_000,
        unit: LeaseUnit::tokens(),
    })
    .with_teachers(
        DeclaredTeachers::new(
            [own_id.clone()],
            [],
            "student",
            format!("distil {SENTINEL}"),
        )
        .unwrap(),
    );
    let run = runtime.declared_run(format!("{SENTINEL} nightly digest"), declaration, None);
    // A callsite registration racing another test can miss one capture; the
    // settled and refused rows prove this capture saw the run.
    for _ in 0..3 {
        let sink = crate::logging::tests::CapturedSink::default();
        let guard = tracing::dispatcher::set_default(&sink.production_dispatch());
        run.generate(own_id.as_str(), request(&own_id, "hi"))
            .await
            .unwrap();
        assert!(
            run.generate(undeclared.as_str(), request(&undeclared, "hi"))
                .await
                .is_err()
        );
        drop(guard);
        let written = sink.text();
        if written.contains("settled") && written.contains("undeclared_teacher") {
            assert!(!written.contains(SENTINEL), "{written}");
            assert!(written.contains("admitted"), "{written}");
            assert!(written.contains("dispatched"), "{written}");
            return;
        }
    }
    panic!("no receipt row was captured");
}

/// The `SingleSend` claim on both HTTP transports: one provider call is one
/// request. A failed or throttled reply is not sent again, and a redirect is
/// not followed, so a credential never reaches a second origin.
#[tokio::test]
async fn each_http_transport_sends_a_call_once_and_follows_no_redirect() {
    for (kind, path) in [
        ("openai-compat", "/v1/chat/completions"),
        ("anthropic-compat", "/v1/messages"),
    ] {
        let elsewhere = FakeLlm::start(vec![], Some(Reply::text("moved"))).await;
        let redirect = Reply::Redirect {
            status: 307,
            location: format!("{}{path}", elsewhere.base_url),
        };
        let script = vec![
            Reply::Status(500),
            Reply::Status(500),
            Reply::Status(429),
            Reply::Status(429),
            redirect.clone(),
            redirect,
        ];
        let fake = FakeLlm::start(script, Some(Reply::text("unreached"))).await;
        let runtime = ModelRuntime::build(Some(&config(&format!(
            "default = \"p:m\"\n[providers.p]\nkind = \"{kind}\"\nbase_url = \"{}\"\nkey_env = \"HOME\"\n",
            fake.base_url
        ))));
        let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
        for sent in 1..=6 {
            let run = test_run();
            let call = request(&seat.model, "hi");
            if sent % 2 == 1 {
                assert!(seat.ladder.generate(&run, call, None).await.is_err());
            } else {
                let mut events = seat.ladder.stream(&run, call, None).unwrap();
                let mut failed = false;
                while let Some(event) = events.next().await {
                    failed |= event.is_err();
                }
                assert!(failed, "{kind}: call {sent} ends in an error");
            }
            assert_eq!(fake.seen().len(), sent, "{kind}: call {sent} sent once");
        }
        assert!(
            elsewhere.seen().is_empty(),
            "{kind}: the redirect is not followed"
        );
    }
}

#[test]
fn sse_events_decode_across_reads_and_every_line_end() {
    use super::sse::SseDecoder;
    let datas = |events: Vec<super::sse::SseEvent>| -> Vec<String> {
        events.into_iter().map(|event| event.data).collect()
    };
    // LF framing, an event split across reads, and a leading BOM.
    let mut decoder = SseDecoder::default();
    let mut push = |bytes: &[u8]| decoder.push(bytes).unwrap();
    assert!(push(b"\xEF\xBB").is_empty());
    let first = push(b"\xBF\nevent: a\ndata: {\"x\":1}\n\ndata: par");
    assert_eq!(first[0].event.as_deref(), Some("a"));
    assert_eq!(datas(first), [r#"{"x":1}"#]);
    // A CRLF pair split across two reads, and a comment.
    assert!(push(b"tial\r").is_empty());
    assert_eq!(datas(push(b"\n\r\n: comment\n\n")), ["partial"]);
    // Lone-CR framing: a CR ends its line at once, so an event closed by a
    // read's last CR dispatches without waiting for another byte.
    assert_eq!(datas(push(b"data: one\r\rdata: two\r\r")), ["one", "two"]);
    // An LF opening the next read pairs with that CR; multi-line data; a last
    // event the stream ends without closing.
    assert_eq!(datas(push(b"\ndata: a\ndata: b\n\ndata: tail")), ["a\nb"]);
    assert_eq!(datas(decoder.finish()), ["tail"]);
}

/// A vault-held key's rung refuses, before its permit starts, a call that
/// could only fail before anything is sent: no broker socket at the
/// configured path (nothing there, or a file that is not a socket), a
/// same-user child that exits before it serves or that let its channel go
/// (Astra on #1416), or a custody door that would not release the key to the
/// broker. None reads the key, and none is charged.
#[cfg(unix)]
#[tokio::test]
async fn a_broker_call_that_cannot_go_out_is_refused_uncharged() {
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Door {
        holds: bool,
        reads: AtomicUsize,
    }
    impl KeyDoor for Door {
        fn check(&self, name: &str) -> anyhow::Result<()> {
            anyhow::ensure!(self.holds, "no secret is registered as {name}");
            Ok(())
        }
        fn read(&self, _: &str) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("this door hands out nothing")
        }
    }
    let dir = tempfile::tempdir().unwrap();
    // A separate-user broker: any uid but this process's own.
    let uid = std::fs::metadata(dir.path()).unwrap().uid().wrapping_add(1);
    let socket = dir.path().join("broker.sock");
    // A same-user child that exits before it serves.
    let child = config(
        "[providers.paid]\nkind = \"openai-compat\"\nbase_url = \"https://api.example.test/v1\"\nkey_secret = \"provider-key\"\n[roles.checker]\nrungs = [{ model = \"paid:teacher\" }]\n[broker]\nprogram = \"/bin/false\"\n",
    );
    // A live same-user child whose channel is already closed: it lets its
    // end go, says it serves, and stays up.
    let dropped = dir.path().join("dropped-channel");
    std::fs::write(
        &dropped,
        "#!/bin/sh\nexec 3>&-\necho listening\nexec /bin/cat >/dev/null\n",
    )
    .unwrap();
    std::fs::set_permissions(
        &dropped,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let dropped = config(&format!(
        "[providers.paid]\nkind = \"openai-compat\"\nbase_url = \"https://api.example.test/v1\"\nkey_secret = \"provider-key\"\n[roles.checker]\nrungs = [{{ model = \"paid:teacher\" }}]\n[broker]\nprogram = \"{}\"\n",
        dropped.display()
    ));
    let config = config(&format!(
        "[providers.paid]\nkind = \"openai-compat\"\nbase_url = \"https://api.example.test/v1\"\nkey_secret = \"provider-key\"\n[roles.checker]\nrungs = [{{ model = \"paid:teacher\" }}]\n[broker]\nsocket = \"{}\"\nuid = {uid}\n",
        socket.display()
    ));
    let mut listener = None;
    let cases = [
        ("no path", true),
        ("a plain file", true),
        ("a door that refuses", false),
        ("a child that never serves", true),
        ("a child that let its channel go", true),
    ];
    for (case, holds) in cases {
        match case {
            "a plain file" => std::fs::write(&socket, b"").unwrap(),
            "a door that refuses" => {
                std::fs::remove_file(&socket).unwrap();
                listener = Some(std::os::unix::net::UnixListener::bind(&socket).unwrap());
            }
            _ => {}
        }
        let door = Arc::new(Door {
            holds,
            reads: AtomicUsize::new(0),
        });
        let config = match case {
            "a child that never serves" => &child,
            "a child that let its channel go" => &dropped,
            _ => &config,
        };
        let runtime = ModelRuntime::build_with_keys(Some(config), Some(door.clone()));
        let model = runtime
            .seat(ModelRole::Checker)
            .expect("seat")
            .model
            .clone();
        let receipts = Arc::new(MemoryReceipts::default());
        let meter = BudgetGuard::new("broker-test", 100_000, BudgetExhaustionPolicy::Suspend);
        let run = undeclared_run("broker-test", meter.clone(), receipts.clone());
        let (_, ladder) = runtime.router().unwrap().served(&model).unwrap();
        let refused = ladder.generate(&run, request(&model, "hi"), None).await;
        assert!(refused.is_err(), "{case}");
        assert_eq!(
            door.reads.load(Ordering::SeqCst),
            0,
            "{case}: the key was read"
        );
        assert_eq!(
            (meter.read().used_units, meter.read().reserved_units),
            (0, 0),
            "{case}"
        );
        let rows = receipts.rows();
        assert!(!events(&rows).contains(&"dispatched"), "{case}");
        let denied: Vec<_> = rows
            .iter()
            .filter_map(|row| match &row.event {
                RunEvent::Denied { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(denied, [RunDenied::BackendRefused], "{case}: {rows:?}");
    }
    drop(listener);
}

/// Engine ruling 2026-10-14 (NIGHTLY-SWITCH): a provider set to
/// `response_format = "none"` sends a JSON call no `response_format`; the
/// default still sends the call's schema, on a generate and on a stream.
#[tokio::test]
async fn a_provider_set_to_no_schema_sends_no_response_format() {
    let fake = FakeLlm::start(vec![], Some(Reply::text("{}"))).await;
    let schema = json!({"type": "object"});
    for (line, sends) in [("", true), ("response_format = \"none\"\n", false)] {
        let before = fake.seen().len();
        let runtime = ModelRuntime::build(Some(&config(&format!(
            "default = \"p:m\"\n[providers.p]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n{line}",
            fake.base_url
        ))));
        let seat = runtime.seat(ModelRole::DreamerCurrent).expect("seat");
        let run = test_run();
        let mut call = request(&seat.model, "extract");
        call.envelope.response_format = ResponseFormat::Json {
            schema: schema.clone(),
        };
        seat.ladder
            .generate(&run, call.clone(), None)
            .await
            .unwrap();
        let mut events = seat.ladder.stream(&run, call, None).unwrap();
        while events.next().await.is_some() {}
        let seen = fake.seen();
        assert_eq!(seen.len(), before + 2);
        for sent in &seen[before..] {
            assert_eq!(
                sent.body.get("response_format").is_some(),
                sends,
                "{}",
                sent.body
            );
        }
    }
}
