//! The scripted provider answers each prompt from its script, in the mode the
//! request asked for, and fails loudly on anything else.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::panic::{AssertUnwindSafe, catch_unwind};

use oneiron_testkit::provider::{Protocol, Reply, ScriptedProvider, Step, prompt_of};
use oneiron_testkit::{HashingEmbedder, PromptDigest};
use serde_json::{Value, json};

struct Answer {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    /// Whether a chunked body ended with its final empty chunk.
    complete: bool,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).expect("UTF-8 body")
    }
}

fn decode_chunked(mut raw: &[u8]) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let Some(end) = raw.windows(2).position(|w| w == b"\r\n") else {
            return (body, false);
        };
        let size = usize::from_str_radix(std::str::from_utf8(&raw[..end]).expect("chunk size"), 16)
            .expect("hex chunk size");
        raw = &raw[end + 2..];
        if size == 0 {
            return (body, true);
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

fn send(provider: &ScriptedProvider, method: &str, path: &str, body: Option<&Value>) -> Answer {
    let address = provider.base_url().trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(address).expect("connect to the provider");
    let payload = body.map(Value::to_string).unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nhost: provider\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{payload}",
        payload.len()
    )
    .expect("send the request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read the answer");
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a header block");
    let head = String::from_utf8(raw[..split].to_vec()).expect("UTF-8 headers");
    let rest = &raw[split + 4..];
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("status");
    let header = |name: &str| {
        head.lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name).then(|| value.trim().to_owned())
            })
            .unwrap_or_default()
    };
    let (body, complete) = if header("transfer-encoding").contains("chunked") {
        decode_chunked(rest)
    } else {
        (rest.to_vec(), true)
    };
    Answer {
        status,
        content_type: header("content-type"),
        body,
        complete,
    }
}

fn chat(prompt: &str, stream: bool) -> Value {
    json!({
        "model": "test-model",
        "stream": stream,
        "stream_options": {"include_usage": true},
        "messages": [{"role": "system", "content": "You are the executor."}, {"role": "user", "content": prompt}]
    })
}

fn digest(prompt: &str) -> PromptDigest {
    PromptDigest::of_request(&chat(prompt, false))
}

/// The `data:` payloads of an event stream, in order.
fn data_lines(stream: &str) -> Vec<String> {
    stream
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_streamed_request_gets_events_and_a_buffered_one_gets_one_json_body() {
    let provider = ScriptedProvider::start(vec![
        Step::text("streamed", digest("write the program"), "print(1)"),
        Step::text("buffered", digest("write the program"), "print(1)"),
    ])
    .expect("start");
    let streamed = send(&provider, "POST", "/v1/chat/completions", Some(&chat("write the program", true)));
    assert_eq!(streamed.status, 200);
    assert_eq!(streamed.content_type, "text/event-stream");
    assert!(streamed.complete, "the stream ends with its final chunk");
    let events = data_lines(&streamed.text());
    let first: Value = serde_json::from_str(&events[0]).expect("a JSON event");
    assert_eq!(first["choices"][0]["delta"]["content"], "print(1)");
    assert_eq!(first["object"], "chat.completion.chunk");
    let usage: Value = serde_json::from_str(&events[events.len() - 2]).expect("the usage event");
    assert_eq!(usage["usage"]["total_tokens"], 18);
    assert_eq!(events.last().map(String::as_str), Some("[DONE]"));

    let buffered = send(&provider, "POST", "/v1/chat/completions", Some(&chat("write the program", false)));
    assert_eq!(buffered.status, 200);
    assert_eq!(buffered.content_type, "application/json");
    let body = buffered.json();
    assert_eq!(body["choices"][0]["message"]["content"], "print(1)");
    assert_eq!(body["object"], "chat.completion");

    let seen = provider.finish();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].streamed && !seen[1].streamed);
    assert_eq!(seen[0].step.as_deref(), Some("streamed"));
}

#[test]
fn an_anthropic_stream_opens_and_closes_as_the_messages_protocol_does() {
    let provider = ScriptedProvider::start(vec![Step::new(
        "drafter",
        digest("draft it"),
        Reply::Deltas(vec!["Dear ".into(), "owner".into()]),
    )])
    .expect("start");
    let answer = send(&provider, "POST", "/v1/messages", Some(&chat("draft it", true)));
    let text = answer.text();
    let names: Vec<&str> = text.lines().filter_map(|line| line.strip_prefix("event: ")).collect();
    assert_eq!(
        names,
        [
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "message_stop"
        ]
    );
    let _ = provider.finish();
}

#[test]
fn a_prompt_with_no_scripted_reply_is_refused_and_fails_the_test() {
    let provider = ScriptedProvider::start(Vec::new()).expect("start");
    let answer = send(&provider, "POST", "/v1/chat/completions", Some(&chat("an unscripted prompt", true)));
    assert_eq!(answer.status, 400);
    let message = answer.json()["error"]["message"].as_str().unwrap_or_default().to_owned();
    let expected = digest("an unscripted prompt");
    assert!(message.starts_with("oneiron-testkit: no scripted reply for prompt digest"));
    assert!(message.contains(expected.as_hex()));
    let mismatch = provider.check().expect_err("a miss is a violation");
    assert!(mismatch.violations[0].contains(expected.as_hex()));
    assert!(mismatch.violations[0].contains("PromptDigest::from_hex"));
    let finished = catch_unwind(AssertUnwindSafe(|| provider.finish()));
    assert!(finished.is_err(), "finish panics on a miss");
}

#[test]
fn a_step_that_expects_a_stream_refuses_a_buffered_request() {
    // The silent miss of OPUS-E2E-3 (10 Nov): the executor streams, the
    // script answered buffered. Here the mismatch is loud either way round.
    let provider = ScriptedProvider::start(vec![
        Step::text("executor", digest("run"), "print(2)").streamed(),
    ])
    .expect("start");
    let answer = send(&provider, "POST", "/v1/chat/completions", Some(&chat("run", false)));
    assert_eq!(answer.status, 400);
    let mismatch = provider.check().expect_err("a mode mismatch is a violation");
    assert!(mismatch.violations[0].contains("expects a streamed request"));
    assert!(catch_unwind(AssertUnwindSafe(|| provider.finish())).is_err());
}

#[test]
fn a_one_body_reply_refuses_a_streamed_request() {
    let provider = ScriptedProvider::start(vec![Step::new(
        "decision",
        digest("decide"),
        Reply::Json(json!({"choices": []})),
    )])
    .expect("start");
    let answer = send(&provider, "POST", "/v1/chat/completions", Some(&chat("decide", true)));
    assert_eq!(answer.status, 400);
    let mismatch = provider.check().expect_err("a shape mismatch is a violation");
    assert!(mismatch.violations[0].contains("expects a buffered request"));
    assert!(catch_unwind(AssertUnwindSafe(|| provider.finish())).is_err());
}

#[test]
fn a_step_never_requested_fails_the_script() {
    let provider =
        ScriptedProvider::start(vec![Step::text("unused", digest("never sent"), "x")]).expect("start");
    let mismatch = provider.check().expect_err("an unused step is a violation");
    assert!(mismatch.violations[0].contains("\"unused\""));
    assert!(catch_unwind(AssertUnwindSafe(|| provider.finish())).is_err());
}

#[test]
fn a_standing_step_answers_any_number_of_times_including_none() {
    let provider = ScriptedProvider::start(vec![
        Step::text("tagger", digest("tag"), "[]").standing(),
        Step::text("idle", digest("idle"), "[]").standing(),
    ])
    .expect("start");
    for _ in 0..3 {
        assert_eq!(send(&provider, "POST", "/v1/chat/completions", Some(&chat("tag", false))).status, 200);
    }
    assert_eq!(provider.finish().len(), 3);
}

#[test]
fn the_digest_covers_the_prompt_and_not_the_transport() {
    let mut other_model = chat("same", true);
    other_model["model"] = json!("another-model");
    other_model["max_tokens"] = json!(64);
    assert_eq!(PromptDigest::of_request(&chat("same", false)), PromptDigest::of_request(&other_model));
    assert_ne!(digest("same"), digest("different"));
    let mut reordered = json!({"messages": chat("same", false)["messages"].clone()});
    reordered["messages"][0] = json!({"content": "You are the executor.", "role": "system"});
    assert_eq!(PromptDigest::of_request(&reordered), digest("same"));
    assert_eq!(prompt_of(&chat("x", true)).as_object().map(|o| o.len()), Some(1));
    let hex = digest("same").as_hex().to_owned();
    assert_eq!(PromptDigest::from_hex(&hex), Some(digest("same")));
    assert_eq!(PromptDigest::from_hex("abc"), None);
}

#[test]
fn the_digest_covers_the_output_schema_wherever_the_protocol_carries_it() {
    let anthropic = |schema: &str, effort: &str| {
        json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "output_config": {"format": {"type": "json_schema", "schema": {"title": schema}}, "effort": effort}
        })
    };
    let base = PromptDigest::of_request(&anthropic("a", "low"));
    assert_ne!(base, PromptDigest::of_request(&anthropic("b", "low")), "a schema change is a prompt change");
    assert_eq!(base, PromptDigest::of_request(&anthropic("a", "high")), "effort is not the prompt");
    let typed = |format: &str| json!({"messages": [], "envelope": {"response_format": format, "scope": {}}});
    assert_ne!(PromptDigest::of_request(&typed("Text")), PromptDigest::of_request(&typed("Json")));
}

#[test]
fn a_held_reply_answers_only_after_the_test_releases_it() {
    let provider = ScriptedProvider::start(vec![
        Step::text("held", digest("wait"), "done").held("barrier"),
    ])
    .expect("start");
    std::thread::scope(|scope| {
        let request = scope.spawn(|| send(&provider, "POST", "/v1/chat/completions", Some(&chat("wait", false))));
        provider.await_reached("barrier");
        assert!(!request.is_finished(), "the reply waits at the barrier");
        provider.release("barrier");
        let answer = request.join().expect("the request thread");
        assert_eq!(answer.json()["choices"][0]["message"]["content"], "done");
    });
    let _ = provider.finish();
}

#[test]
fn a_cut_stream_stops_mid_answer_with_no_final_chunk() {
    let provider = ScriptedProvider::start(vec![Step::new(
        "dying",
        digest("stream"),
        Reply::CutStream {
            deltas: vec!["a".into(), "b".into(), "c".into()],
            after: 1,
        },
    )])
    .expect("start");
    let answer = send(&provider, "POST", "/v1/chat/completions", Some(&chat("stream", true)));
    assert!(!answer.complete);
    let events = data_lines(&answer.text());
    assert_eq!(events.len(), 1);
    assert!(!answer.text().contains("[DONE]"));
    let _ = provider.finish();
}

#[test]
fn a_scripted_status_answers_with_a_protocol_shaped_error() {
    let provider =
        ScriptedProvider::start(vec![Step::new("down", digest("x"), Reply::Status(503))]).expect("start");
    let answer = send(&provider, "POST", "/v1/messages", Some(&chat("x", false)));
    assert_eq!(answer.status, 503);
    assert_eq!(answer.json()["type"], "error");
    let _ = provider.finish();
}

#[test]
fn the_embeddings_route_serves_the_hashing_embedder() {
    let embedder = HashingEmbedder::new(32);
    let provider = ScriptedProvider::with_embedder(Vec::new(), embedder.clone()).expect("start");
    let answer = send(
        &provider,
        "POST",
        "/v1/embeddings",
        Some(&json!({"model": embedder.model(), "input": ["alpha beta", "gamma"]})),
    );
    let body = answer.json();
    let first: Vec<f32> = serde_json::from_value(body["data"][0]["embedding"].clone()).expect("a vector");
    assert_eq!(first, embedder.embed_text("alpha beta"));
    assert_eq!(body["data"].as_array().map(Vec::len), Some(2));
    let wrong = send(&provider, "POST", "/v1/embeddings", Some(&json!({"model": "other", "input": "x"})));
    assert_eq!(wrong.status, 400);
    assert!(catch_unwind(AssertUnwindSafe(|| provider.finish())).is_err());
}

#[test]
fn an_unknown_route_is_a_violation() {
    let provider = ScriptedProvider::start(Vec::new()).expect("start");
    assert_eq!(send(&provider, "POST", "/v1/completions", Some(&json!({}))).status, 404);
    assert!(provider.check().is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| provider.finish())).is_err());
    let _ = Protocol::OpenAi;
}
