//! A scripted local model server speaking the OpenAI-compatible
//! (`/v1/chat/completions`) and Anthropic-compatible (`/v1/messages`)
//! protocols, JSON and streamed. Test-only: shared by the crate's unit tests
//! and its process-level integration tests.
// Each including test binary uses a different subset; integration-test
// helpers are not covered by allow-unwrap-in-tests.
#![allow(dead_code, clippy::unwrap_used)]

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::{Value, json};
use tokio::sync::Notify;

/// Builds a reply's text from the request body the fake received.
pub(crate) type Compute = Arc<dyn Fn(&Value) -> String + Send + Sync>;

/// One reply the fake gives, in script order.
#[derive(Clone)]
pub(crate) enum Reply {
    /// Answer with this text, in the protocol and mode the request asked
    /// for. `model` is what the reply claims served it.
    Text { text: String, model: String },
    /// Answer with these deltas as a stream (or their concatenation when
    /// the request did not stream).
    Deltas { deltas: Vec<String>, model: String },
    /// Like `Deltas`, but with no usage: an OpenAI-compatible stream sends
    /// no usage chunk, an Anthropic-compatible one none on any event, and a
    /// plain reply carries `"usage": null`.
    NoUsage { deltas: Vec<String>, model: String },
    /// An HTTP error status with a protocol-shaped body.
    Status(u16),
    /// Never answer until [`FakeLlm::release`] is called; then answer `text`.
    Hold { text: String },
    /// Answer with text computed from the request (to echo ids it carries).
    Computed(Compute),
}

impl Reply {
    pub(crate) fn text(text: impl Into<String>) -> Self {
        Self::Text {
            text: text.into(),
            model: "fake-model".into(),
        }
    }
}

/// One request the fake received.
#[derive(Clone)]
pub(crate) struct Seen {
    pub(crate) path: String,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: Value,
}

#[derive(Default)]
struct Shared {
    script: Mutex<VecDeque<Reply>>,
    fallback: Mutex<Option<Reply>>,
    seen: Mutex<Vec<Seen>>,
    released: Notify,
    holding: Notify,
}

pub(crate) struct FakeLlm {
    pub(crate) base_url: String,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeLlm {
    /// Starts on an ephemeral loopback port. Replies come from `script` in
    /// order; once it runs out, every call gets `fallback` (or a 500).
    pub(crate) async fn start(script: Vec<Reply>, fallback: Option<Reply>) -> Self {
        let shared = Arc::new(Shared::default());
        *shared.script.lock().unwrap() = script.into();
        *shared.fallback.lock().unwrap() = fallback;
        let app = Router::new()
            .route("/v1/chat/completions", post(answer))
            .route("/v1/messages", post(answer))
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base_url: format!("http://{addr}"),
            shared,
            task,
        }
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.shared.seen.lock().unwrap().clone()
    }

    pub(crate) fn push(&self, reply: Reply) {
        self.shared.script.lock().unwrap().push_back(reply);
    }

    /// Lets every held reply answer.
    pub(crate) fn release(&self) {
        self.shared.released.notify_waiters();
        self.shared.released.notify_one();
    }

    /// Resolves once some request is being held.
    pub(crate) async fn wait_holding(&self) {
        self.shared.holding.notified().await;
    }
}

impl Drop for FakeLlm {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn answer(
    State(shared): State<Arc<Shared>>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::Json<Value>,
) -> Response {
    let body = body.0;
    shared.seen.lock().unwrap().push(Seen {
        path: uri.path().to_owned(),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect(),
        body: body.clone(),
    });
    let reply = shared
        .script
        .lock()
        .unwrap()
        .pop_front()
        .or_else(|| shared.fallback.lock().unwrap().clone());
    let anthropic = uri.path().ends_with("/messages");
    let stream = body["stream"].as_bool().unwrap_or(false);
    let reply = match reply {
        Some(Reply::Hold { text }) => {
            let released = shared.released.notified();
            shared.holding.notify_one();
            released.await;
            Reply::text(text)
        }
        Some(reply) => reply,
        None => Reply::Status(500),
    };
    let usage = !matches!(reply, Reply::NoUsage { .. });
    let (deltas, model) = match reply {
        Reply::Status(status) => {
            let body = if anthropic {
                json!({"type": "error", "error": {"type": "api_error", "message": "scripted"}})
            } else {
                json!({"error": {"message": "scripted", "type": "server_error"}})
            };
            return (StatusCode::from_u16(status).unwrap(), axum::Json(body)).into_response();
        }
        Reply::Text { text, model } => (vec![text], model),
        Reply::Deltas { deltas, model } | Reply::NoUsage { deltas, model } => (deltas, model),
        Reply::Computed(compute) => (vec![compute(&body)], "fake-model".to_owned()),
        Reply::Hold { .. } => unreachable!("resolved above"),
    };
    match (anthropic, stream) {
        (false, false) => {
            let mut reply = openai_json(&deltas.concat(), &model);
            if !usage {
                reply["usage"] = Value::Null;
            }
            axum::Json(reply).into_response()
        }
        (true, false) => {
            let mut reply = anthropic_json(&deltas.concat(), &model);
            if !usage {
                reply["usage"] = Value::Null;
            }
            axum::Json(reply).into_response()
        }
        (false, true) => {
            let mut events = openai_events(&deltas, &model);
            if !usage {
                events.pop();
            }
            sse(events)
        }
        (true, true) => {
            let mut events = anthropic_events(&deltas, &model);
            if !usage {
                for (_, event) in &mut events {
                    if let Some(message) = event.get_mut("message").and_then(Value::as_object_mut) {
                        message.remove("usage");
                    }
                    if let Some(event) = event.as_object_mut() {
                        event.remove("usage");
                    }
                }
            }
            sse(events)
        }
    }
}

fn openai_json(text: &str, model: &str) -> Value {
    json!({
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    })
}

fn anthropic_json(text: &str, model: &str) -> Value {
    json!({
        "id": "msg_fake",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 11, "output_tokens": 7}
    })
}

fn openai_events(deltas: &[String], model: &str) -> Vec<(Option<&'static str>, Value)> {
    let mut events: Vec<(Option<&'static str>, Value)> = deltas
        .iter()
        .map(|delta| {
            (
                None,
                json!({"model": model, "choices": [{"index": 0, "delta": {"content": delta}, "finish_reason": null}]}),
            )
        })
        .collect();
    events.push((
        None,
        json!({"model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
    ));
    events.push((
        None,
        json!({"model": model, "choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}),
    ));
    events
}

fn anthropic_events(deltas: &[String], model: &str) -> Vec<(Option<&'static str>, Value)> {
    let mut events = vec![
        (
            Some("message_start"),
            json!({"type": "message_start", "message": {"id": "msg_fake", "type": "message", "role": "assistant", "model": model, "content": [], "usage": {"input_tokens": 11, "output_tokens": 1}}}),
        ),
        (
            Some("content_block_start"),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
    ];
    for delta in deltas {
        events.push((
            Some("content_block_delta"),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": delta}}),
        ));
    }
    events.push((
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 0}),
    ));
    events.push((
        Some("message_delta"),
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 7}}),
    ));
    events.push((Some("message_stop"), json!({"type": "message_stop"})));
    events
}

fn sse(events: Vec<(Option<&'static str>, Value)>) -> Response {
    let mut body = String::new();
    for (name, data) in events {
        if let Some(name) = name {
            body.push_str(&format!("event: {name}\n"));
        }
        body.push_str(&format!("data: {data}\n\n"));
    }
    if !body.contains("event: ") {
        body.push_str("data: [DONE]\n\n");
    }
    // One chunk per event, so the client sees deltas arrive separately.
    let chunks: Vec<Result<String, std::io::Error>> = body
        .split_inclusive("\n\n")
        .map(|chunk| Ok(chunk.to_owned()))
        .collect();
    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(futures_util::stream::iter(chunks)))
        .unwrap()
}
