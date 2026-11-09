//! Scripted model doors: answers from a script keyed by prompt digest, never
//! from a model.
//!
//! - [`ScriptedProvider`]: an OpenAI- and Anthropic-compatible HTTP endpoint
//!   on a loopback port, for a server in another process or an engine
//!   configured with an HTTP provider.
//! - [`ScriptedBackend`]: an [`oneiron::LlmBackend`] for in-process door
//!   tests that hand the engine a backend (`call_as_step`, the code-mode
//!   executor).
//!
//! Both follow one script:
//! - **Keyed by prompt.** Each [`Step`] names the [`PromptDigest`] of the
//!   call it answers (the HTTP body's prompt, or the typed request's).
//!   Steps are not FIFO: concurrent calls find their own.
//! - **Answers in the call's own mode.** A streamed call (`"stream": true`,
//!   or `LlmBackend::stream`) gets a stream (server-sent events over HTTP);
//!   any other gets one body. A step may pin the mode it expects
//!   ([`Step::streamed`], [`Step::buffered`]); a call in the other mode is a
//!   mismatch, and so is a reply that has only one shape ([`Reply::Json`],
//!   [`Reply::Events`], [`Reply::CutStream`]) asked for in the other mode.
//!   This is the silent miss the E2E harness hit (OPUS-E2E-3, 10 Nov): a
//!   buffered JSON body fed to the engine's SSE decoder reads as a cut
//!   stream, and the run waits for a program that never comes.
//! - **Fails loudly.** A call no step answers, a mode or model mismatch, an
//!   unexpected route, or a step never requested is a violation. The call
//!   is refused as the caller's error (HTTP 400, or a fatal invalid request
//!   in process), which the engine does not retry, with a message starting
//!   `oneiron-testkit:`; a
//!   report goes to stderr (with the digest to script, for a miss), and
//!   `finish` or drop panics, so an engine that degrades quietly past the
//!   refusal still fails the test.
//!
//! With [`ScriptedProvider::with_embedder`] the HTTP provider also serves
//! [`HashingEmbedder`] vectors on `POST /v1/embeddings`.

mod backend;
pub mod digest;
mod http;
mod script;
pub mod wire;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::TcpStream;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use serde_json::{Value, json};

pub use self::backend::ScriptedBackend;
pub use self::digest::{NESTED_PROMPT_FIELDS, PROMPT_FIELDS, PromptDigest, canonical_json, prompt_of};
pub use self::script::{ProviderMismatch, SeenCall};
pub use self::wire::{Protocol, Usage};
use self::script::{BarrierState, Script, barrier_map, lock};
use crate::embedder::HashingEmbedder;

/// The call mode a step expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Either; the reply takes the mode the call asked for.
    AsRequested,
    /// Only a streamed call.
    Streamed,
    /// Only a call that does not stream.
    Buffered,
}

/// What a step answers with.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// This text: one delta when streamed, the whole body when buffered.
    Text(String),
    /// These deltas when streamed; their concatenation when buffered.
    Deltas(Vec<String>),
    /// An HTTP error with this status and a protocol-shaped body, in either
    /// mode: a provider that refuses or is down. In process: a retryable
    /// server error for 429 and 5xx, a fatal invalid request otherwise.
    Status(u16),
    /// A stream that sends the first `after` of `deltas` and then ends with
    /// no stop, no usage and no `[DONE]`: a provider that died mid-answer.
    /// Streamed calls only.
    CutStream { deltas: Vec<String>, after: usize },
    /// This exact JSON body with status 200. Buffered HTTP calls only.
    Json(Value),
    /// These exact server-sent event blocks (each ending in a blank line).
    /// Streamed HTTP calls only.
    Events(Vec<String>),
    /// This status, content type and exact body bytes (a malformed answer).
    /// Buffered HTTP calls only.
    Body {
        status: u16,
        content_type: String,
        body: Vec<u8>,
    },
}

/// One scripted answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    id: String,
    digest: PromptDigest,
    reply: Reply,
    mode: Mode,
    model: Option<String>,
    usage: Option<Usage>,
    standing: bool,
    hold: Option<String>,
}

impl Step {
    /// Answers the prompt with digest `digest` once, with `reply`, in the
    /// mode the call asks for.
    #[must_use]
    pub fn new(id: impl Into<String>, digest: PromptDigest, reply: Reply) -> Self {
        Self {
            id: id.into(),
            digest,
            reply,
            mode: Mode::AsRequested,
            model: None,
            usage: Some(Usage::default()),
            standing: false,
            hold: None,
        }
    }

    /// [`Self::new`] with [`Reply::Text`].
    #[must_use]
    pub fn text(id: impl Into<String>, digest: PromptDigest, text: impl Into<String>) -> Self {
        Self::new(id, digest, Reply::Text(text.into()))
    }

    /// Only a streamed call matches; a buffered one is a mismatch.
    #[must_use]
    pub fn streamed(mut self) -> Self {
        self.mode = Mode::Streamed;
        self
    }

    /// Only a buffered call matches; a streamed one is a mismatch.
    #[must_use]
    pub fn buffered(mut self) -> Self {
        self.mode = Mode::Buffered;
        self
    }

    /// The call must name this model, and the reply says it served it.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// The token counts the reply declares (default 11 in, 7 out).
    #[must_use]
    pub fn usage(mut self, input_tokens: u64, output_tokens: u64) -> Self {
        self.usage = Some(Usage {
            input_tokens,
            output_tokens,
        });
        self
    }

    /// The reply declares no usage: no usage chunk when streamed, `"usage":
    /// null` when buffered.
    #[must_use]
    pub fn no_usage(mut self) -> Self {
        self.usage = None;
        self
    }

    /// Answers any number of matching calls, zero included: a background
    /// producer whose call count the test does not pin.
    #[must_use]
    pub fn standing(mut self) -> Self {
        self.standing = true;
        self
    }

    /// The HTTP request waits at barrier `name` until the test calls
    /// [`ScriptedProvider::release`]; [`ScriptedProvider::await_reached`]
    /// returns once it is there. For controlled interleavings, never timing.
    /// [`ScriptedBackend`] refuses a held step.
    #[must_use]
    pub fn held(mut self, name: impl Into<String>) -> Self {
        self.hold = Some(name.into());
        self
    }

    /// The step's id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

struct Shared {
    script: Script,
    embedder: Option<HashingEmbedder>,
    barriers: Mutex<BTreeMap<String, BarrierState>>,
    barrier_changed: Condvar,
}

/// The HTTP scripted provider. See the module docs.
pub struct ScriptedProvider {
    listener: http::Listener,
    shared: Arc<Shared>,
    finished: bool,
}

impl fmt::Debug for ScriptedProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptedProvider")
            .field("base_url", &self.base_url())
            .finish_non_exhaustive()
    }
}

impl ScriptedProvider {
    /// Starts on a free loopback port with `steps` and no embeddings route.
    ///
    /// # Errors
    /// Two steps share an id or a barrier, or the port cannot be bound.
    pub fn start(steps: Vec<Step>) -> io::Result<Self> {
        Self::start_with(steps, None)
    }

    /// [`Self::start`], also serving `embedder` on `POST /v1/embeddings`.
    ///
    /// # Errors
    /// As [`Self::start`].
    pub fn with_embedder(steps: Vec<Step>, embedder: HashingEmbedder) -> io::Result<Self> {
        Self::start_with(steps, Some(embedder))
    }

    fn start_with(steps: Vec<Step>, embedder: Option<HashingEmbedder>) -> io::Result<Self> {
        let (script, barriers) = Script::new(steps)?;
        let shared = Arc::new(Shared {
            script,
            embedder,
            barriers: Mutex::new(barrier_map(barriers)),
            barrier_changed: Condvar::new(),
        });
        let answering = Arc::clone(&shared);
        let listener = http::Listener::start(Arc::new(
            move |request: http::Request, stream: &mut TcpStream| {
                answer(&answering, &request, stream);
            },
        ))?;
        Ok(Self {
            listener,
            shared,
            finished: false,
        })
    }

    /// `http://127.0.0.1:<port>`, with no path.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.listener.addr())
    }

    /// `http://127.0.0.1:<port>/v1`, the base an OpenAI-compatible client
    /// appends `/chat/completions` to.
    #[must_use]
    pub fn openai_base_url(&self) -> String {
        format!("{}/v1", self.base_url())
    }

    /// Every request so far, in arrival order.
    #[must_use]
    pub fn seen(&self) -> Vec<SeenCall> {
        self.shared.script.seen()
    }

    /// Blocks until a request is held at barrier `name`. No timeout: the
    /// test runner's slow-timeout ends a test that never gets there.
    ///
    /// # Panics
    /// No step holds at `name`.
    pub fn await_reached(&self, name: &str) {
        let mut barriers = lock(&self.shared.barriers);
        assert!(
            barriers.contains_key(name),
            "oneiron-testkit: no step holds at barrier {name:?}"
        );
        while !barriers.get(name).is_some_and(|barrier| barrier.reached) {
            barriers = self
                .shared
                .barrier_changed
                .wait(barriers)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Lets the request held at barrier `name` answer (now, or as soon as it
    /// arrives).
    ///
    /// # Panics
    /// No step holds at `name`.
    pub fn release(&self, name: &str) {
        let mut barriers = lock(&self.shared.barriers);
        let barrier = barriers.get_mut(name);
        assert!(
            barrier.is_some(),
            "oneiron-testkit: no step holds at barrier {name:?}"
        );
        if let Some(barrier) = barrier {
            barrier.released = true;
        }
        self.shared.barrier_changed.notify_all();
    }

    /// The violations so far, plus every step that answers once and was
    /// never requested.
    ///
    /// # Errors
    /// Any violation.
    pub fn check(&self) -> Result<(), ProviderMismatch> {
        self.shared.script.check()
    }

    /// Ends the script: returns every request it saw.
    ///
    /// # Panics
    /// On any violation (see [`Self::check`]).
    #[must_use]
    pub fn finish(mut self) -> Vec<SeenCall> {
        self.finished = true;
        if let Err(mismatch) = self.check() {
            panic!("{mismatch}");
        }
        self.seen()
    }
}

impl Drop for ScriptedProvider {
    fn drop(&mut self) {
        {
            let mut barriers = lock(&self.shared.barriers);
            for barrier in barriers.values_mut() {
                barrier.released = true;
            }
            self.shared.barrier_changed.notify_all();
        }
        if self.finished || std::thread::panicking() {
            return;
        }
        if let Err(mismatch) = self.check() {
            panic!("{mismatch}");
        }
    }
}

fn protocol_of(path: &str) -> Option<Protocol> {
    if path.ends_with("/chat/completions") {
        Some(Protocol::OpenAi)
    } else if path.ends_with("/messages") {
        Some(Protocol::Anthropic)
    } else {
        None
    }
}

fn answer(shared: &Shared, request: &http::Request, stream: &mut TcpStream) {
    let mut seen = SeenCall {
        step: None,
        method: request.method.clone(),
        path: request.path.clone(),
        digest: None,
        streamed: false,
        model: None,
        body: Value::Null,
    };
    if let Some(encoding) = &request.content_encoding {
        let violation = format!(
            "{} {} came {encoding}-encoded; the scripted provider reads plain bodies: set the provider's `request_compression = false`",
            request.method, request.path
        );
        shared.script.violate(violation.clone());
        shared.script.see(seen);
        let body = wire::error_body(Protocol::OpenAi, 415, &format!("oneiron-testkit: {violation}"));
        let _ = http::write_body(stream, 415, "application/json", body.to_string().as_bytes());
        return;
    }
    seen.body = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
    seen.model = seen.body.get("model").and_then(Value::as_str).map(str::to_owned);
    seen.streamed = seen.body.get("stream").and_then(Value::as_bool) == Some(true);
    let result = match (request.method.as_str(), protocol_of(&request.path)) {
        ("POST", Some(protocol)) => chat(shared, protocol, &mut seen, stream),
        ("POST", None) if request.path.ends_with("/embeddings") => {
            embeddings(shared, &seen, stream)
        }
        ("GET", None) if request.path.ends_with("/models") => models(shared, stream),
        _ => {
            shared.script.violate(format!(
                "unexpected request {} {}",
                request.method, request.path
            ));
            http::write_body(stream, 404, "text/plain", b"oneiron-testkit: no such route")
        }
    };
    shared.script.see(seen);
    if let Err(error) = result {
        eprintln!("oneiron-testkit ScriptedProvider: writing the answer failed: {error}");
    }
}

/// Refuses a call that broke the script with a 400: the engine reads it as
/// its own request's fault and does not retry it, so a script error stays
/// one loud failure, never a simulated outage.
fn refuse(stream: &mut TcpStream, protocol: Protocol, message: &str) -> io::Result<()> {
    let body = wire::error_body(protocol, 400, &format!("oneiron-testkit: {message}"));
    http::write_body(stream, 400, "application/json", body.to_string().as_bytes())
}

fn chat(
    shared: &Shared,
    protocol: Protocol,
    seen: &mut SeenCall,
    stream: &mut TcpStream,
) -> io::Result<()> {
    if seen.body.is_null() {
        shared
            .script
            .violate(format!("{} {}: the body is not JSON", seen.method, seen.path));
        return refuse(stream, protocol, "the request body is not JSON");
    }
    let body = seen.body.clone();
    let step = match shared.script.answer(seen, &body) {
        Ok(step) => step,
        Err(refusal) => return refuse(stream, protocol, &refusal),
    };
    if let Some(name) = &step.hold {
        let mut barriers = lock(&shared.barriers);
        if let Some(barrier) = barriers.get_mut(name) {
            barrier.reached = true;
        }
        shared.barrier_changed.notify_all();
        while !barriers.get(name).is_some_and(|barrier| barrier.released) {
            barriers = shared
                .barrier_changed
                .wait(barriers)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
    reply(&step, protocol, seen, stream)
}

fn reply(step: &Step, protocol: Protocol, seen: &SeenCall, stream: &mut TcpStream) -> io::Result<()> {
    let id = format!("testkit-{}", step.id);
    let model = step
        .model
        .clone()
        .or_else(|| seen.model.clone())
        .unwrap_or_else(|| "oneiron-testkit-model".to_owned());
    let deltas = match &step.reply {
        Reply::Text(text) => vec![text.clone()],
        Reply::Deltas(deltas) => deltas.clone(),
        Reply::Status(status) => {
            let body = wire::error_body(
                protocol,
                *status,
                &format!("oneiron-testkit: scripted status {status} for step {:?}", step.id),
            );
            return http::write_body(stream, *status, "application/json", body.to_string().as_bytes());
        }
        Reply::CutStream { deltas, after } => {
            let mut events = wire::opening_events(protocol, &id, &model, step.usage);
            let sent = &deltas[..(*after).min(deltas.len())];
            events.extend(wire::delta_events(protocol, &id, &model, sent));
            return http::write_events(stream, &events, true);
        }
        Reply::Json(body) => {
            return http::write_body(stream, 200, "application/json", body.to_string().as_bytes());
        }
        Reply::Events(events) => return http::write_events(stream, events, false),
        Reply::Body {
            status,
            content_type,
            body,
        } => return http::write_body(stream, *status, content_type, body),
    };
    if seen.streamed {
        let mut events = wire::opening_events(protocol, &id, &model, step.usage);
        events.extend(wire::delta_events(protocol, &id, &model, &deltas));
        events.extend(wire::closing_events(protocol, &id, &model, step.usage));
        http::write_events(stream, &events, false)
    } else {
        let body = wire::json_reply(protocol, &id, &model, &deltas.concat(), step.usage);
        http::write_body(stream, 200, "application/json", body.to_string().as_bytes())
    }
}

fn embeddings(shared: &Shared, seen: &SeenCall, stream: &mut TcpStream) -> io::Result<()> {
    let Some(embedder) = &shared.embedder else {
        shared.script.violate(format!(
            "{} {}: embeddings requested, but this provider serves none",
            seen.method, seen.path
        ));
        return refuse(stream, Protocol::OpenAi, "no embedder configured");
    };
    if let Some(model) = &seen.model {
        if model != embedder.model() {
            let mismatch = format!(
                "embeddings asked for model {model:?}; the hashing embedder is {:?}",
                embedder.model()
            );
            shared.script.violate(mismatch.clone());
            return refuse(stream, Protocol::OpenAi, &mismatch);
        }
    }
    let texts: Option<Vec<String>> = match seen.body.get("input") {
        Some(Value::String(text)) => Some(vec![text.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => None,
    };
    let Some(texts) = texts else {
        shared
            .script
            .violate("embeddings: `input` is not a string or an array of strings".to_owned());
        return refuse(stream, Protocol::OpenAi, "embeddings input must be text");
    };
    let vectors: Vec<Vec<f32>> = texts.iter().map(|text| embedder.embed_text(text)).collect();
    let words = texts
        .iter()
        .map(|text| text.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).count())
        .sum::<usize>();
    let body = wire::embeddings_reply(embedder.model(), &vectors, words as u64);
    http::write_body(stream, 200, "application/json", body.to_string().as_bytes())
}

fn models(shared: &Shared, stream: &mut TcpStream) -> io::Result<()> {
    let mut ids = shared.script.models();
    if let Some(embedder) = &shared.embedder {
        ids.push(embedder.model().to_owned());
    }
    ids.sort();
    ids.dedup();
    let body = json!({
        "object": "list",
        "data": ids
            .iter()
            .map(|id| json!({"id": id, "object": "model", "owned_by": "oneiron-testkit"}))
            .collect::<Vec<_>>()
    });
    http::write_body(stream, 200, "application/json", body.to_string().as_bytes())
}
