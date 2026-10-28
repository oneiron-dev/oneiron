//! `oneiron-server embedder serve`: the local provider over an
//! OpenAI-compatible `/v1/embeddings`, for several vaults to share.
//!
//! One model in one process, on whichever host should carry it — a GPU box,
//! or the one machine that should hold the gigabyte — and every vault on the
//! `endpoint` provider pointed at it. The vectors are the local provider's: the
//! same verified files, tokenizer, prompts, pooling and module chain, run by
//! the same code.
//!
//! A response carries each input's module-chain output before the numerics
//! contract, which is what sentence-transformers' `encode` returns for the
//! model. The vault's endpoint client then normalises and rounds through f16
//! exactly as the local provider does, so an endpoint vault stores the very
//! vectors a local vault would rather than a rounding of them.
//!
//! The wire is OpenAI's plus three optional fields, which the vault's endpoint
//! client sends once `/v1/models` marks the server as this one
//! (`oneiron_wire`): `input_type` (`query` or `document`) picks the prompt and
//! the pool's prompt rows as the local provider would, `instruction` is a
//! vault's own `query_instruction`, and `error_member` asks that a streamed
//! answer a later batch cannot complete end with an `error` member rather
//! than broken ([`batches`]). That client then also leaves the input cap
//! to this server's tokenizer, as a local vault's is. A request without
//! `input_type` is a document request. One input runs at query priority and
//! more park for queries ([`super::local::Priority`]), whichever side they
//! embed: a recall sends one input and the fill worker sends batches. Every
//! listing row, an alias's too, and every answer names the model loaded, the
//! transform that makes its vectors and the profile it runs with, which the
//! vault's client holds to the listing it admitted: a restart with another
//! model behind the same name is refused like one with other settings. The
//! profile also decides whether the vault takes the model's measured evidence
//! floors. Every answer also names the device and runtime that computed it,
//! which the vault marks each of its vectors with (ARCH-0036), so a vault on a
//! shared endpoint still tells a CPU's vectors from a GPU's.
//!
//! A request's bearer key is checked from its headers before any of its body
//! is read. A body must declare its length, and is read only once that fits a
//! budget, which it holds until its request's work ends: small bodies
//! (queries, a vault's document batches) and large ones each have their own,
//! so a recall never waits behind an upload. Any number of inputs is
//! embedded in batches of [`MAX_INPUTS`] ([`batches`]): each batch takes room
//! for its rows and their encoding in the `embedder_answer_bytes` row of
//! `[limits]` before the model makes it, and keeps it until its rows are
//! handed on; the endpoint does not start when the row cannot hold its
//! model's largest batch. Past the `embedder_requests` row, past a full budget or answer
//! row, and past the few requests the model works on at once, a request with
//! the key waits its turn in order, each wait up to the queue deadline; it is
//! never refused for how many wait (the owner's rate law, ARCH-0044 C5).
//! Crossing a row or a budget asks whether everything is okay (OF-520). A
//! body that does not arrive in time gives its budget back, and an answer its
//! reader stops taking gives its room back at the idle limit, so however many
//! callers wait, the server holds little more than the budgets and the
//! answer row.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use oneiron::embed::{Embedder, EmbeddingProvenance};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::local::evidence::RunProfile;
use super::local::model_manager::ModelManager;
use super::local::{Embedded, LocalEmbedder, Priority, Side};
use crate::admission::Admission;
use crate::byte_line::{ByteLine, HeldBytes};
use crate::config::{EmbedderConfig, EmbedderProvider};
use crate::wire_telemetry::{LimitQuestions, LimitRow};

mod batches;
mod budget;
use budget::answer_bytes;
#[cfg(test)]
use budget::encoding_bytes;

/// Inputs the model embeds as one batch, as OpenAI caps one request: a
/// request with more is embedded batch by batch, never refused for its count
/// ([`batches`], FIX 9487).
const MAX_INPUTS: usize = 2_048;
/// Request bodies above this are refused before they are read.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
/// A body of at most this many bytes draws on [`SMALL_BODIES_BYTES`]: a
/// recall's query, or a vault's batch of documents (its client sends at most
/// 32 KiB of text a request).
const SMALL_BODY_BYTES: usize = 256 * 1024;
/// What small bodies may hold at once, read or being read, until their
/// requests' work ends. Their own budget, so a query never waits behind a
/// large upload.
const SMALL_BODIES_BYTES: usize = 16 * 1024 * 1024;
/// What larger bodies may hold at once: two of the largest.
const LARGE_BODIES_BYTES: usize = 2 * MAX_BODY_BYTES;
/// The pieces an answer streams out in, each copied, so what the transport
/// holds of an answer is a few pieces, never the whole of it.
const ANSWER_PIECE: usize = 64 * 1024;
/// How long a body has to arrive once its bytes are reserved. One that is
/// still arriving then is refused, and its reservation returned: a stalled
/// upload holds a budget for this long at most.
const BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// Bulk requests the model works on at once. It runs one forward at a time
/// anyway; two keep it busy while the next request is tokenised, and the rest
/// wait their turn rather than each holding a blocking thread a query may
/// need. This is the model's scheduling, not a row: the row is
/// `embedder_requests`.
const BULK_REQUESTS: usize = 2;
/// Query requests the model works on at once, for the same reason.
const QUERY_REQUESTS: usize = 64;
/// The longest query instruction a request may carry. A vault's is a line;
/// each input is embedded behind its own copy, so the cap is what bounds a
/// request's prompted text.
const MAX_INSTRUCTION_BYTES: usize = 4 * 1024;
/// The version of the two fields beyond OpenAI's that this server reads,
/// advertised on every `/v1/models` row.
pub(crate) const ONEIRON_WIRE: u32 = 1;

/// Where to listen, and who may ask.
pub(crate) struct Listen {
    pub(crate) addr: SocketAddr,
    /// The bearer key every request must carry, if any.
    pub(crate) key: Option<Zeroizing<String>>,
    /// Names a request's `model` may give besides the space id.
    pub(crate) aliases: Vec<String>,
    /// The `[limits]` the endpoint serves under.
    pub(crate) limits: crate::config::LimitsConfig,
}

/// Loads the configured local model and serves it until interrupted.
pub(crate) async fn run(config: EmbedderConfig, listen: Listen) -> anyhow::Result<()> {
    if config.provider != EmbedderProvider::Local {
        anyhow::bail!(
            "embedder serve runs the local provider; the configured provider is not local"
        );
    }
    if !listen.addr.ip().is_loopback() && listen.key.is_none() {
        anyhow::bail!(
            "embedder serve on a non-loopback address needs --api-key-env: anyone who can reach it could spend this host's model"
        );
    }
    let embedder: Arc<dyn ServedModel> =
        tokio::task::spawn_blocking(move || LocalEmbedder::load(&config, &ModelManager::default()))
            .await??;
    let listener = tokio::net::TcpListener::bind(listen.addr).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        model_id = embedder.model_id(),
        dimensions = embedder.dimensions(),
        auth = listen.key.is_some(),
        "embedder endpoint serving /v1/embeddings"
    );
    let served = Arc::new(Served::new(
        embedder,
        listen.aliases,
        listen.key,
        &listen.limits,
    )?);
    let questions = Arc::clone(&served.questions);
    crate::http_listener::serve(
        listener,
        routes(served),
        listen.limits.connections(),
        questions,
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
    )
    .await;
    Ok(())
}

/// The model the routes serve: the local provider, loaded once.
pub(super) trait ServedModel: Send + Sync + 'static {
    /// The space id, `org/name@revision`.
    fn model_id(&self) -> &str;
    fn dimensions(&self) -> usize;
    /// How it turns text into stored vectors.
    fn transform(&self) -> &str;
    /// The settings it runs with that a vault's evidence floors depend on.
    fn profile(&self) -> &RunProfile;
    /// The device and runtime it computes on.
    fn provenance(&self) -> EmbeddingProvenance;
    /// Each text's module-chain output, in input order.
    fn embed_raw(
        &self,
        texts: &[String],
        side: Side,
        instruction: Option<&str>,
        priority: Priority,
    ) -> oneiron::Result<Embedded>;
}

impl ServedModel for LocalEmbedder {
    fn model_id(&self) -> &str {
        Embedder::model_id(self)
    }

    fn dimensions(&self) -> usize {
        Embedder::dimensions(self)
    }

    fn transform(&self) -> &str {
        LocalEmbedder::transform(self)
    }

    fn profile(&self) -> &RunProfile {
        LocalEmbedder::profile(self)
    }

    fn provenance(&self) -> EmbeddingProvenance {
        Embedder::provenance(self)
    }

    fn embed_raw(
        &self,
        texts: &[String],
        side: Side,
        instruction: Option<&str>,
        priority: Priority,
    ) -> oneiron::Result<Embedded> {
        LocalEmbedder::embed_raw(self, texts, side, instruction, priority)
    }
}

struct Served {
    embedder: Arc<dyn ServedModel>,
    /// The space id first, then the aliases.
    names: Vec<String>,
    key: Option<Zeroizing<String>>,
    /// Requests held at once, from the key check until the request's
    /// embedding work ends: the `embedder_requests` row. Past it a request
    /// waits its turn.
    requests: Admission<()>,
    /// The model's turns, held until the request's embedding work ends, not
    /// only its handler: a client that hangs up does not free a turn its work
    /// still takes. Past them a request waits in order, up to `wait`.
    bulk: Arc<tokio::sync::Semaphore>,
    queries: Arc<tokio::sync::Semaphore>,
    /// The bytes request bodies may hold, by size ([`SMALL_BODY_BYTES`]).
    small_bodies: ByteLine,
    large_bodies: ByteLine,
    /// Room answers hold until they are delivered (`embedder_answer_bytes`).
    answers: ByteLine,
    /// Where crossed rows ask, the listener's descriptor floor's too. No
    /// vault keeps them here; each is logged.
    questions: Arc<LimitQuestions>,
    /// How long a request waits for its turn before it is told to retry,
    /// nothing started.
    wait: Duration,
    /// How long an answer waits for its client to read the next piece.
    idle: Duration,
}

impl Served {
    /// Fails when the answer row cannot hold the model's largest answer:
    /// such an answer would never fit, and a smaller claim would not bound
    /// what it holds.
    fn new(
        embedder: Arc<dyn ServedModel>,
        aliases: Vec<String>,
        key: Option<Zeroizing<String>>,
        limits: &crate::config::LimitsConfig,
    ) -> anyhow::Result<Self> {
        let largest = answer_bytes(MAX_INPUTS, embedder.dimensions());
        let answers = usize::try_from(limits.embedder_answer_bytes).unwrap_or(usize::MAX);
        if answers < largest {
            anyhow::bail!(
                "limits.embedder_answer_bytes is {answers}, under the {largest} bytes one answer of {MAX_INPUTS} inputs at {} dimensions holds; raise it",
                embedder.dimensions()
            );
        }
        let mut names = vec![embedder.model_id().to_owned()];
        names.extend(aliases.into_iter().filter(|alias| !alias.is_empty()));
        let questions = Arc::new(LimitQuestions::default());
        let wait = limits.queue_wait();
        Ok(Self {
            embedder,
            names,
            key,
            requests: Admission::new(
                LimitRow::EmbedderRequests,
                Arc::clone(&questions),
                limits.embedder_requests,
                wait,
            ),
            bulk: Arc::new(tokio::sync::Semaphore::new(BULK_REQUESTS)),
            queries: Arc::new(tokio::sync::Semaphore::new(QUERY_REQUESTS)),
            small_bodies: ByteLine::new(LimitRow::EmbedderBodyBytes, SMALL_BODIES_BYTES),
            large_bodies: ByteLine::new(LimitRow::EmbedderBodyBytes, LARGE_BODIES_BYTES),
            answers: ByteLine::new(LimitRow::EmbedderAnswerBytes, answers),
            questions,
            wait,
            idle: Duration::from_millis(limits.transfer_idle_timeout_ms),
        })
    }

    /// Body bytes held now: reserved for bodies being read, or kept by
    /// requests whose work has not ended.
    #[cfg(test)]
    fn body_bytes_held(&self) -> usize {
        self.small_bodies.held_bytes() + self.large_bodies.held_bytes()
    }
}

/// The two routes, over one loaded model.
#[cfg(test)]
fn router(
    embedder: Arc<dyn ServedModel>,
    aliases: Vec<String>,
    key: Option<Zeroizing<String>>,
) -> Router {
    routes(Arc::new(
        Served::new(
            embedder,
            aliases,
            key,
            &crate::config::LimitsConfig::default(),
        )
        .expect("the default answer row holds a test model's answers"),
    ))
}

/// Every request's key is checked from its headers first, before any route
/// reads a byte of its body.
fn routes(served: Arc<Served>) -> Router {
    Router::new()
        .route("/v1/models", get(models))
        .route("/v1/embeddings", post(embeddings))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&served),
            require_key,
        ))
        .with_state(served)
}

async fn require_key(State(served): State<Arc<Served>>, request: Request, next: Next) -> Response {
    match unauthorised(&served, request.headers()) {
        Some(refused) => refused,
        None => next.run(request).await,
    }
}

#[derive(Serialize)]
struct ModelList {
    object: &'static str,
    data: Vec<ModelRow>,
}

#[derive(Serialize)]
struct ModelRow {
    id: String,
    object: &'static str,
    created: u64,
    owned_by: &'static str,
    /// Beyond OpenAI's fields: what an operator checks a vault against, and
    /// the mark the vault's client reads. `model_id` is the model loaded,
    /// on an alias's row as on its own: a vault holds an alias to it. The
    /// profile decides whether the vault takes the model's measured
    /// evidence floors.
    dimensions: usize,
    model_id: String,
    transform: String,
    profile: RunProfile,
    oneiron_wire: u32,
}

async fn models(State(served): State<Arc<Served>>) -> Response {
    let data = served
        .names
        .iter()
        .map(|name| ModelRow {
            id: name.clone(),
            object: "model",
            created: 0,
            owned_by: "oneiron",
            dimensions: served.embedder.dimensions(),
            model_id: served.embedder.model_id().to_owned(),
            transform: served.embedder.transform().to_owned(),
            profile: served.embedder.profile().clone(),
            oneiron_wire: ONEIRON_WIRE,
        })
        .collect();
    axum::Json(ModelList {
        object: "list",
        data,
    })
    .into_response()
}

#[derive(Deserialize)]
struct EmbeddingsRequest {
    model: String,
    input: Input,
    #[serde(default)]
    encoding_format: Option<String>,
    #[serde(default)]
    dimensions: Option<usize>,
    #[serde(default)]
    input_type: Option<String>,
    #[serde(default)]
    instruction: Option<String>,
    /// The client reads the `error` member that ends a streamed answer a
    /// later batch could not complete (FIX 10702); without it such an answer
    /// ends broken.
    #[serde(default)]
    error_member: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Input {
    One(String),
    Many(Vec<String>),
}

/// One row of an answer's `data`. The answer around the rows also names the
/// model loaded, whichever name the request gave, how these vectors were
/// made and how it runs, which a vault holds every answer to, and the device
/// and runtime that computed them, which the vault marks them with
/// ([`batches`]).
#[derive(Serialize)]
struct EmbeddingRow {
    object: &'static str,
    index: usize,
    embedding: Encoded,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Encoded {
    Float(Vec<f32>),
    /// Little-endian f32 bytes, base64: the exact values, a quarter the size.
    Base64(String),
}

#[derive(Serialize)]
struct Usage {
    prompt_tokens: usize,
    total_tokens: usize,
}

/// Reads a request's body once the bytes it declares fit its budget, which
/// the returned permit holds. A body must declare its length: what it may
/// take is known before any of it is read, and a short one never waits on
/// the large budget. The key was checked before this ([`require_key`]).
async fn read_body(
    served: &Served,
    request: Request,
) -> Result<(HeldBytes, axum::body::Bytes), Response> {
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let bytes = match declared {
        None => {
            return Err(refuse(
                StatusCode::LENGTH_REQUIRED,
                "invalid_request_error",
                "a request body must declare its Content-Length",
            ));
        }
        Some(declared) if declared > MAX_BODY_BYTES as u64 => {
            return Err(refuse(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request_error",
                &format!("a request body is at most {MAX_BODY_BYTES} bytes"),
            ));
        }
        Some(declared) => declared as usize,
    };
    let budget = if bytes <= SMALL_BODY_BYTES {
        &served.small_bodies
    } else {
        &served.large_bodies
    };
    let Some(held) = budget.reserve(bytes, served.wait, &served.questions).await else {
        return Err(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "the request waited past its deadline for room for its body; nothing was read; retry",
        ));
    };
    match tokio::time::timeout(
        BODY_READ_TIMEOUT,
        axum::body::to_bytes(request.into_body(), bytes),
    )
    .await
    {
        Ok(Ok(body)) => Ok((held, body)),
        Ok(Err(_)) => Err(refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "the body ended before its declared length",
        )),
        Err(_) => Err(refuse(
            StatusCode::REQUEST_TIMEOUT,
            "invalid_request_error",
            &format!(
                "the body did not arrive within {} s",
                BODY_READ_TIMEOUT.as_secs()
            ),
        )),
    }
}

async fn embeddings(State(served): State<Arc<Served>>, request: Request) -> Response {
    let Ok(held) = served.requests.admit(()).await else {
        return waited_out();
    };
    let (body_held, body) = match read_body(&served, request).await {
        Ok(read) => read,
        Err(refused) => return refused,
    };
    let request: EmbeddingsRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "the body is not an embeddings request: a model, and an input that is a string or an array of strings",
            );
        }
    };
    // The parsed request owns its texts; the bytes go before admission.
    drop(body);
    if !served.names.contains(&request.model) {
        return refuse(
            StatusCode::NOT_FOUND,
            "model_not_found",
            &format!("this endpoint serves {}", served.names.join(", ")),
        );
    }
    let base64 = match request.encoding_format.as_deref() {
        None | Some("float") => false,
        Some("base64") => true,
        Some(other) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("encoding_format {other:?} is not float or base64"),
            );
        }
    };
    if let Some(asked) = request.dimensions
        && asked != served.embedder.dimensions()
    {
        return refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!(
                "this model embeds at {} dimensions, not {asked}",
                served.embedder.dimensions()
            ),
        );
    }
    let texts = match request.input {
        Input::One(text) => vec![text],
        Input::Many(texts) => texts,
    };
    // Any number of inputs is owed its answer, embedded a batch at a time
    // ([`batches`], FIX 9487).
    if texts.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "a request carries at least 1 input",
        );
    }
    if let Some(index) = texts
        .iter()
        .position(|text| text.chars().all(|c| c.is_whitespace() || c.is_control()))
    {
        return refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!("input {index} has no text to embed"),
        );
    }
    let (side, priority) = match (request.input_type.as_deref(), texts.len()) {
        (Some("query"), 1) => (Side::Query, Priority::Query),
        (Some("query"), _) => (Side::Query, Priority::Bulk),
        (Some("document" | "passage"), _) | (None, 2..) => (Side::Document, Priority::Bulk),
        (None, _) => (Side::Document, Priority::Query),
        (Some(other), _) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("input_type {other:?} is not query or document"),
            );
        }
    };
    if request.instruction.is_some() && side != Side::Query {
        return refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "instruction goes with input_type query",
        );
    }
    if request
        .instruction
        .as_ref()
        .is_some_and(|instruction| instruction.len() > MAX_INSTRUCTION_BYTES)
    {
        return refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!("an instruction is at most {MAX_INSTRUCTION_BYTES} bytes"),
        );
    }
    let work = batches::EmbeddingRequestWork {
        texts,
        side,
        instruction: request.instruction,
        priority,
        base64,
        model: request.model,
        error_member: request.error_member,
    };
    batches::stream_embedding_rows(Arc::clone(&served), work, (held, body_held)).await
}

/// The refusal for a request without the configured bearer key; `None` when
/// no key is configured or the request carries it.
fn unauthorised(served: &Served, headers: &HeaderMap) -> Option<Response> {
    let key = served.key.as_ref()?;
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if bool::from(presented.as_bytes().ct_eq(key.as_bytes())) {
        crate::http_listener::authenticated();
        return None;
    }
    Some(refuse(
        StatusCode::UNAUTHORIZED,
        "invalid_api_key",
        "this endpoint needs its bearer key",
    ))
}

/// An OpenAI-shaped error body. The message never echoes an input.
/// A wait for a turn reached the queue deadline.
fn waited_out() -> Response {
    refuse(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "the request waited past its deadline for its turn; nothing was started; retry",
    )
}

fn refuse(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({
            "error": {
                "message": message,
                "type": if status.is_server_error() { "server_error" } else { "invalid_request_error" },
                "param": null,
                "code": code,
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
pub(crate) mod tests;
