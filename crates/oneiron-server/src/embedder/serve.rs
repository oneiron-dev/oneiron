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
//! The wire is OpenAI's plus two optional fields, which the vault's endpoint
//! client sends once `/v1/models` marks the server as this one
//! (`oneiron_wire`): `input_type` (`query` or `document`) picks the prompt and
//! the pool's prompt rows as the local provider would, and `instruction` is a
//! vault's own `query_instruction`. That client then also leaves the input cap
//! to this server's tokenizer, as a local vault's is. A request without
//! `input_type` is a document request. One input runs at query priority and
//! more park for queries ([`super::local::Priority`]), whichever side they
//! embed: a recall sends one input and the fill worker sends batches. Every
//! answer names the transform that made it, which the vault's client holds to
//! the one it admitted from the listing.
//!
//! A request's bearer key is checked from its headers before any of its body
//! is read. A body is read only once the bytes it declares fit a budget,
//! which it holds until its request's work ends: small bodies (queries, a
//! vault's document batches) and large ones each have their own, so a recall
//! never waits behind an upload, and no number of callers can make the server
//! hold more than both.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use oneiron::embed::Embedder;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::local::model_manager::ModelManager;
use super::local::{Embedded, LocalEmbedder, Priority, Side};
use crate::config::{EmbedderConfig, EmbedderProvider};

/// Inputs one request may carry, as OpenAI caps them.
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
/// What larger bodies, and bodies of no declared length, may hold at once:
/// two of the largest.
const LARGE_BODIES_BYTES: usize = 2 * MAX_BODY_BYTES;
/// Bulk requests in flight at once. The model runs one forward at a time
/// anyway; two keep it busy while the next request is tokenised, and the rest
/// wait here rather than each holding a blocking thread a query may need.
const BULK_REQUESTS: usize = 2;
/// Query requests in flight at once, for the same reason.
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
    axum::serve(listener, router(embedder, listen.aliases, listen.key))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// The model the routes serve: the local provider, loaded once.
pub(super) trait ServedModel: Send + Sync + 'static {
    /// The space id, `org/name@revision`.
    fn model_id(&self) -> &str;
    fn dimensions(&self) -> usize;
    /// How it turns text into stored vectors.
    fn transform(&self) -> &str;
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
    /// Admission, held until the request's embedding work ends, not only its
    /// handler: a client that hangs up does not free a turn its work still
    /// takes.
    bulk: Arc<tokio::sync::Semaphore>,
    queries: Arc<tokio::sync::Semaphore>,
    /// The bytes request bodies may hold, by size ([`SMALL_BODY_BYTES`]), one
    /// permit a byte, taken before a body is read and held with admission.
    small_bodies: Arc<tokio::sync::Semaphore>,
    large_bodies: Arc<tokio::sync::Semaphore>,
}

impl Served {
    fn new(
        embedder: Arc<dyn ServedModel>,
        aliases: Vec<String>,
        key: Option<Zeroizing<String>>,
    ) -> Self {
        let mut names = vec![embedder.model_id().to_owned()];
        names.extend(aliases.into_iter().filter(|alias| !alias.is_empty()));
        Self {
            embedder,
            names,
            key,
            bulk: Arc::new(tokio::sync::Semaphore::new(BULK_REQUESTS)),
            queries: Arc::new(tokio::sync::Semaphore::new(QUERY_REQUESTS)),
            small_bodies: Arc::new(tokio::sync::Semaphore::new(SMALL_BODIES_BYTES)),
            large_bodies: Arc::new(tokio::sync::Semaphore::new(LARGE_BODIES_BYTES)),
        }
    }

    /// Body bytes held now: reserved for bodies being read, or kept by
    /// requests whose work has not ended.
    fn body_bytes_held(&self) -> usize {
        SMALL_BODIES_BYTES - self.small_bodies.available_permits() + LARGE_BODIES_BYTES
            - self.large_bodies.available_permits()
    }
}

/// The two routes, over one loaded model.
fn router(
    embedder: Arc<dyn ServedModel>,
    aliases: Vec<String>,
    key: Option<Zeroizing<String>>,
) -> Router {
    routes(Arc::new(Served::new(embedder, aliases, key)))
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
    /// the mark the vault's client reads.
    dimensions: usize,
    transform: String,
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
            transform: served.embedder.transform().to_owned(),
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
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Input {
    One(String),
    Many(Vec<String>),
}

#[derive(Serialize)]
struct EmbeddingsResponse {
    object: &'static str,
    data: Vec<EmbeddingRow>,
    model: String,
    usage: Usage,
    /// How these vectors were made: a vault holds every answer to the
    /// transform it admitted from the listing, so a server restarted with
    /// other settings is refused rather than mixed in.
    transform: String,
}

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

/// Reads a request's body once the bytes it may take fit its budget, which
/// the returned permit holds. A body of no declared length may take the most.
/// The key was checked before this ([`require_key`]).
async fn read_body(
    served: &Served,
    request: Request,
) -> Result<(tokio::sync::OwnedSemaphorePermit, axum::body::Bytes), Response> {
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let bytes = match declared {
        Some(declared) if declared > MAX_BODY_BYTES as u64 => {
            return Err(refuse(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request_error",
                &format!("a request body is at most {MAX_BODY_BYTES} bytes"),
            ));
        }
        Some(declared) => declared as usize,
        None => MAX_BODY_BYTES,
    };
    let budget = if bytes <= SMALL_BODY_BYTES {
        &served.small_bodies
    } else {
        &served.large_bodies
    };
    // Every size fits its budget, and both are far under `u32::MAX`.
    let Ok(held) = Arc::clone(budget).acquire_many_owned(bytes as u32).await else {
        return Err(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "the endpoint is shutting down",
        ));
    };
    axum::body::to_bytes(request.into_body(), bytes)
        .await
        .map(|body| (held, body))
        .map_err(|_| {
            refuse(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!(
                    "the body could not be read in full, within its declared length and \
                     {MAX_BODY_BYTES} bytes"
                ),
            )
        })
}

async fn embeddings(State(served): State<Arc<Served>>, request: Request) -> Response {
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
    if texts.is_empty() || texts.len() > MAX_INPUTS {
        return refuse(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!("a request carries 1 to {MAX_INPUTS} inputs"),
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
    let admitted = match priority {
        Priority::Query => Arc::clone(&served.queries).acquire_owned().await,
        Priority::Bulk => Arc::clone(&served.bulk).acquire_owned().await,
    };
    let Ok(admitted) = admitted else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "the endpoint is shutting down",
        );
    };
    let embedder = Arc::clone(&served.embedder);
    let instruction = request.instruction;
    let embedded = tokio::task::spawn_blocking(move || {
        let _held = (admitted, body_held);
        embedder.embed_raw(&texts, side, instruction.as_deref(), priority)
    })
    .await;
    let embedded = match embedded {
        Ok(Ok(embedded)) => embedded,
        Ok(Err(error)) => {
            tracing::warn!(?error, "endpoint embedding failed");
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the model could not embed this request",
            );
        }
        Err(error) => {
            tracing::warn!(?error, "endpoint embedding task failed");
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the model could not embed this request",
            );
        }
    };
    let data = embedded
        .rows
        .into_iter()
        .enumerate()
        .map(|(index, row)| EmbeddingRow {
            object: "embedding",
            index,
            embedding: if base64 {
                let bytes: Vec<u8> = row.iter().flat_map(|value| value.to_le_bytes()).collect();
                Encoded::Base64(base64::engine::general_purpose::STANDARD.encode(bytes))
            } else {
                Encoded::Float(row)
            },
        })
        .collect();
    axum::Json(EmbeddingsResponse {
        object: "list",
        data,
        model: request.model,
        usage: Usage {
            prompt_tokens: embedded.tokens,
            total_tokens: embedded.tokens,
        },
        transform: served.embedder.transform().to_owned(),
    })
    .into_response()
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
        return None;
    }
    Some(refuse(
        StatusCode::UNAUTHORIZED,
        "invalid_api_key",
        "this endpoint needs its bearer key",
    ))
}

/// An OpenAI-shaped error body. The message never echoes an input.
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
mod tests;
