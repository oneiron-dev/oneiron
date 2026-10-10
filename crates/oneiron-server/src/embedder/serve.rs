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
//! `input_type` is a document request; one input runs at query priority and
//! more park for queries ([`super::local::Priority`]), since a recall sends one
//! input and the fill worker sends batches.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use oneiron::embed::Embedder;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::local::model_manager::ModelManager;
use super::local::{LocalEmbedder, Priority, Side};
use crate::config::{EmbedderConfig, EmbedderProvider};

/// Inputs one request may carry, as OpenAI caps them.
const MAX_INPUTS: usize = 2_048;
/// Request bodies above this are refused before they are parsed.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
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
    let embedder =
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

struct Served {
    embedder: Arc<LocalEmbedder>,
    /// The space id first, then the aliases.
    names: Vec<String>,
    key: Option<Zeroizing<String>>,
}

/// The two routes, over one loaded model.
pub(crate) fn router(
    embedder: Arc<LocalEmbedder>,
    aliases: Vec<String>,
    key: Option<Zeroizing<String>>,
) -> Router {
    let mut names = vec![embedder.model_id().to_owned()];
    names.extend(aliases.into_iter().filter(|alias| !alias.is_empty()));
    Router::new()
        .route("/v1/models", get(models))
        .route("/v1/embeddings", post(embeddings))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(Arc::new(Served {
            embedder,
            names,
            key,
        }))
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

async fn models(State(served): State<Arc<Served>>, headers: HeaderMap) -> Response {
    if let Some(refused) = unauthorised(&served, &headers) {
        return refused;
    }
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

async fn embeddings(
    State(served): State<Arc<Served>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refused) = unauthorised(&served, &headers) {
        return refused;
    }
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
        (Some("query"), _) => (Side::Query, Priority::Query),
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
    let embedder = Arc::clone(&served.embedder);
    let instruction = request.instruction;
    let embedded = tokio::task::spawn_blocking(move || {
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
mod tests {
    use oneiron::embed::PendingEmbeddingInput;

    use super::super::endpoint::{HttpEmbedder, ProbeOutcome, probe_endpoint};
    use super::super::local::bench::{
        cpu_config, document, synthetic_documents, synthetic_queries,
    };
    use super::*;
    use crate::config::EndpointEmbedderConfig;
    use crate::embedder::QueryEmbedder;

    /// The check the shared endpoint exists for: a vault on the `endpoint`
    /// provider pointed at it stores the vectors a vault on the `local`
    /// provider makes, to the bit, and embeds queries the same way, with and
    /// without a vault-side query instruction. One document is longer than
    /// the input cap, which the server's tokenizer must cut where a local
    /// vault's does. Both sides run the same loaded model, so any difference
    /// is the wire's or the request path's.
    #[test]
    #[ignore = "needs the 2.38 GB pplx-embed-v1 checkpoint; run with --run-ignored=all"]
    fn an_endpoint_vault_stores_the_vectors_a_local_vault_makes() {
        let local_config = cpu_config();
        let local = LocalEmbedder::load(&local_config, &ModelManager::default()).expect("loads");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("bound");
        let addr = listener.local_addr().expect("address");
        let app = router(Arc::clone(&local), vec!["pplx".to_owned()], None);
        std::thread::spawn(move || {
            runtime.block_on(async move { axum::serve(listener, app).await })
        });
        let endpoint_vault = |query_instruction: Option<&str>| {
            HttpEmbedder::from_config(&EmbedderConfig {
                provider: EmbedderProvider::Endpoint,
                query_instruction: query_instruction.map(str::to_owned),
                endpoint: EndpointEmbedderConfig {
                    endpoint: Some(format!("http://{addr}/v1")),
                    model_key: Some(local_config.model_id.clone()),
                    ..EndpointEmbedderConfig::default()
                },
                ..local_config.clone()
            })
            .expect("client")
        };
        let remote = endpoint_vault(None);
        assert_eq!(probe_endpoint(&remote), Ok(ProbeOutcome::Ready));
        let bits = |vector: &[f32]| vector.iter().map(|v| v.to_bits()).collect::<Vec<_>>();

        let mut texts = synthetic_documents(48, 21);
        texts.push(texts[0].clone());
        let long = texts.join(" ");
        assert!(
            long.len() > 4 * local_config.max_input_tokens,
            "past the input cap"
        );
        texts.push(long);
        let inputs: Vec<PendingEmbeddingInput> = texts.iter().map(|text| document(text)).collect();
        let stored_locally = local.embed(&inputs).expect("local");
        let stored_remotely = remote.embed(&inputs).expect("remote");
        let differing = stored_locally
            .iter()
            .zip(&stored_remotely)
            .filter(|(a, b)| bits(a) != bits(b))
            .count();
        assert_eq!(differing, 0, "documents whose stored vector differs");

        let instructed_config = EmbedderConfig {
            query_instruction: Some("query: ".to_owned()),
            ..local_config.clone()
        };
        let instructed_local =
            LocalEmbedder::load(&instructed_config, &ModelManager::default()).expect("loads");
        let instructed_remote = endpoint_vault(Some("query: "));
        for query in synthetic_queries(12, 22) {
            assert_eq!(
                bits(&local.embed_query(&query).expect("local query")),
                bits(&remote.embed_query(&query).expect("remote query")),
                "a query vector differs"
            );
            assert_eq!(
                bits(&instructed_local.embed_query(&query).expect("local query")),
                bits(&instructed_remote.embed_query(&query).expect("remote query")),
                "an instructed query vector differs"
            );
        }
        println!(
            "{} documents and 24 queries equal to the bit over the wire",
            texts.len()
        );
    }
}
