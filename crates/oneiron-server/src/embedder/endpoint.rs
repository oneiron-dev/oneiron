//! The `endpoint` provider: any OpenAI-compatible `/v1/embeddings` server.
//!
//! One client shape for every host that speaks that wire — LM Studio, Ollama,
//! `llama-server`, a cloud. The server cannot see what the remote actually
//! loaded, so the configured artifact string is provenance it logs and never
//! verifies; the `model_id` it reports is the vault's space id, unchanged.
//!
//! One remote gets more: `oneiron-server embedder serve` marks its `/models`
//! rows, and to it this client sends what a local vault's provider would see —
//! whole texts, each marked query or document ([`Wire::Oneiron`]).

use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput};

use super::{EmbedderCommon, QueryEmbedder, engine_locality};
use crate::config::EmbedderConfig;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Characters per token used to turn the provider-agnostic `max_input_tokens`
/// into the character cap this provider can actually enforce. There is no
/// tokenizer on this side of the wire, and four is the ratio the 2026-09 bench
/// corpus measured (8,000 chars ≈ 2K tokens).
const CHARS_PER_TOKEN: usize = 4;
/// Probe string. Short, ASCII, and meaningless on purpose: it tells the server
/// the remote answers and how many components it returns, nothing else.
const PROBE_TEXT: &str = "oneiron embedder probe";
/// Tool name on every upstream failure this provider reports.
const EMBEDDER_TOOL: &str = "embedder-endpoint";

/// What a startup probe found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProbeOutcome {
    /// The remote answers and returns the configured number of components.
    Ready,
    /// The remote could not be reached. NOT fatal: writes land, the vault
    /// answers BM25, and the worker keeps probing (OF-022, two-tier write).
    Unreachable(String),
}

/// A probe failure that is a configuration error, not a transient one.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProbeError {
    #[error("embedder endpoint {endpoint} does not serve model {model_key}")]
    ModelKeyMissing { endpoint: String, model_key: String },
    #[error("embedder endpoint returned {got} components, configured dimensions is {expected}")]
    DimensionMismatch { expected: usize, got: usize },
}

#[derive(serde::Serialize)]
struct EmbeddingsRequest<'a> {
    model: &'a str,
    input: Vec<&'a str>,
    #[serde(flatten)]
    side: Side<'a>,
}

/// The fields beyond OpenAI's, sent only on [`Wire::Oneiron`].
#[derive(Clone, Copy, Default, serde::Serialize)]
struct Side<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    input_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction: Option<&'a str>,
}

/// What the remote reads beyond OpenAI's fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Wire {
    /// Any OpenAI-compatible server. A query carries the configured
    /// instruction in its text, and the input cap is approximated here in
    /// characters, there being no tokenizer on this side.
    OpenAi,
    /// `oneiron-server embedder serve`, running the local provider: inputs go
    /// whole, marked query or document, with any configured instruction
    /// beside a query, so its tokenizer caps them and its prompts apply as in
    /// a local vault.
    Oneiron,
}

#[derive(serde::Deserialize)]
struct EmbeddingsResponse {
    data: Vec<EmbeddingRow>,
}

#[derive(serde::Deserialize)]
struct EmbeddingRow {
    index: usize,
    embedding: Vec<f32>,
}

#[derive(serde::Deserialize)]
struct ModelsResponse {
    data: Vec<ModelRow>,
}

#[derive(serde::Deserialize)]
struct ModelRow {
    id: String,
    /// Set by `oneiron-server embedder serve`.
    #[serde(default)]
    oneiron_wire: Option<u32>,
}

pub(crate) struct HttpEmbedder {
    common: EmbedderCommon,
    endpoint: String,
    model_key: String,
    locality: EmbedderLocality,
    max_input_chars: usize,
    /// The vault's own query prompt, if it names one.
    query_instruction: Option<String>,
    /// Read from the remote's `/models` listing once, before the first
    /// request that depends on it.
    wire: OnceLock<Wire>,
    client: reqwest::blocking::Client,
    truncations: AtomicU64,
}

impl HttpEmbedder {
    pub(super) fn from_config(config: &EmbedderConfig) -> oneiron::Result<Arc<Self>> {
        let endpoint = config
            .endpoint
            .endpoint
            .as_deref()
            .ok_or_else(|| {
                oneiron::Error::InvalidConfig("embedder.endpoint is required".to_owned())
            })?
            .trim_end_matches('/')
            .to_owned();
        let model_key = config.endpoint.model_key.clone().ok_or_else(|| {
            oneiron::Error::InvalidConfig("embedder.model_key is required".to_owned())
        })?;
        let timeout = Duration::from_millis(config.endpoint.timeout_ms);
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|_| oneiron::Error::InvalidConfig("invalid embedder endpoint URL".into()))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(oneiron::Error::InvalidConfig(
                "embedder URL must not contain credentials or query secrets".into(),
            ));
        }
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if config.endpoint.locality == crate::config::EmbedderLocality::OnDevice && !loopback {
            return Err(oneiron::Error::InvalidConfig("on-device endpoints must be loopback; configure remote rung locality and egress for network endpoints".into()));
        }
        if !loopback && url.scheme() != "https" {
            return Err(oneiron::Error::InvalidConfig(
                "network embedder endpoints require HTTPS".into(),
            ));
        }
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(name) = &config.endpoint.api_key_env {
            let key = std::env::var(name).map_err(|_| {
                oneiron::Error::InvalidConfig("embedder key environment variable is missing".into())
            })?;
            let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
                .map_err(|_| {
                    oneiron::Error::InvalidConfig("invalid embedder authorization value".into())
                })?;
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
        // One attempt, no redirects, bounded body — the house transport shape.
        // The worker loop is the retry; a retry inside the client would hide a
        // dead remote behind a long stall and re-charge a metered one.
        let client = reqwest::blocking::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(timeout)
            .build()
            .map_err(|e| oneiron::Error::InvalidConfig(format!("embedder http client: {e}")))?;
        if let Some(artifact) = config.endpoint.artifact.as_deref() {
            tracing::info!(%endpoint, %model_key, artifact, "endpoint embedder configured");
        } else {
            tracing::info!(%endpoint, %model_key, "endpoint embedder configured");
        }
        Ok(Arc::new(Self {
            common: EmbedderCommon::from_config(config),
            endpoint,
            model_key,
            locality: engine_locality(config.endpoint.locality),
            max_input_chars: config.max_input_tokens.saturating_mul(CHARS_PER_TOKEN),
            query_instruction: config.query_instruction.clone(),
            wire: OnceLock::new(),
            client,
            truncations: AtomicU64::new(0),
        }))
    }

    /// Drops the tail of an over-long input at a character boundary.
    fn truncate(&self, text: String) -> String {
        if text.len() <= self.max_input_chars {
            return text;
        }
        let cut = text
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= self.max_input_chars)
            .last()
            .unwrap_or(0);
        self.truncations.fetch_add(1, Ordering::Relaxed);
        let mut text = text;
        text.truncate(cut);
        text
    }

    /// What the remote reads, from its `/models` listing. A listing that
    /// does not answer is an error and is asked again next time; one that
    /// answers without the mark, or not with a listing, is the OpenAI wire.
    fn wire(&self) -> oneiron::Result<Wire> {
        if let Some(wire) = self.wire.get() {
            return Ok(*wire);
        }
        let url = format!("{}/models", self.endpoint);
        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|e| transport_error("models listing", &e))?;
        let listed = if response.status().is_success() {
            bounded_body(response)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<ModelsResponse>(&bytes).ok())
        } else {
            None
        };
        let wire = listed.map_or(Wire::OpenAi, |listed| self.wire_of(&listed));
        Ok(*self.wire.get_or_init(|| wire))
    }

    fn wire_of(&self, listed: &ModelsResponse) -> Wire {
        let marked = listed.data.iter().any(|row| {
            row.id == self.model_key && row.oneiron_wire == Some(super::serve::ONEIRON_WIRE)
        });
        if marked { Wire::Oneiron } else { Wire::OpenAi }
    }

    fn post_embeddings(&self, texts: &[&str], side: Side<'_>) -> oneiron::Result<Vec<Vec<f32>>> {
        let url = format!("{}/embeddings", self.endpoint);
        let body = EmbeddingsRequest {
            model: &self.model_key,
            input: texts.to_vec(),
            side,
        };
        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| transport_error("embeddings request", &e))?;
        let status = response.status();
        if !status.is_success() {
            return Err(oneiron::Error::UpstreamToolFailure {
                tool: EMBEDDER_TOOL,
                code: format!("embedder endpoint returned HTTP {status}"),
            });
        }
        let parsed: EmbeddingsResponse =
            serde_json::from_slice(&bounded_body(response)?).map_err(|e| {
                oneiron::Error::UpstreamToolFailure {
                    tool: EMBEDDER_TOOL,
                    code: format!("embeddings response: {e}"),
                }
            })?;
        self.order_rows(parsed.data, texts.len())
    }

    /// Re-orders `data` by the index each row reports.
    ///
    /// The wire does not promise request order, and a silently mis-ordered
    /// batch would attach every vector to the wrong entity.
    fn order_rows(
        &self,
        rows: Vec<EmbeddingRow>,
        expected: usize,
    ) -> oneiron::Result<Vec<Vec<f32>>> {
        if rows.len() != expected {
            return Err(oneiron::Error::UpstreamToolFailure {
                tool: EMBEDDER_TOOL,
                code: format!(
                    "embedder endpoint returned {} rows for {expected} inputs",
                    rows.len()
                ),
            });
        }
        let mut ordered: Vec<Option<Vec<f32>>> = vec![None; expected];
        for row in rows {
            let slot =
                ordered
                    .get_mut(row.index)
                    .ok_or_else(|| oneiron::Error::UpstreamToolFailure {
                        tool: EMBEDDER_TOOL,
                        code: format!(
                            "embedder endpoint returned index {} for {expected} inputs",
                            row.index
                        ),
                    })?;
            if slot.is_some() {
                return Err(oneiron::Error::UpstreamToolFailure {
                    tool: EMBEDDER_TOOL,
                    code: format!("embedder endpoint repeated index {}", row.index),
                });
            }
            *slot = Some(row.embedding);
        }
        ordered
            .into_iter()
            .map(|row| {
                let row = row.ok_or(oneiron::Error::InvariantViolation(
                    "embedder endpoint left an input unanswered",
                ))?;
                self.common.finish_vector(row)
            })
            .collect()
    }
}

fn transport_error(what: &str, error: &reqwest::Error) -> oneiron::Error {
    // The message carries the failure class, never the response body: a remote
    // that echoes the input back in an error must not put vault text into this
    // server's logs.
    let class = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_decode() {
        "decode failed"
    } else {
        "failed"
    };
    oneiron::Error::UpstreamToolFailure {
        tool: EMBEDDER_TOOL,
        code: format!("embedder {what} {class}"),
    }
}

fn bounded_body(response: reqwest::blocking::Response) -> oneiron::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Err(oneiron::Error::UpstreamToolFailure {
            tool: EMBEDDER_TOOL,
            code: "embedder endpoint response exceeds the body cap".to_owned(),
        });
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| oneiron::Error::UpstreamToolFailure {
            tool: EMBEDDER_TOOL,
            code: format!("embedder response read: {e}"),
        })?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(oneiron::Error::UpstreamToolFailure {
            tool: EMBEDDER_TOOL,
            code: "embedder endpoint response exceeds the body cap".to_owned(),
        });
    }
    Ok(bytes)
}

impl Embedder for HttpEmbedder {
    fn model_id(&self) -> &str {
        &self.common.model_id
    }

    fn dimensions(&self) -> usize {
        self.common.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let wire = self.wire()?;
        let texts: Vec<String> = inputs
            .iter()
            .map(|input| {
                self.common.document_text(input).map(|text| match wire {
                    Wire::OpenAi => self.truncate(text),
                    Wire::Oneiron => text,
                })
            })
            .collect::<oneiron::Result<_>>()?;
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let side = match wire {
            Wire::OpenAi => Side::default(),
            Wire::Oneiron => Side {
                input_type: Some("document"),
                instruction: None,
            },
        };
        self.post_embeddings(&refs, side)
    }
}

impl QueryEmbedder for HttpEmbedder {
    fn truncations(&self) -> u64 {
        self.truncations.load(Ordering::Relaxed)
    }

    fn as_endpoint(&self) -> Option<&Self> {
        Some(self)
    }

    fn embed_query(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        let mut vectors = match self.wire()? {
            Wire::OpenAi => {
                let prefixed = self.truncate(self.common.query_text(text));
                self.post_embeddings(&[prefixed.as_str()], Side::default())?
            }
            Wire::Oneiron => self.post_embeddings(
                &[text],
                Side {
                    input_type: Some("query"),
                    instruction: self.query_instruction.as_deref(),
                },
            )?,
        };
        vectors.pop().ok_or(oneiron::Error::InvariantViolation(
            "embedder endpoint answered a single query with no row",
        ))
    }
}

/// Startup probe: the remote must list the configured model and return the
/// configured number of components.
///
/// A reachable remote that serves a different model or a different width is a
/// configuration error and stops `serve` — filling a vault from it would
/// silently mix two spaces. An unreachable remote is not: the vault opens at
/// rung 0 and the worker keeps trying.
pub(crate) fn probe_endpoint(embedder: &HttpEmbedder) -> Result<ProbeOutcome, ProbeError> {
    let url = format!("{}/models", embedder.endpoint);
    let listed = match embedder.client.get(&url).send() {
        Ok(response) if response.status().is_success() => bounded_body(response)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ModelsResponse>(&bytes).ok()),
        Ok(response) => {
            return Ok(ProbeOutcome::Unreachable(format!(
                "GET {url} returned HTTP {}",
                response.status()
            )));
        }
        Err(error) => {
            return Ok(ProbeOutcome::Unreachable(
                transport_error("models probe", &error).to_string(),
            ));
        }
    };
    // A remote that answers but cannot be parsed is treated as reachable with
    // an unknown catalog: some servers omit `/models` entirely, and refusing
    // to start over a missing listing would be stricter than the contract.
    if let Some(listed) = &listed
        && !listed.data.iter().any(|row| row.id == embedder.model_key)
    {
        return Err(ProbeError::ModelKeyMissing {
            endpoint: embedder.endpoint.clone(),
            model_key: embedder.model_key.clone(),
        });
    }
    let _ = embedder
        .wire
        .set(listed.map_or(Wire::OpenAi, |listed| embedder.wire_of(&listed)));
    match embedder.post_embeddings(&[PROBE_TEXT], Side::default()) {
        Ok(vectors) => {
            let got = vectors.first().map_or(0, Vec::len);
            if got == embedder.common.dimensions {
                Ok(ProbeOutcome::Ready)
            } else {
                Err(ProbeError::DimensionMismatch {
                    expected: embedder.common.dimensions,
                    got,
                })
            }
        }
        // `finish_vector` refuses a wrong width before this point, so a
        // dimension mismatch arrives as an error rather than a short vector.
        Err(oneiron::Error::DimensionMismatch { expected, got }) => {
            Err(ProbeError::DimensionMismatch { expected, got })
        }
        Err(error) => Ok(ProbeOutcome::Unreachable(error.to_string())),
    }
}
