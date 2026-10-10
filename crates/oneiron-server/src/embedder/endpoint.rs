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
use std::sync::{Arc, Mutex, PoisonError};
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
/// Bytes of text one request to `embedder serve` carries at most; an input
/// over it goes alone. About 8K tokens, which a CPU host embeds well inside
/// the default request timeout: whole texts go on that wire, and a batch of
/// long ones in one request would time out, and be retried, for ever.
const ONEIRON_REQUEST_BYTES: usize = 32 * 1024;

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
    /// How these vectors were made, from `embedder serve`.
    #[serde(default)]
    transform: Option<String>,
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
    /// Set by `oneiron-server embedder serve`, with `transform`.
    #[serde(default)]
    oneiron_wire: Option<u32>,
    #[serde(default)]
    transform: Option<String>,
}

/// What the vault admitted for a remote.
#[derive(Clone, Debug, Default)]
enum Admitted {
    /// Nothing yet, or never (a remote rung): answers are not checked.
    #[default]
    Unchecked,
    /// The transform the remote listed when the vault admitted it, or none
    /// for a remote that lists none. Every answer must name exactly this:
    /// `embedder serve` names its transform in each, other servers none.
    Transform(Option<String>),
}

/// What the remote's `/models` listing said about the configured model.
#[derive(Clone, Debug)]
struct Listing {
    wire: Wire,
    /// How the remote makes vectors, when it says ([`Wire::Oneiron`]).
    transform: Option<String>,
}

pub(crate) struct HttpEmbedder {
    common: EmbedderCommon,
    endpoint: String,
    model_key: String,
    locality: EmbedderLocality,
    max_input_chars: usize,
    /// The vault's own query prompt, if it names one; an empty one for a vault
    /// on a shipped model's measured evidence floors, which were measured
    /// with no query prompt, so the server's own never applies to it.
    query_instruction: Option<String>,
    /// The remote's last `/models` listing that answered, read before the
    /// first request that depends on it and again at every admission.
    listing: Mutex<Option<Listing>>,
    /// What the vault admitted for this remote ([`Self::admit`]), which every
    /// answer is then held to.
    admitted: Mutex<Admitted>,
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
            query_instruction: config.query_instruction.clone().or_else(|| {
                super::local::model_manager::pinned_endpoint_evidence(config)
                    .map(|_| String::new())
            }),
            listing: Mutex::new(None),
            admitted: Mutex::new(Admitted::Unchecked),
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

    /// What the remote reads, from its `/models` listing.
    fn wire(&self) -> oneiron::Result<Wire> {
        let cached = self
            .listing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|listing| listing.wire);
        match cached {
            Some(wire) => Ok(wire),
            None => Ok(self.read_listing()?.wire),
        }
    }

    /// How the remote makes vectors, when it says, read afresh: `embedder
    /// serve` does, and the slot holds it to the vault's pinned transform as
    /// it holds the local provider's.
    pub(crate) fn served_transform(&self) -> oneiron::Result<Option<String>> {
        Ok(self.read_listing()?.transform)
    }

    /// Records what the vault admitted. From then on an answer that names
    /// another transform, or names one where none was admitted, is refused: a
    /// remote restarted with other settings, or whose listing could not be
    /// read as one, fills and answers nothing until it is restored or the
    /// vault is reembedded.
    pub(crate) fn admit(&self, transform: Option<String>) {
        *self.admitted.lock().unwrap_or_else(PoisonError::into_inner) =
            Admitted::Transform(transform);
    }

    /// Reads the remote's `/models` listing and keeps it. A listing that does
    /// not answer, or answers with a failure, is an error and keeps nothing:
    /// it is asked again next time. A remote with no listing route, or one
    /// that answers without the mark, is the OpenAI wire.
    fn read_listing(&self) -> oneiron::Result<Listing> {
        let url = format!("{}/models", self.endpoint);
        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|e| transport_error("models listing", &e))?;
        let status = response.status();
        let listed = if status.is_success() {
            let bytes = bounded_body(response)?;
            serde_json::from_slice::<ModelsResponse>(&bytes).ok()
        } else if no_listing_route(status) {
            None
        } else {
            return Err(oneiron::Error::UpstreamToolFailure {
                tool: EMBEDDER_TOOL,
                code: format!("embedder models listing returned HTTP {status}"),
            });
        };
        let listing = self.listing_of(listed.as_ref());
        *self.listing.lock().unwrap_or_else(PoisonError::into_inner) = Some(listing.clone());
        Ok(listing)
    }

    fn listing_of(&self, listed: Option<&ModelsResponse>) -> Listing {
        let row = listed.and_then(|listed| {
            listed.data.iter().find(|row| {
                row.id == self.model_key && row.oneiron_wire == Some(super::serve::ONEIRON_WIRE)
            })
        });
        match row {
            Some(row) => Listing {
                wire: Wire::Oneiron,
                transform: row.transform.clone(),
            },
            None => Listing {
                wire: Wire::OpenAi,
                transform: None,
            },
        }
    }

    /// Posts `texts`; the answer is held to what the vault admitted.
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
        if let Admitted::Transform(admitted) =
            &*self.admitted.lock().unwrap_or_else(PoisonError::into_inner)
            && parsed.transform != *admitted
        {
            return Err(oneiron::Error::UpstreamToolFailure {
                tool: EMBEDDER_TOOL,
                code: "embedder endpoint now makes vectors another way than the vault admitted; restore its settings or run `oneiron-server reembed`".to_owned(),
            });
        }
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

/// `texts` in order, as consecutive requests of at most `bytes` bytes each,
/// or of one text where a text alone is over it.
fn requests<'t, 'a>(texts: &'t [&'a str], bytes: usize) -> Vec<&'t [&'a str]> {
    let mut requests = Vec::new();
    let (mut start, mut size) = (0, 0);
    for (index, text) in texts.iter().enumerate() {
        if index > start && size + text.len() > bytes {
            requests.push(&texts[start..index]);
            (start, size) = (index, 0);
        }
        size += text.len();
    }
    if start < texts.len() {
        requests.push(&texts[start..]);
    }
    requests
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
        match wire {
            Wire::OpenAi => self.post_embeddings(&refs, Side::default()),
            Wire::Oneiron => {
                let side = Side {
                    input_type: Some("document"),
                    instruction: None,
                };
                let mut vectors = Vec::with_capacity(refs.len());
                for request in requests(&refs, ONEIRON_REQUEST_BYTES) {
                    vectors.extend(self.post_embeddings(request, side)?);
                }
                Ok(vectors)
            }
        }
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

/// Whether a `/models` answer says the remote has no listing route, which
/// any OpenAI-compatible server may lack: the OpenAI wire, with an unknown
/// catalog.
fn no_listing_route(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::NOT_FOUND
            | reqwest::StatusCode::METHOD_NOT_ALLOWED
            | reqwest::StatusCode::NOT_IMPLEMENTED
    )
}

/// How the configured remote makes vectors, asked now: what `embedder serve`
/// lists for the model, `None` for any other remote. The remote must then
/// pass the startup probe held to that answer — it lists the model and
/// answers at the configured width, naming the listed transform — so a vault
/// is never moved to a remote that cannot fill it, nor to a listing no answer
/// came from. An error when it does not answer or does not pass.
pub(crate) fn resolve_transform(config: &EmbedderConfig) -> oneiron::Result<Option<String>> {
    let embedder = HttpEmbedder::from_config(config)?;
    let served = embedder.served_transform()?;
    embedder.admit(served.clone());
    match probe_endpoint(&embedder) {
        Ok(ProbeOutcome::Ready) => Ok(served),
        Ok(ProbeOutcome::Unreachable(why)) => Err(oneiron::Error::UpstreamToolFailure {
            tool: EMBEDDER_TOOL,
            code: format!("embedder endpoint did not answer the probe: {why}"),
        }),
        Err(refused) => Err(oneiron::Error::InvalidConfig(refused.to_string())),
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
        Ok(response) if response.status().is_success() => match bounded_body(response) {
            Ok(bytes) => serde_json::from_slice::<ModelsResponse>(&bytes).ok(),
            Err(error) => return Ok(ProbeOutcome::Unreachable(error.to_string())),
        },
        // No listing route: an unknown catalog, so only the width is checked.
        Ok(response) if no_listing_route(response.status()) => None,
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
    *embedder
        .listing
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(embedder.listing_of(listed.as_ref()));
    // Unmarked, so any remote answers it as a document; held to the transform
    // admitted, if any (none at startup, the listed one before a move).
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
