//! The `endpoint` provider: any OpenAI-compatible `/v1/embeddings` server.
//!
//! One client shape for every host that speaks that wire — LM Studio, Ollama,
//! `llama-server`, a cloud. The server cannot see what the remote actually
//! loaded, so the configured artifact string is provenance it logs and never
//! verifies; the `model_id` it reports is the vault's space id, unchanged.
//!
//! One remote gets more: `oneiron-server embedder serve` marks its `/models`
//! rows, and to it this client sends what a local vault's provider would see —
//! whole texts, each marked query or document ([`Wire::Oneiron`]). It names
//! the model it loaded and how it makes vectors, in its listing and in every
//! answer, and the vault holds both to what it admitted. Each answer also
//! names the device and runtime that computed it, which the vault marks its
//! vectors with (ARCH-0036); an endpoint that does not say is marked `remote`.

use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use oneiron::config::VectorEvidenceFloors;
use oneiron::embed::{
    Embedder, EmbedderLocality, EmbeddingDevice, EmbeddingProvenance, PendingEmbeddingInput,
};
use oneiron::error::StoreError;
use oneiron::federation::derivation::DerivationScope;
use serde_json::value::RawValue;

use super::local::evidence::{self, RunProfile};
use super::remote::RungHold;
use super::{EmbedderCommon, QueryEmbedder, engine_locality};
use crate::config::EmbedderConfig;
use crate::runtime::{GpuPool, GpuRegistryError};

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
/// The longest runtime an answer's mark may name; a longer one is not taken.
const MAX_RUNTIME_BYTES: usize = 128;
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
    /// The model that made these vectors, from `embedder serve`.
    #[serde(default)]
    model_id: Option<String>,
    /// How these vectors were made, from `embedder serve`.
    #[serde(default)]
    transform: Option<String>,
    /// How the model that made them runs, from `embedder serve`
    /// ([`RunProfile`]), kept as sent.
    #[serde(default)]
    profile: Option<serde_json::Value>,
    /// The device and runtime that computed them, from `embedder serve`,
    /// kept as raw text and read by [`answer_mark`]: a mark this build cannot
    /// read, even one nested past the decoder's depth limit, never fails the
    /// answer.
    #[serde(default)]
    provenance: Option<Box<RawValue>>,
}

/// One answer's vectors, in request order, and the device and runtime it
/// names; `None` when it does not say.
struct Answer {
    vectors: Vec<Vec<f32>>,
    mark: Option<EmbeddingProvenance>,
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
    /// Set by `oneiron-server embedder serve`, with `model_id` and
    /// `transform`.
    #[serde(default)]
    oneiron_wire: Option<u32>,
    /// The model the server loaded, which an alias in `id` stands for.
    #[serde(default)]
    model_id: Option<String>,
    #[serde(default)]
    transform: Option<String>,
    #[serde(default)]
    profile: Option<serde_json::Value>,
}

/// What the vault admitted for a remote.
#[derive(Clone, Debug, Default)]
enum Admitted {
    /// Nothing yet (the startup probe): answers are not checked.
    #[default]
    Unchecked,
    /// The remote's listing when the vault admitted it, which every answer
    /// must agree with ([`Listing::agrees_with`]).
    Listing(Listing),
    /// A remote rung, held to the vault's space without a listing of its own
    /// ([`HttpEmbedder::hold_as_rung`]).
    Rung(Arc<Mutex<RungHold>>),
}

/// What the remote's `/models` listing said about the configured model.
#[derive(Clone, Debug)]
pub(crate) struct Listing {
    wire: Wire,
    /// The model the remote loaded, when it says ([`Wire::Oneiron`]): the
    /// configured model key may be an alias, and the model behind an alias
    /// can change while the alias stays.
    model_id: Option<String>,
    /// How the remote makes vectors, when it says ([`Wire::Oneiron`]).
    transform: Option<String>,
    /// How it runs the model, when it says ([`Wire::Oneiron`]), as sent: a
    /// profile this build cannot read is held to all the same, and judged
    /// unmeasured.
    profile: Option<serde_json::Value>,
}

impl Listing {
    /// How the remote makes vectors, when it says.
    pub(crate) fn transform(&self) -> Option<&str> {
        self.transform.as_deref()
    }

    /// Where vector evidence starts in the space this listing serves: a
    /// shipped model's measured floors when the remote names that model
    /// loaded and runs it as it was measured ([`RunProfile`]), and the
    /// vault's queries go unprompted; the engine's default otherwise, and for
    /// any remote that does not say.
    pub(crate) fn evidence(&self, config: &EmbedderConfig) -> VectorEvidenceFloors {
        let profile = self
            .profile
            .clone()
            .and_then(|profile| serde_json::from_value::<RunProfile>(profile).ok());
        match (&self.model_id, profile) {
            (Some(model_id), Some(profile)) => evidence::measured_floors(
                model_id,
                &profile,
                evidence::endpoint_queries_unprompted(config),
            )
            .unwrap_or_default(),
            _ => VectorEvidenceFloors::default(),
        }
    }

    /// Whether an answer names what this listing did: `embedder serve` names
    /// the model it loaded, its transform and its profile in every answer,
    /// and any other server none of them.
    fn agrees_with(&self, answer: &EmbeddingsResponse) -> bool {
        match self.wire {
            Wire::OpenAi => answer.transform.is_none(),
            Wire::Oneiron => {
                answer.model_id == self.model_id
                    && answer.transform == self.transform
                    && answer.profile == self.profile
            }
        }
    }
}

/// The door each embedding request of an endpoint goes through, admitted
/// before it is sent and settled after ([`HttpEmbedder::pay_through`]).
pub(crate) trait PaidRequests: Send + Sync {
    /// Sends `texts` by `post`, which makes exactly one request.
    fn send(
        &self,
        texts: &[&str],
        post: &mut dyn FnMut() -> oneiron::Result<Vec<Vec<f32>>>,
    ) -> oneiron::Result<Vec<Vec<f32>>>;
}

pub(crate) struct HttpEmbedder {
    common: EmbedderCommon,
    endpoint: String,
    model_key: String,
    locality: EmbedderLocality,
    max_input_chars: usize,
    /// The vault's own query prompt, if it names one; an empty one for a vault
    /// on a shipped model with measured evidence floors, which were measured
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
    /// The endpoint's paid door: every embedding request goes through it
    /// once it is set. The primary endpoint's is set before its probe
    /// ([`super::build_slot`]), a remote rung's when it is built.
    paid: OnceLock<Arc<dyn PaidRequests>>,
    /// The serve host's GPU pool, once set: document batches lease a pod
    /// from it ([`Self::route_batches_through`]).
    pods: OnceLock<PodRoute>,
}

/// Which serving lane a request rides (ARCH-0019 §5). A query and the startup
/// probe are interactive and stay on the configured endpoint; a document
/// batch is retry-tolerant and may go to a leased GPU pod.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lane {
    Interactive,
    Batch,
}

/// The pool document batches lease a pod from, and the client that reaches
/// the pods with their own key, never the endpoint's.
struct PodRoute {
    pool: GpuPool,
    /// The holding vault's account, when one is bound: each request is then a
    /// derivation job whose answer is sealed to that account.
    scope: Option<DerivationScope>,
    client: reqwest::blocking::Client,
}

impl PodRoute {
    /// Sends one request to a leased pod, or to the configured endpoint when
    /// no pod is healthy. An answer from a pod whose lease lapsed meanwhile
    /// (preempted, or unhealthy at the last poll) is dropped, and the
    /// worker's retry sends the rows again.
    fn post(&self, http: &HttpEmbedder, texts: &[&str], side: Side<'_>) -> oneiron::Result<Answer> {
        let Some(scope) = self.scope else {
            let lease = match self.pool.acquire() {
                Ok(lease) => lease,
                Err(GpuRegistryError::Unavailable) => {
                    return http.post_at(&http.client, &http.endpoint, texts, side, Ok);
                }
                Err(error) => return Err(pod_error(&error)),
            };
            let answer = http.post_at(&self.client, lease.url(), texts, side, Ok)?;
            return if lease.is_live() {
                Ok(answer)
            } else {
                Err(pod_error(&GpuRegistryError::LeaseExpired))
            };
        };
        let computation = format!("embed:{}", http.model_key).into_bytes();
        let job = match self
            .pool
            .acquire_derivation(scope, computation, batch_digest(texts))
        {
            Ok(job) => job,
            Err(GpuRegistryError::Unavailable) => {
                return http.post_at(&http.client, &http.endpoint, texts, side, Ok);
            }
            Err(error) => return Err(pod_error(&error)),
        };
        let url = job.url().to_owned();
        http.post_at(&self.client, &url, texts, side, |body| {
            let sealed = job.complete(body).map_err(|error| pod_error(&error))?;
            sealed
                .read(scope.owner())
                .map(<[u8]>::to_vec)
                .ok_or_else(|| pod_error(&GpuRegistryError::InvalidInput))
        })
    }
}

/// What a derivation job is over: the batch's texts, each length-prefixed.
fn batch_digest(texts: &[&str]) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    for text in texts {
        hash.update(&(text.len() as u64).to_le_bytes());
        hash.update(text.as_bytes());
    }
    hash.finalize().as_bytes().to_vec()
}

fn pod_error(error: &GpuRegistryError) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: EMBEDDER_TOOL,
        code: format!("embedder gpu pod: {error}"),
    }
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
        // dead remote behind a long stall and re-charge a metered one. No
        // proxy either: one from the environment or the system would receive
        // the bearer key and every text the vault embeds.
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
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
                super::local::evidence::names_measured_model(&config.model_id).then(String::new)
            }),
            listing: Mutex::new(None),
            admitted: Mutex::new(Admitted::Unchecked),
            client,
            truncations: AtomicU64::new(0),
            paid: OnceLock::new(),
            pods: OnceLock::new(),
        }))
    }

    /// Sends this endpoint's document batches through leases on the serve
    /// host's GPU pool (ARCH-0019 §5, the batch lane); queries stay on the
    /// configured endpoint. Set once.
    pub(crate) fn route_batches_through(
        &self,
        pool: GpuPool,
        scope: Option<DerivationScope>,
        timeout: Duration,
    ) -> oneiron::Result<()> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(bearer) = pool.bearer() {
            headers.insert(reqwest::header::AUTHORIZATION, bearer.clone());
        }
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(timeout)
            .build()
            .map_err(|e| oneiron::Error::InvalidConfig(format!("gpu pod http client: {e}")))?;
        tracing::info!(
            region = pool.region(),
            bound = scope.is_some(),
            "embedder batches route through the GPU pool"
        );
        if self
            .pods
            .set(PodRoute {
                pool,
                scope,
                client,
            })
            .is_err()
        {
            tracing::warn!(endpoint = %self.endpoint, "an endpoint embedder's GPU pool is set once");
        }
        Ok(())
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

    /// What the remote serves, read afresh. `embedder serve` names the model
    /// it loaded, which must be this section's, the vault's space, and its
    /// transform, which the slot holds to the vault's pin as it holds the
    /// local provider's. An error when the listing does not answer, or names
    /// another model.
    pub(crate) fn served(&self) -> oneiron::Result<Listing> {
        let listing = self.read_listing()?;
        if listing.wire == Wire::Oneiron
            && listing.model_id.as_deref() != Some(self.common.model_id.as_str())
        {
            return Err(oneiron::Error::Store(StoreError::EmbeddingModelChanged {
                stored: self.common.model_id.clone(),
                requested: listing.model_id.unwrap_or_default(),
            }));
        }
        Ok(listing)
    }

    /// Records what the vault admitted. From then on an answer that names
    /// another model, transform or profile than the admitted listing, or
    /// names one where none was listed, is refused: a remote restarted with
    /// another model or other settings, or whose listing could not be read as
    /// `embedder serve`'s, fills and answers nothing until it is restored or
    /// the vault is reembedded, or, for a profile alone, until the worker
    /// admits it again with the floors that profile takes.
    pub(crate) fn admit(&self, listing: Listing) {
        *self.admitted.lock().unwrap_or_else(PoisonError::into_inner) = Admitted::Listing(listing);
    }

    /// [`Self::admit`], once `vault_side` has taken the listing (its
    /// transform against the vault's pin, its floors), with no answer checked
    /// in between: an answer is held either to the listing before, under the
    /// floors before, or to this one under this one's. Nothing is recorded
    /// when `vault_side` refuses.
    pub(crate) fn admit_with<E>(
        &self,
        listing: Listing,
        vault_side: impl FnOnce(&Listing) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut admitted = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
        vault_side(&listing)?;
        *admitted = Admitted::Listing(listing);
        Ok(())
    }

    /// Holds a remote rung to the vault's space. A rung is never admitted
    /// from a listing of its own and fills the rows the vault's provider
    /// would: an answer that names the model it loaded must name the vault's,
    /// one that names a transform must name the one the vault admitted from
    /// its provider, and under a model's measured floors one that names its
    /// profile must name the measured one ([`RungHold::holds`]).
    pub(crate) fn hold_as_rung(&self, hold: Arc<Mutex<RungHold>>) {
        *self.admitted.lock().unwrap_or_else(PoisonError::into_inner) = Admitted::Rung(hold);
    }

    /// Sends every embedding request of this remote through `door`, from
    /// now on. A door set once stays.
    pub(crate) fn pay_through(&self, door: Arc<dyn PaidRequests>) {
        if self.paid.set(door).is_err() {
            tracing::warn!(endpoint = %self.endpoint, "a remote embedder's paid door is set once");
        }
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
                model_id: row.model_id.clone(),
                transform: row.transform.clone(),
                profile: row.profile.clone(),
            },
            None => Listing {
                wire: Wire::OpenAi,
                model_id: None,
                transform: None,
                profile: None,
            },
        }
    }

    /// Posts `texts` as one request, through the paid door when this remote
    /// has one; the answer is held to what the vault admitted.
    fn post_embeddings(
        &self,
        texts: &[&str],
        side: Side<'_>,
        lane: Lane,
    ) -> oneiron::Result<Answer> {
        let Some(door) = self.paid.get() else {
            return self.post_once(texts, side, lane);
        };
        // The door settles on the vectors; the mark rides beside them.
        let mut mark = None;
        let vectors = door.send(texts, &mut || {
            let answer = self.post_once(texts, side, lane)?;
            mark = answer.mark;
            Ok(answer.vectors)
        })?;
        Ok(Answer { vectors, mark })
    }

    fn post_once(&self, texts: &[&str], side: Side<'_>, lane: Lane) -> oneiron::Result<Answer> {
        match self.pods.get() {
            Some(pods) if lane == Lane::Batch => pods.post(self, texts, side),
            _ => self.post_at(&self.client, &self.endpoint, texts, side, Ok),
        }
    }

    /// Posts one request to `base`. `settle` takes the answer's body before
    /// it is read: a pod's derivation job seals it there.
    fn post_at(
        &self,
        client: &reqwest::blocking::Client,
        base: &str,
        texts: &[&str],
        side: Side<'_>,
        settle: impl FnOnce(Vec<u8>) -> oneiron::Result<Vec<u8>>,
    ) -> oneiron::Result<Answer> {
        let url = format!("{base}/embeddings");
        let body = EmbeddingsRequest {
            model: &self.model_key,
            input: texts.to_vec(),
            side,
        };
        let response = client
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
        let parsed: EmbeddingsResponse = serde_json::from_slice(&settle(bounded_body(response)?)?)
            .map_err(|e| oneiron::Error::UpstreamToolFailure {
                tool: EMBEDDER_TOOL,
                code: format!("embeddings response: {e}"),
            })?;
        let agrees = match &*self.admitted.lock().unwrap_or_else(PoisonError::into_inner) {
            Admitted::Unchecked => true,
            Admitted::Listing(listing) => listing.agrees_with(&parsed),
            Admitted::Rung(hold) => hold.lock().unwrap_or_else(PoisonError::into_inner).holds(
                &self.common.model_id,
                parsed.model_id.as_deref(),
                parsed.transform.as_deref(),
                parsed.profile.as_ref(),
            ),
        };
        if !agrees {
            return Err(oneiron::Error::UpstreamToolFailure {
                tool: EMBEDDER_TOOL,
                code: "embedder endpoint now serves another model, or makes vectors another way, than the vault admitted; restore it or run `oneiron-server reembed`".to_owned(),
            });
        }
        Ok(Answer {
            vectors: self.order_rows(parsed.data, texts.len())?,
            // A pod's answer that does not say is marked with the pod.
            mark: answer_mark(parsed.provenance)
                .or_else(|| (base != self.endpoint).then(|| self.provenance_at(base))),
        })
    }

    /// Each of `answer`'s vectors with the device and runtime that computed
    /// it: the answer's own, or this endpoint's when it does not say.
    fn marked(&self, answer: Answer) -> Vec<(Vec<f32>, EmbeddingProvenance)> {
        let mark = answer.mark.unwrap_or_else(|| self.provenance());
        answer
            .vectors
            .into_iter()
            .map(|vector| (vector, mark.clone()))
            .collect()
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
        Ok(self
            .embed_marked(inputs)?
            .into_iter()
            .map(|(vector, _)| vector)
            .collect())
    }

    fn embed_marked(
        &self,
        inputs: &[PendingEmbeddingInput],
    ) -> oneiron::Result<Vec<(Vec<f32>, EmbeddingProvenance)>> {
        self.embed_documents(inputs, &|_| Ok(()))
    }

    fn embed_released(
        &self,
        inputs: &[PendingEmbeddingInput],
        release: &dyn Fn(&[oneiron::EntityId]) -> oneiron::Result<()>,
    ) -> oneiron::Result<Vec<(Vec<f32>, EmbeddingProvenance)>> {
        self.embed_documents(inputs, release)
    }
    /// An answer that does not name its device was computed on one the vault
    /// does not see; it is named as an offer, model at place. The URL holds no
    /// credential or query ([`Self::from_config`] refuses one).
    fn provenance(&self) -> EmbeddingProvenance {
        self.provenance_at(&self.endpoint)
    }
}

impl HttpEmbedder {
    fn provenance_at(&self, base: &str) -> EmbeddingProvenance {
        EmbeddingProvenance::new(
            EmbeddingDevice::Remote,
            format!("{}@{}", self.model_key, base),
        )
    }

    /// Embeds `inputs` as documents, one request or several, each sent only
    /// once `release` lets the rows it carries leave, and each vector marked
    /// with the device and runtime that computed it.
    fn embed_documents(
        &self,
        inputs: &[PendingEmbeddingInput],
        release: &dyn Fn(&[oneiron::EntityId]) -> oneiron::Result<()>,
    ) -> oneiron::Result<Vec<(Vec<f32>, EmbeddingProvenance)>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let wire = self.wire()?;
        let rows: Vec<oneiron::EntityId> = inputs.iter().map(|input| input.entity_id).collect();
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
            Wire::OpenAi => {
                release(&rows)?;
                Ok(self.marked(self.post_embeddings(&refs, Side::default(), Lane::Batch)?))
            }
            Wire::Oneiron => {
                let side = Side {
                    input_type: Some("document"),
                    instruction: None,
                };
                let mut vectors = Vec::with_capacity(refs.len());
                let mut sent = 0;
                for request in requests(&refs, ONEIRON_REQUEST_BYTES) {
                    release(&rows[sent..sent + request.len()])?;
                    sent += request.len();
                    vectors.extend(self.marked(self.post_embeddings(
                        request,
                        side,
                        Lane::Batch,
                    )?));
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
                self.post_embeddings(&[prefixed.as_str()], Side::default(), Lane::Interactive)?
            }
            Wire::Oneiron => self.post_embeddings(
                &[text],
                Side {
                    input_type: Some("query"),
                    instruction: self.query_instruction.as_deref(),
                },
                Lane::Interactive,
            )?,
        }
        .vectors;
        vectors.pop().ok_or(oneiron::Error::InvariantViolation(
            "embedder endpoint answered a single query with no row",
        ))
    }
}

/// The device and runtime an answer names, when it names a device the
/// endpoint ran on and a runtime fit to store; otherwise the endpoint did not
/// say.
fn answer_mark(sent: Option<Box<RawValue>>) -> Option<EmbeddingProvenance> {
    let mark: EmbeddingProvenance = serde_json::from_str(sent?.get()).ok()?;
    let ran_on = matches!(
        mark.device,
        EmbeddingDevice::Cpu | EmbeddingDevice::Cuda | EmbeddingDevice::Metal
    );
    let storable = !mark.runtime.is_empty()
        && mark.runtime.len() <= MAX_RUNTIME_BYTES
        && !mark.runtime.chars().any(char::is_control);
    (ran_on && storable).then_some(mark)
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
/// lists for the model, `None` for any other remote. `embedder serve` must
/// serve the configured model itself, and the remote must then pass the
/// startup probe held to that listing — it lists the model key and answers at
/// the configured width, naming the listed model and transform — so a vault
/// is never moved to a remote that cannot fill it, nor to a listing no answer
/// came from. An error when it does not answer or does not pass.
pub(crate) fn resolve_transform(config: &EmbedderConfig) -> oneiron::Result<Option<String>> {
    let embedder = HttpEmbedder::from_config(config)?;
    // The probe is a paid call like serve's; its rows go to the log.
    super::admitted::pay_primary(
        &embedder,
        config,
        Arc::new(crate::models::ServerReceipts::default()),
    )?;
    let served = embedder.served()?;
    let transform = served.transform.clone();
    embedder.admit(served);
    match probe_endpoint(&embedder) {
        Ok(ProbeOutcome::Ready) => Ok(transform),
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
    // Unmarked, so any remote answers it as a document; held to the listing
    // admitted, if any (none at startup, the listed one before a move).
    match embedder.post_embeddings(&[PROBE_TEXT], Side::default(), Lane::Interactive) {
        Ok(answer) => {
            let got = answer.vectors.first().map_or(0, Vec::len);
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
