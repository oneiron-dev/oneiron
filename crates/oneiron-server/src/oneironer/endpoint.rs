//! The `endpoint` provider: a tagger server on this machine that speaks the
//! slot's contract.
//!
//! `GET {url}/v1/model` answers with a model card (identity and what the model
//! returns); `POST {url}/v1/extract` takes the engine's `EncoderInput` and
//! answers with an `EncoderOutput`. The client follows the embedder endpoint's
//! rules: a loopback host is on-device, one attempt per call, no redirects, a
//! bounded body, and errors that carry the failure class and never vault text.

use std::io::Read;
use std::time::Duration;

use oneiron::ModelId;
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{EncoderInput, EncoderOutput, ExtractionEncoder};
use serde::Deserialize;

use crate::config::OneironerConfig;

/// The slot's wire contract version. A tagger must report exactly this.
pub(crate) const CONTRACT_VERSION: u32 = 1;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Tool name on every upstream failure this provider reports.
const TAGGER_TOOL: &str = "oneironer-endpoint";

/// What a tagger says it is and what it returns.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct ModelCard {
    pub(crate) checkpoint_sha16: String,
    pub(crate) contract_version: u32,
    pub(crate) label_count: u32,
    pub(crate) returns: Returns,
    /// Which runtime serves the model; reported, never checked.
    #[serde(default)]
    pub(crate) engine: Option<String>,
}

/// The outputs a model declares.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Returns {
    pub(crate) spans: bool,
    pub(crate) links: bool,
    pub(crate) mood: bool,
}

/// What a startup probe found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProbeOutcome {
    /// The tagger answers and is the configured one.
    Ready(ModelCard),
    /// The tagger could not be reached. Not fatal: writes land with their
    /// markers, and the worker probes again before it drains.
    Unreachable(String),
}

/// A reachable tagger that is not the configured one: a configuration error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProbeError {
    #[error("the tagger serves checkpoint {got}, configured checkpoint_sha16 is {expected}")]
    WrongCheckpoint { expected: String, got: String },
    #[error("the tagger speaks contract version {got}, this server speaks {expected}")]
    WrongContract { expected: u32, got: u32 },
    #[error("the tagger reports {got} labels, configured label_count is {expected}")]
    WrongLabelCount { expected: u32, got: u32 },
    #[error("the tagger declares no spans")]
    NoSpans,
    #[error(
        "the tagger returns no mood; a spans-only tagger needs the optional-mood contract (ONE-2167)"
    )]
    NoMood,
    #[error("the tagger did not answer GET /v1/model with a model card")]
    NoModelCard,
}

pub(crate) struct HttpTagger {
    base: String,
    model: ModelId,
    expected_checkpoint: String,
    expected_label_count: u32,
    client: reqwest::blocking::Client,
}

impl HttpTagger {
    pub(crate) fn from_config(config: &OneironerConfig) -> oneiron::Result<Self> {
        let invalid = |reason: &str| oneiron::Error::InvalidConfig(reason.to_owned());
        let base = config
            .url
            .as_deref()
            .ok_or_else(|| invalid("oneironer.url is required"))?
            .trim()
            .trim_end_matches('/')
            .to_owned();
        let url = reqwest::Url::parse(&base).map_err(|_| invalid("invalid oneironer URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "oneironer URL must be http(s) with no credentials, query or fragment",
            ));
        }
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        // A tagger reads every turn. Off the device it would carry vault text
        // away, which extraction may do only behind the host egress
        // predicate, and no tagger door has one yet.
        if !loopback {
            return Err(invalid(
                "the oneironer endpoint must be a loopback address; a network tagger needs the host egress predicate",
            ));
        }
        let expected_checkpoint = config
            .checkpoint_sha16
            .clone()
            .ok_or_else(|| invalid("oneironer.checkpoint_sha16 is required"))?;
        let model = ModelId::new(format!("oneironer/endpoint@{expected_checkpoint}"))
            .map_err(|_| invalid("oneironer.checkpoint_sha16 does not form a model id"))?;
        // One attempt, no redirects, bounded body: the worker loop is the
        // retry, and a retry here would hide a dead tagger behind a stall.
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|_| invalid("oneironer http client could not be built"))?;
        Ok(Self {
            base,
            model,
            expected_checkpoint,
            expected_label_count: config.label_count.unwrap_or_default(),
            client,
        })
    }

    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// Checks the tagger's identity and reads what it returns.
    ///
    /// A reachable tagger with the wrong checkpoint, contract or label count
    /// is refused: tags from it would carry another model's name. An
    /// unreachable one is not; its markers wait.
    pub(crate) fn probe(&self) -> Result<ProbeOutcome, ProbeError> {
        let url = format!("{}/v1/model", self.base);
        let response = match self.client.get(&url).send() {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                return Ok(ProbeOutcome::Unreachable(format!(
                    "GET /v1/model returned HTTP {}",
                    response.status().as_u16()
                )));
            }
            Err(error) => {
                return Ok(ProbeOutcome::Unreachable(
                    transport_error("model probe", &error).to_string(),
                ));
            }
        };
        let card: ModelCard = bounded_body(response)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or(ProbeError::NoModelCard)?;
        if card.checkpoint_sha16 != self.expected_checkpoint {
            return Err(ProbeError::WrongCheckpoint {
                expected: self.expected_checkpoint.clone(),
                got: card.checkpoint_sha16,
            });
        }
        if card.contract_version != CONTRACT_VERSION {
            return Err(ProbeError::WrongContract {
                expected: CONTRACT_VERSION,
                got: card.contract_version,
            });
        }
        if card.label_count != self.expected_label_count {
            return Err(ProbeError::WrongLabelCount {
                expected: self.expected_label_count,
                got: card.label_count,
            });
        }
        if !card.returns.spans {
            return Err(ProbeError::NoSpans);
        }
        if !card.returns.mood && !oneiron::tagging::spans_only_answers_admitted() {
            return Err(ProbeError::NoMood);
        }
        Ok(ProbeOutcome::Ready(card))
    }

    fn post_extract(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        let url = format!("{}/v1/extract", self.base);
        let response = self
            .client
            .post(&url)
            .json(input)
            .send()
            .map_err(|error| transport_error("extract", &error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(failure(format!(
                "tagger extract returned HTTP {}",
                status.as_u16()
            )));
        }
        // A parse error names the failure only: serde's message can quote the
        // body, and the body is derived from vault text.
        serde_json::from_slice(&bounded_body(response)?)
            .map_err(|_| failure("tagger extract response is not the contract".to_owned()))
    }
}

impl ExtractionEncoder for HttpTagger {
    fn model_id(&self) -> &ModelId {
        &self.model
    }

    fn locality(&self) -> EmbedderLocality {
        // `from_config` admits loopback hosts only.
        EmbedderLocality::OnDevice
    }

    fn infer(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        self.post_extract(input)
    }
}

fn failure(code: String) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: TAGGER_TOOL,
        code,
    }
}

/// The failure class, never the body: a server that echoes its input in an
/// error must not put vault text into this server's logs or traces.
fn transport_error(what: &str, error: &reqwest::Error) -> oneiron::Error {
    let class = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_decode() {
        "decode failed"
    } else {
        "failed"
    };
    failure(format!("tagger {what} {class}"))
}

fn bounded_body(response: reqwest::blocking::Response) -> oneiron::Result<Vec<u8>> {
    let too_large = || failure("tagger response exceeds the body cap".to_owned());
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("tagger response read failed".to_owned()))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}
