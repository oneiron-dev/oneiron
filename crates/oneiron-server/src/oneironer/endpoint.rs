//! The `endpoint` provider: a tagger server on this machine that speaks the
//! slot's contract.
//!
//! `GET {url}/v1/model` answers with a model card (identity and what the model
//! returns); `POST {url}/v1/extract` takes the engine's `EncoderInput` and
//! answers with an `EncoderOutput`, which a card read after it vouches for.
//! The client follows the embedder endpoint's rules: a loopback host is
//! on-device, one attempt per call, no redirects, a bounded body, and errors
//! that carry the failure class and never vault text. It takes no proxy.

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

/// What a tagger says it is and what it returns. A card may carry more
/// (which runtime serves the model, say); this server keeps none of it, since
/// any string the tagger reports could hold text it has read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct ModelCard {
    pub(crate) checkpoint_sha16: String,
    pub(crate) contract_version: u32,
    pub(crate) label_count: u32,
    pub(crate) returns: Returns,
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
    /// The tagger could not be reached, or its card could not be read whole.
    /// Not fatal: writes land with their markers, and the worker probes again
    /// before it drains.
    Unreachable(String),
}

/// A reachable tagger that is not the configured one: a configuration error.
///
/// A refusal names only what this server expected, never what the tagger
/// reported: any value in its card, a checkpoint-shaped string or a number,
/// could be text it has read, and a refusal is logged.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProbeError {
    #[error("the tagger serves another checkpoint than the configured checkpoint_sha16 {expected}")]
    WrongCheckpoint { expected: String },
    #[error("the tagger reports a checkpoint that is not 16 lowercase hex digits")]
    MalformedCheckpoint,
    #[error("the tagger speaks another contract version than this server's {expected}")]
    WrongContract { expected: u32 },
    #[error("the tagger reports another label count than the configured label_count {expected}")]
    WrongLabelCount { expected: u32 },
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
        // No proxy either: the loopback check above is the egress boundary,
        // and a proxy from the environment or the system would carry every
        // turn's text off the device past it.
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
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
                    "GET /v1/model returned {}",
                    status_class(response.status())
                )));
            }
            Err(error) => {
                return Ok(ProbeOutcome::Unreachable(
                    transport_error("model probe", &error).to_string(),
                ));
            }
        };
        // A body that breaks off or times out is a tagger that could not be
        // read, as a refused connection is: the worker backs off and probes
        // again. A body past the cap, or one that is not a card, is refused.
        let bytes = match bounded_body(response) {
            Ok(bytes) => bytes,
            Err(BodyError::TooLarge) => return Err(ProbeError::NoModelCard),
            Err(BodyError::Read(class)) => {
                return Ok(ProbeOutcome::Unreachable(format!(
                    "GET /v1/model body read {class}"
                )));
            }
        };
        let card: ModelCard =
            serde_json::from_slice(&bytes).map_err(|_| ProbeError::NoModelCard)?;
        // The card comes from a server that has read vault text, and a
        // refusal is logged: no refusal names what the tagger reported.
        if oneiron::tagging::TaggingMarkerConfig::new(card.checkpoint_sha16.as_str()).is_err() {
            return Err(ProbeError::MalformedCheckpoint);
        }
        if card.checkpoint_sha16 != self.expected_checkpoint {
            return Err(ProbeError::WrongCheckpoint {
                expected: self.expected_checkpoint.clone(),
            });
        }
        if card.contract_version != CONTRACT_VERSION {
            return Err(ProbeError::WrongContract {
                expected: CONTRACT_VERSION,
            });
        }
        if card.label_count != self.expected_label_count {
            return Err(ProbeError::WrongLabelCount {
                expected: self.expected_label_count,
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
                "tagger extract returned {}",
                status_class(status)
            )));
        }
        let bytes = bounded_body(response).map_err(|error| match error {
            BodyError::TooLarge => failure("tagger response exceeds the body cap".to_owned()),
            BodyError::Read(_) => failure("tagger response read failed".to_owned()),
        })?;
        // A parse error names the failure only: serde's message can quote the
        // body, and the body is derived from vault text.
        serde_json::from_slice(&bytes)
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
        let output = self.post_extract(input)?;
        // The answer names no checkpoint, and it settles under the configured
        // one; so the card is read again once the answer is in. A tagger that
        // is no longer the configured one fails the call, and its marker
        // waits. Only a swap there and back inside one call passes this.
        match self.probe() {
            Ok(ProbeOutcome::Ready(_)) => Ok(output),
            Ok(ProbeOutcome::Unreachable(_)) => Err(failure(
                "tagger model card unreadable after extract".to_owned(),
            )),
            Err(_) => Err(failure(
                "tagger is not the configured checkpoint after extract".to_owned(),
            )),
        }
    }
}

/// A failure names a registered HTTP status by its number, and any other
/// only as a class: a tagger picks its own status line, and a number it made
/// up could be text it has read.
fn status_class(status: reqwest::StatusCode) -> String {
    if status.canonical_reason().is_some() {
        format!("HTTP {}", status.as_u16())
    } else {
        "a nonstandard HTTP status".to_owned()
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

/// Why a response body was not read whole.
enum BodyError {
    /// It declared or ran past the body cap.
    TooLarge,
    /// The read broke off or timed out; the class names which, never a byte
    /// of what arrived.
    Read(&'static str),
}

fn bounded_body(response: reqwest::blocking::Response) -> Result<Vec<u8>, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(BodyError::TooLarge);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            let timed_out = error.kind() == std::io::ErrorKind::TimedOut
                || error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<reqwest::Error>())
                    .is_some_and(reqwest::Error::is_timeout);
            BodyError::Read(if timed_out { "timed out" } else { "failed" })
        })?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(BodyError::TooLarge);
    }
    Ok(bytes)
}
