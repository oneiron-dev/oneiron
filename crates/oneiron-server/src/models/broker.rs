//! A provider whose key stays in the vault's custody (T0) and leaves only
//! through the credential broker (ARCH-0069 `#broker-design`).
//!
//! The daemon builds the exact request bytes first, and the run's permit for
//! the call binds their digest. The gate checks that digest again before the
//! call starts. Only then does the call connect to the broker and check its
//! user, read the key at the custody door, and hand the broker the key with
//! that one request. The broker checks the request again, adds the auth,
//! sends once over verified TLS and strips the key from the reply. A refused
//! or unreachable call never reads the key.
//!
//! A streamed call is refused before its permit starts: the broker buffers
//! and strips whole replies only.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::{BrokerIsolation, SingleRouteBackend};
use oneiron::{
    BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmCatalogEntry, LlmError,
    LlmGenerateFuture, LlmRequest, LlmResponse, LlmResult, LlmStreamResult, ModelId,
    RetryableLlmError, UnsupportedCapability, Vault,
};
use oneiron_broker::{
    BrokerClient, BrokerError, CallHeader, ChildBroker, Failure, Isolation, Outcome, Refusal, Shape,
};
use oneiron_llm_anthropic::{
    AnthropicMessagesConfig, build_anthropic_messages_request, classify_anthropic_status,
    parse_anthropic_messages_response,
};
use oneiron_llm_openai::{
    OpenAiCompatConfig, build_openai_chat_request, classify_openai_status,
    parse_openai_chat_response,
};
use serde_json::Value as JsonValue;
use zeroize::Zeroizing;

use super::output_cap::OutputCap;
use crate::config::models::{
    BrokerConfig, ModelsConfig, ProviderConfig, ProviderKind, ResponseFormatWire,
};

/// The effector a `key_secret`'s custody binding names: the custody door
/// hands the key to a model call's broker leg and to nothing else.
pub const BROKER_EFFECTOR: &str = "broker:model";

/// How long the daemon waits for a reply past the provider's own timeout,
/// which the broker's send runs under.
const REPLY_MARGIN: Duration = Duration::from_secs(15);

/// Reads a provider key at the vault's custody door, for one call.
pub trait KeyDoor: Send + Sync {
    /// Whether the door would release the secret `name` to
    /// [`BROKER_EFFECTOR`] now, checked without reading its value, so a call
    /// it would refuse is refused before its permit starts.
    fn check(&self, name: &str) -> anyhow::Result<()>;

    /// The value of the secret `name`, released to [`BROKER_EFFECTOR`], or
    /// why the door refused it.
    fn read(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>>;
}

/// The vault's T0 door: it checks the secret's binding to
/// [`BROKER_EFFECTOR`], its tier, the live floor and the materialization dial
/// before it hands the value over.
pub struct VaultKeyDoor {
    vault: Arc<Vault>,
}

impl VaultKeyDoor {
    #[must_use]
    pub fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }
}

impl KeyDoor for VaultKeyDoor {
    fn check(&self, name: &str) -> anyhow::Result<()> {
        Ok(self.vault.check_secret_at_door(name, BROKER_EFFECTOR)?)
    }

    fn read(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let mut key = Zeroizing::new(Vec::new());
        self.vault
            .inject_secret_at_door(name, BROKER_EFFECTOR, &mut |value: &[u8]| {
                // Sized once, so no reallocation leaves an unwiped copy.
                key.reserve_exact(value.len());
                key.extend_from_slice(value);
                Ok(())
            })?;
        Ok(key)
    }
}

/// The request builder of the provider's wire protocol.
enum Wire {
    OpenAi(OpenAiCompatConfig),
    Anthropic(AnthropicMessagesConfig),
}

/// One `key_secret` provider's backend: its wire adapter's request builder,
/// reply classifier and parser around a broker call.
pub(super) struct BrokerBackend {
    wire: Wire,
    cap: OutputCap,
    response_format: ResponseFormatWire,
    /// The provider's `https://host[:port]`.
    origin: String,
    /// The base URL's path under the origin, with no trailing `/`.
    prefix: String,
    /// The provider's extra headers, names lowercase.
    headers: BTreeMap<String, String>,
    /// The provider's models, none of them streaming.
    catalog: BTreeMap<ModelId, LlmCatalogEntry>,
    secret: String,
    client: BrokerClient,
    keys: Arc<dyn KeyDoor>,
}

/// Where this server's `key_secret` providers send: a broker the host runs
/// as its own user, or this server's same-user child
/// (`#broker-same-user-open`), one for every provider.
pub(super) enum BrokerSite {
    User { socket: PathBuf, uid: u32 },
    Child(Arc<ChildBroker>),
}

impl BrokerSite {
    /// The site `config` names. A child is not started here: its first call
    /// starts it.
    pub(super) fn new(config: &ModelsConfig) -> anyhow::Result<Self> {
        match &config.broker {
            BrokerConfig::SeparateUser { socket, uid } => Ok(Self::User {
                socket: socket.clone(),
                uid: *uid,
            }),
            BrokerConfig::SameUser {
                program,
                extra_roots,
            } => {
                let program = match program {
                    Some(program) => program.clone(),
                    None => std::env::current_exe()?.with_file_name("oneiron-broker"),
                };
                anyhow::ensure!(
                    program.is_file(),
                    "no credential broker at {}; set models.broker.program",
                    program.display()
                );
                // The child sends every provider's calls, under the longest
                // of their timeouts.
                let timeout = config
                    .providers
                    .values()
                    .filter(|provider| provider.key_secret.is_some())
                    .map(|provider| provider.timeout_secs)
                    .max()
                    .unwrap_or(1);
                tracing::warn!(
                    program = %program.display(),
                    "the credential broker runs as this server's own user (same_user): \
                     no separate user is configured in [models.broker]"
                );
                Ok(Self::Child(Arc::new(ChildBroker::new(
                    program,
                    extra_roots,
                    Duration::from_secs(timeout),
                ))))
            }
        }
    }

    fn client(&self, reply_timeout: Duration) -> anyhow::Result<BrokerClient> {
        match self {
            Self::User { socket, uid } => BrokerClient::new(
                socket.clone(),
                *uid,
                Isolation::SeparateUser,
                reply_timeout,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "models.broker.uid is this server's own user; the broker runs as its own"
                )
            }),
            Self::Child(child) => Ok(BrokerClient::child(Arc::clone(child), reply_timeout)),
        }
    }
}

/// One `key_secret` provider's backend, over the broker at `site` and the
/// key door `keys`.
pub(super) fn broker_backend(
    provider: &ProviderConfig,
    catalog: Vec<LlmCatalogEntry>,
    cap: OutputCap,
    site: &BrokerSite,
    keys: Option<&Arc<dyn KeyDoor>>,
) -> anyhow::Result<BrokerBackend> {
    let secret = provider
        .key_secret
        .clone()
        .ok_or_else(|| anyhow::anyhow!("the provider names no key_secret"))?;
    let keys = keys
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("this server has no vault custody door"))?;
    let client = site.client(Duration::from_secs(provider.timeout_secs) + REPLY_MARGIN)?;
    let url = reqwest::Url::parse(&provider.base_url)?;
    let prefix = url.path().trim_end_matches('/').to_owned();
    let catalog: BTreeMap<ModelId, LlmCatalogEntry> = catalog
        .into_iter()
        .map(|mut entry| {
            entry
                .capabilities
                .retain(|capability| *capability != LlmCapability::Streaming);
            (entry.model.clone(), entry)
        })
        .collect();
    let rows = catalog.values().cloned();
    let wire = match provider.kind {
        ProviderKind::AnthropicCompat => {
            Wire::Anthropic(AnthropicMessagesConfig::from_catalog(rows))
        }
        ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat => {
            Wire::OpenAi(OpenAiCompatConfig::from_catalog(rows))
        }
        ProviderKind::Oneironer => anyhow::bail!("a tagger provider sends no model call"),
        ProviderKind::Cartesia | ProviderKind::Elevenlabs | ProviderKind::Voxcpm2 => {
            anyhow::bail!("a speech provider sends no model call")
        }
        ProviderKind::Gemini => anyhow::bail!("a gemini provider sends media calls only"),
    };
    Ok(BrokerBackend {
        wire,
        cap,
        response_format: provider.response_format,
        origin: url.origin().ascii_serialization(),
        prefix,
        headers: provider
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect(),
        catalog,
        secret,
        client,
        keys,
    })
}

impl BrokerBackend {
    /// The call frame's header and the exact body bytes it carries, checked
    /// as the broker will check them. `call` is the broker's call id; the
    /// digest does not cover it.
    fn build(
        &self,
        request: &LlmRequest,
        stream: bool,
        call: &str,
    ) -> LlmResult<(CallHeader, Vec<u8>)> {
        if stream {
            return Err(no_streaming(&request.model));
        }
        let (shape, path, wire_headers, mut body) = match &self.wire {
            Wire::OpenAi(config) => {
                let wire = build_openai_chat_request(config, request, false)?;
                (Shape::OpenAiChat, wire.path, wire.headers, wire.body)
            }
            Wire::Anthropic(config) => {
                let wire = build_anthropic_messages_request(config, request, false)?;
                (Shape::AnthropicMessages, wire.path, wire.headers, wire.body)
            }
        };
        self.cap.apply(&mut body);
        super::openai::send_format(self.response_format, &mut body);
        let wire_model = self
            .catalog
            .get(&request.model)
            .and_then(|entry| entry.metadata.get("wire_model")?.as_str())
            .ok_or(FatalLlmError::InvalidRequest)?;
        let mut headers = self.headers.clone();
        for (name, value) in wire_headers {
            headers.insert(name.to_ascii_lowercase(), value);
        }
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        let bytes = serde_json::to_vec(&body).map_err(|_| FatalLlmError::InvalidRequest)?;
        let header = CallHeader::new(
            call.to_owned(),
            shape,
            self.origin.clone(),
            join(&self.prefix, &path),
            headers.into_iter().collect(),
            wire_model.to_owned(),
            &bytes,
        );
        header
            .check(&bytes)
            .map_err(|_| LlmError::from(FatalLlmError::InvalidRequest))?;
        Ok((header, bytes))
    }

    /// Connects to the broker (a host's broker must run as its user; the
    /// child gets its socket over its channel), reads the key at the door,
    /// and makes the one broker call. Nothing reads the key before the broker
    /// is reached.
    async fn send(
        &self,
        header: &CallHeader,
        body: &[u8],
    ) -> LlmResult<oneiron_broker::BrokerReply> {
        let connection = self.client.connect().await.map_err(broker_error)?;
        let keys = Arc::clone(&self.keys);
        let secret = self.secret.clone();
        let key = tokio::task::spawn_blocking(move || keys.read(&secret))
            .await
            .map_err(|_| LlmError::from(FatalLlmError::Auth))?
            .map_err(|_| {
                tracing::warn!(
                    reason = "key_custody_refused",
                    "the custody door refused a provider key"
                );
                LlmError::from(FatalLlmError::Auth)
            })?;
        connection
            .call(header, body, key)
            .await
            .map_err(broker_error)
    }

    /// The provider's answer as the adapter reads it.
    fn answer(&self, outcome: Outcome, body: &[u8]) -> LlmResult<LlmResponse> {
        let (status, headers) = match outcome {
            Outcome::Answered { status, headers } => (status, headers),
            // Nothing reached the provider.
            Outcome::Refused {
                reason: Refusal::Connect,
            } => return Err(RetryableLlmError::StreamCut.into()),
            Outcome::Refused { .. } => return Err(FatalLlmError::InvalidRequest.into()),
            Outcome::Failed {
                reason: Failure::Timeout,
            } => return Err(RetryableLlmError::Timeout.into()),
            Outcome::Failed {
                reason: Failure::Send,
            } => return Err(RetryableLlmError::StreamCut.into()),
            Outcome::Failed {
                reason: Failure::ReplyTooLarge | Failure::ReplyEncoded,
            } => return Err(RetryableLlmError::ServerError.into()),
        };
        let parsed = serde_json::from_slice::<JsonValue>(body);
        if !(200..300).contains(&status) {
            let headers: BTreeMap<String, String> = headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect();
            let body = parsed.unwrap_or(JsonValue::Null);
            return Err(match &self.wire {
                Wire::OpenAi(_) => classify_openai_status(status, &headers, &body),
                Wire::Anthropic(_) => classify_anthropic_status(status, &headers, &body),
            });
        }
        let mut body = parsed.map_err(|_| LlmError::from(RetryableLlmError::ServerError))?;
        match &self.wire {
            Wire::OpenAi(_) => {
                super::openai::carry_served_model(status, &mut body);
                parse_openai_chat_response(&body)
            }
            Wire::Anthropic(_) => {
                super::anthropic::carry_served_model(&mut body);
                parse_anthropic_messages_response(&body)
            }
        }
    }
}

/// The base URL's path prefix and a protocol path. A prefix that already
/// ends in `/v1` absorbs the path's own `/v1`, as the HTTP transport does.
fn join(prefix: &str, path: &str) -> String {
    match (prefix.strip_suffix("/v1"), path.strip_prefix("/v1/")) {
        (Some(base), Some(rest)) => format!("{base}/v1/{rest}"),
        _ => format!("{prefix}{path}"),
    }
}

fn no_streaming(model: &ModelId) -> LlmError {
    FatalLlmError::Unsupported(UnsupportedCapability {
        capability: LlmCapability::Streaming,
        model: Some(model.clone()),
        reason: Some("the credential broker sends whole replies only".to_owned()),
    })
    .into()
}

fn broker_error(error: BrokerError) -> LlmError {
    match error {
        // Nothing was written: no key read, no send.
        BrokerError::Unreachable => RetryableLlmError::StreamCut.into(),
        BrokerError::Peer => FatalLlmError::Auth.into(),
        BrokerError::Refused(_) => FatalLlmError::InvalidRequest.into(),
        // The call may have gone out: its reservation stays charged.
        BrokerError::Lost => RetryableLlmError::StreamCut.into(),
    }
}

/// One request per call: the broker sends once, with no retry and no
/// redirect, so a run's gate may wrap this backend.
impl SingleRouteBackend for BrokerBackend {
    /// Everything a call can fail on before anything is sent, short of the
    /// broker's own answer: the request, the broker (a host's socket, or the
    /// same-user child, started here at its first call, which can take a
    /// moment), and the custody binding. Each refuses the call before its
    /// permit starts.
    fn preflight(&self, request: &LlmRequest, stream: bool) -> LlmResult<()> {
        self.build(request, stream, "")?;
        // A call to no broker would fail before anything went out.
        if let Err(error) = self.client.ready() {
            tracing::warn!(%error, "no credential broker to send through");
            return Err(RetryableLlmError::StreamCut.into());
        }
        self.keys.check(&self.secret).map_err(|_| {
            tracing::warn!(
                reason = "key_custody_refused",
                "the custody door would refuse a provider key"
            );
            LlmError::from(FatalLlmError::Auth)
        })
    }

    fn request_digest(&self, request: &LlmRequest, stream: bool) -> LlmResult<Option<String>> {
        let (header, _) = self.build(request, stream, "")?;
        Ok(Some(header.digest))
    }

    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        Some(match self.client.isolation() {
            Isolation::SeparateUser => BrokerIsolation::SeparateUser,
            Isolation::SameUser => BrokerIsolation::SameUser,
        })
    }
}

impl LlmBackend for BrokerBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.catalog
            .get(model)
            .is_some_and(|entry| entry.supports(&capability))
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let (header, body) = self.build(&request, false, lease.id())?;
            let reply = self.send(&header, &body).await?;
            self.answer(reply.outcome, &reply.body)
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(no_streaming(&request.model))
    }
}
