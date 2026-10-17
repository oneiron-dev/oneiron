//! One provider entry: how to reach a model server, as data.
use std::collections::BTreeMap;

use oneiron::llm::run_admission::{LeaseUnit, Payer, UnitRate};
use oneiron::{LlmCapability, ModelLocality};
use serde::Deserialize;

/// How the server talks to a provider. Every kind is reached over HTTP; none
/// names a vendor, so any compatible server fits (llama.cpp, vLLM, MLX, a
/// proxy, a hosted API).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    /// Any OpenAI-compatible `/v1/chat/completions` server.
    OpenaiCompat,
    /// Any Anthropic-compatible `/v1/messages` server.
    AnthropicCompat,
    /// An OpenAI-compatible server on this machine or its private network:
    /// your own endpoint, keyless by default.
    LocalOpenaiCompat,
    /// A retrieval tagger speaking the Oneironer slot contract. It serves the
    /// `extraction_encoder` role only and never generates text.
    Oneironer,
    /// Cartesia's speech API (`POST /tts/bytes`, `x-api-key`): a
    /// `[models.media.speech]` rung only.
    Cartesia,
    /// ElevenLabs' speech API (`POST /v1/text-to-speech/{voice}/stream`,
    /// `xi-api-key`): a `[models.media.speech]` rung only.
    Elevenlabs,
    /// An own-server VoxCPM2 worker (`deploy/voxcpm2`): it renders each
    /// call from the banked identity's reference clip, which the call
    /// carries, so it is reached over loopback HTTP only. A
    /// `[models.media.speech]` rung only.
    Voxcpm2,
    /// Google's Gemini API (`x-goog-api-key`), its origin as `base_url`: a
    /// `[models.media.image]` rung (`models/{model}:generateContent`, asked
    /// for image output) or a `[models.media.video]` rung (a Veo
    /// `predictLongRunning` job) only.
    Gemini,
    /// Soniox's real-time speech-to-text WebSocket
    /// (`wss://stt-rt.soniox.com/transcribe-websocket`, the key as a bearer
    /// on the upgrade only): a live `[models.media.transcribe]` rung only.
    Soniox,
}

impl ProviderKind {
    /// Whether this kind answers `generate` calls on the LLM slot.
    #[must_use]
    pub fn generates(self) -> bool {
        !matches!(self, Self::Oneironer) && !self.media_only()
    }

    /// Whether a `key_secret` key of this kind can leave through the
    /// credential broker: a chat wire's, or the Gemini API's media wire's.
    #[must_use]
    pub fn brokers(self) -> bool {
        self.generates() || matches!(self, Self::Gemini)
    }

    /// Whether this kind serves media seats and nothing else.
    #[must_use]
    pub fn media_only(self) -> bool {
        self.speech_only() || matches!(self, Self::Gemini | Self::Soniox)
    }

    /// Whether this kind is a hosted speech wire, which serves the speech
    /// media seat and nothing else.
    #[must_use]
    pub fn speech_only(self) -> bool {
        matches!(self, Self::Cartesia | Self::Elevenlabs | Self::Voxcpm2)
    }

    /// Whether this kind renders from a banked identity's reference clip on
    /// each call and keeps no clone of it.
    #[must_use]
    pub fn renders_from_refs(self) -> bool {
        matches!(self, Self::Voxcpm2)
    }

    /// Whether this kind serves the `reranker` role, over `/v1/rerank`.
    #[must_use]
    pub fn reranks(self) -> bool {
        matches!(self, Self::OpenaiCompat | Self::LocalOpenaiCompat)
    }

    fn default_locality(self) -> ModelLocality {
        match self {
            Self::OpenaiCompat
            | Self::AnthropicCompat
            | Self::Cartesia
            | Self::Elevenlabs
            | Self::Gemini
            | Self::Soniox => ModelLocality::ThirdParty,
            Self::LocalOpenaiCompat | Self::Oneironer | Self::Voxcpm2 => ModelLocality::OwnServer,
        }
    }

    fn default_capabilities(self) -> Vec<LlmCapability> {
        match self {
            Self::OpenaiCompat => vec![
                LlmCapability::Streaming,
                LlmCapability::JsonResponse,
                LlmCapability::ToolCalling,
                LlmCapability::ToolResults,
            ],
            // A local server takes a reasoning level: one serving a thinking
            // model reads it, one that is not ignores it.
            Self::LocalOpenaiCompat => vec![
                LlmCapability::Streaming,
                LlmCapability::JsonResponse,
                LlmCapability::Reasoning,
            ],
            Self::AnthropicCompat => vec![
                LlmCapability::Streaming,
                LlmCapability::ToolCalling,
                LlmCapability::ToolResults,
            ],
            Self::Oneironer
            | Self::Cartesia
            | Self::Elevenlabs
            | Self::Voxcpm2
            | Self::Gemini
            | Self::Soniox => Vec::new(),
        }
    }
}

/// The request field an OpenAI-compatible endpoint reads its output limit
/// from. Most servers (llama.cpp, vLLM, MLX, most proxies) read
/// `max_tokens`; some hosted reasoning models accept only
/// `max_completion_tokens`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputLimitField {
    #[default]
    MaxTokens,
    MaxCompletionTokens,
}

impl OutputLimitField {
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::MaxTokens => "max_tokens",
            Self::MaxCompletionTokens => "max_completion_tokens",
        }
    }
}

/// What an OpenAI-compatible endpoint is sent for a call that asks for JSON
/// in a schema: the schema in `response_format` (the default), or no
/// `response_format` at all, for a server run without schema-constrained
/// decoding. The answer meets the same validator either way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormatWire {
    #[default]
    Schema,
    #[serde(rename = "none")]
    Omitted,
}

/// Whether an OpenAI-compatible provider serves Responses over a held socket
/// (ARCH-0081 §5), as written: `true`, `false`, or the socket's age limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub(super) enum ResponsesSocketFile {
    Switch(bool),
    Limits { max_age_secs: u64 },
}

/// A provider's Responses socket: each call runs as one response on a held
/// socket, and the socket is replaced before it reaches its age limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponsesSocket {
    pub max_age_secs: u64,
}

/// The origins known to serve Responses over a socket, with each socket's age
/// limit (ARCH-0081 §5): an OpenAI-compatible provider at one holds a socket
/// unless its entry says `responses_socket = false`. Any other origin (a CPA
/// route, say) holds one only when its entry asks.
const RESPONSES_SOCKET_ORIGINS: [(&str, u64); 2] =
    [("https://api.openai.com", 3600), ("https://api.x.ai", 3540)];
/// The age limit of a socket an entry asks for with `true` at an origin not
/// in [`RESPONSES_SOCKET_ORIGINS`]: the shorter of the two known limits.
const DEFAULT_RESPONSES_SOCKET_AGE_SECS: u64 = 3540;

/// A provider's request compression as written: `false`, or the codec its
/// route decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub(super) enum RequestCompressionFile {
    Switch(bool),
    Codec(RequestCodec),
}

/// The codec a provider's JSON request bodies go in (ARCH-0081 §6). Replies
/// do not change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestCodec {
    /// gzip at level 1.
    Gzip,
    /// zstd at level 3.
    Zstd,
}

/// Request compression for one provider: bodies of 16 KiB or more posted to
/// `route` (every route when `None`) go in `codec`, when that is smaller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestCompression {
    pub codec: RequestCodec,
    pub route: Option<&'static str>,
}

/// The routes known to decode a compressed request (ARCH-0081 §6's
/// allowlist): an Anthropic-compatible provider at the origin compresses
/// there unless its entry says `request_compression = false`. Any other
/// route (our CPA agents route, say) compresses only when its entry names a
/// codec, and then on every route it posts to.
const REQUEST_COMPRESSION_ROUTES: [(ProviderKind, &str, &str, RequestCodec); 1] = [(
    ProviderKind::AnthropicCompat,
    "https://api.anthropic.com",
    "/v1/messages",
    RequestCodec::Gzip,
)];

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_CONTEXT_TOKENS: u64 = 128_000;
/// Headers that carry credentials. Keys arrive through `key_env` or
/// `key_secret`, never as a literal in a config file.
const CREDENTIAL_HEADERS: [&str; 5] = [
    "authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
    "proxy-authorization",
];

/// `[models.providers.<name>]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderFile {
    kind: Option<ProviderKind>,
    base_url: Option<String>,
    key_env: Option<String>,
    key_secret: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    timeout_secs: Option<u64>,
    context_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
    output_limit_field: Option<OutputLimitField>,
    response_format: Option<ResponseFormatWire>,
    capabilities: Option<Vec<LlmCapability>>,
    #[serde(default)]
    model_capabilities: BTreeMap<String, Vec<LlmCapability>>,
    family: Option<String>,
    #[serde(default)]
    model_families: BTreeMap<String, String>,
    locality: Option<ModelLocality>,
    revision: Option<String>,
    payer: Option<Payer>,
    #[serde(default)]
    rates: Vec<UnitRate>,
    responses_socket: Option<ResponsesSocketFile>,
    request_compression: Option<RequestCompressionFile>,
}

/// A validated provider entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    /// Origin plus any path prefix, with or without a trailing `/v1`.
    pub base_url: String,
    /// Name of the environment variable holding the key. `None` sends no key.
    pub key_env: Option<String>,
    /// Name of the vault secret holding the key instead (ARCH-0069
    /// `#broker-design`). The key stays in the vault's custody at T0: each
    /// call reads it at the custody door and hands it, with that one request,
    /// to the credential broker `[models.broker]` names, which sends it.
    pub key_secret: Option<String>,
    /// Extra non-credential headers sent on every call.
    pub headers: BTreeMap<String, String>,
    pub timeout_secs: u64,
    pub context_tokens: u64,
    /// The ceiling on every call's output: filled in when a caller names no
    /// limit, and a larger one is cut to it.
    pub max_output_tokens: Option<u64>,
    /// Where an OpenAI-compatible endpoint reads that limit.
    pub output_limit_field: OutputLimitField,
    /// Whether an OpenAI-compatible endpoint is sent a JSON call's schema.
    pub response_format: ResponseFormatWire,
    pub capabilities: Vec<LlmCapability>,
    /// One wire model's own capabilities, in place of `capabilities`, so two
    /// models on one provider can differ (one hears audio, one does not).
    pub model_capabilities: BTreeMap<String, Vec<LlmCapability>>,
    /// The family of models (the line one developer trains) every model on
    /// this provider belongs to, unless `model_families` names its own.
    /// Unset, a model's family is unknown: a provider or proxy name is not
    /// its developer.
    pub family: Option<String>,
    /// One wire model's own family, in place of `family`.
    pub model_families: BTreeMap<String, String>,
    /// Where calls to this provider run, for the engine's route checks.
    pub locality: ModelLocality,
    /// Revision stamped on every engine model id from this provider, so a
    /// change of served weights can be recorded as a new identity.
    pub revision: String,
    /// An explicit host binding; absent config keeps the own-key/local default.
    pub payer: Payer,
    /// Host-supplied token conversions for the allocation's named unit.
    pub rates: Vec<UnitRate>,
    /// The Responses socket an OpenAI-compatible provider's calls hold, or
    /// `None` for the chat HTTP path alone. A broker-held key always takes
    /// HTTP: the broker runs no socket yet.
    pub responses_socket: Option<ResponsesSocket>,
    /// How this provider's JSON request bodies are compressed, or `None` to
    /// send them plain. A broker-held key has none here: the broker
    /// compresses on its own route, Anthropic's Messages API.
    pub request_compression: Option<RequestCompression>,
}

impl ProviderFile {
    pub(super) fn resolve(self, name: &str) -> anyhow::Result<ProviderConfig> {
        let kind = self
            .kind
            .ok_or_else(|| anyhow::anyhow!("models.providers.{name}.kind is required"))?;
        let base_url = self
            .base_url
            .map(|url| url.trim().trim_end_matches('/').to_owned())
            .filter(|url| !url.is_empty())
            .ok_or_else(|| anyhow::anyhow!("models.providers.{name}.base_url is required"))?;
        validate_base_url(name, kind, &base_url)?;
        if let Some(key_env) = &self.key_env
            && !is_env_name(key_env)
        {
            anyhow::bail!(
                "models.providers.{name}.key_env must name an environment variable (A-Z, 0-9, _); put the key itself in that variable, never in the config file"
            );
        }
        if let Some(key_secret) = &self.key_secret {
            validate_key_secret(name, kind, &base_url, key_secret, self.key_env.is_some())?;
        }
        // The live socket sends its key as the upgrade's bearer, read from the
        // environment; there is no keyless Soniox.
        if kind == ProviderKind::Soniox && self.key_env.is_none() {
            anyhow::bail!("models.providers.{name}.key_env is required for a soniox provider");
        }
        for header in self.headers.keys() {
            if CREDENTIAL_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
                anyhow::bail!(
                    "models.providers.{name}.headers.{header} would hold a credential; set key_env or key_secret instead"
                );
            }
        }
        let timeout_secs = self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if timeout_secs == 0 {
            anyhow::bail!("models.providers.{name}.timeout_secs must be greater than zero");
        }
        let context_tokens = self.context_tokens.unwrap_or(DEFAULT_CONTEXT_TOKENS);
        if context_tokens == 0 || self.max_output_tokens == Some(0) {
            anyhow::bail!("models.providers.{name} token limits must be greater than zero");
        }
        if self.output_limit_field.is_some()
            && !matches!(
                kind,
                ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat
            )
        {
            anyhow::bail!(
                "models.providers.{name}.output_limit_field applies to OpenAI-compatible providers only"
            );
        }
        if self.response_format.is_some()
            && !matches!(
                kind,
                ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat
            )
        {
            anyhow::bail!(
                "models.providers.{name}.response_format applies to OpenAI-compatible providers only"
            );
        }
        if self.locality == Some(ModelLocality::OnDevice) {
            anyhow::bail!(
                "models.providers.{name}.locality: on_device names an in-process runtime; a model server reached over HTTP, even on this machine, is own_server"
            );
        }
        let revision = self.revision.unwrap_or_else(|| "live".to_owned());
        if !is_id_segment(name) || !is_id_segment(&revision) {
            anyhow::bail!(
                "models.providers.{name}: the provider name and revision may use only A-Z, a-z, 0-9, '.', '-' and '_'"
            );
        }
        if self
            .model_capabilities
            .keys()
            .any(|model| model.trim().is_empty())
        {
            anyhow::bail!("models.providers.{name}.model_capabilities names a blank model");
        }
        if self.family.iter().any(|family| family.trim().is_empty())
            || self
                .model_families
                .iter()
                .any(|(model, family)| model.trim().is_empty() || family.trim().is_empty())
        {
            anyhow::bail!("models.providers.{name}: a family and the model it names are not blank");
        }
        for rate in &self.rates {
            if rate.per == 0 || LeaseUnit::new(rate.unit.as_str()).is_err() {
                anyhow::bail!(
                    "models.providers.{name}.rates requires a valid unit and nonzero per"
                );
            }
        }
        let responses_socket = responses_socket(
            name,
            kind,
            &base_url,
            self.key_secret.is_some(),
            self.responses_socket,
        )?;
        let request_compression = request_compression(
            name,
            kind,
            &base_url,
            self.key_secret.is_some(),
            self.request_compression,
        )?;
        let payer = self.payer.unwrap_or_else(|| {
            if self.key_env.is_some() || self.key_secret.is_some() {
                Payer::CustomerKey
            } else {
                Payer::Local
            }
        });
        Ok(ProviderConfig {
            kind,
            base_url,
            key_env: self.key_env,
            key_secret: self.key_secret,
            headers: self.headers,
            timeout_secs,
            context_tokens,
            max_output_tokens: self.max_output_tokens,
            output_limit_field: self.output_limit_field.unwrap_or_default(),
            response_format: self.response_format.unwrap_or_default(),
            capabilities: self
                .capabilities
                .unwrap_or_else(|| kind.default_capabilities()),
            model_capabilities: self.model_capabilities,
            family: self.family.map(|family| family.trim().to_owned()),
            model_families: self
                .model_families
                .into_iter()
                .map(|(model, family)| (model, family.trim().to_owned()))
                .collect(),
            locality: self.locality.unwrap_or_else(|| kind.default_locality()),
            revision,
            payer,
            rates: self.rates,
            responses_socket,
            request_compression,
        })
    }
}

/// Whether a kind's request bodies can go compressed: a chat wire's, and
/// our own VoxCPM2 worker's render uploads, which it decodes (OF-604, D1).
fn compresses(kind: ProviderKind) -> bool {
    kind.generates() || kind == ProviderKind::Voxcpm2
}

/// The request compression an entry has: what it wrote, else its route's in
/// [`REQUEST_COMPRESSION_ROUTES`]. A broker-held key has none: the broker
/// picks its own, and an entry's codec does not reach it.
fn request_compression(
    name: &str,
    kind: ProviderKind,
    base_url: &str,
    brokered: bool,
    file: Option<RequestCompressionFile>,
) -> anyhow::Result<Option<RequestCompression>> {
    let known = REQUEST_COMPRESSION_ROUTES
        .iter()
        .find(|(known_kind, origin, _, _)| {
            *known_kind == kind
                && base_url
                    .strip_prefix(origin)
                    .is_some_and(|rest| rest.is_empty() || rest == "/v1")
        })
        .map(|&(_, _, route, codec)| RequestCompression {
            codec,
            route: Some(route),
        });
    let compression = match file {
        None => known,
        Some(RequestCompressionFile::Switch(false)) => None,
        Some(RequestCompressionFile::Switch(true)) => Some(known.ok_or_else(|| {
            anyhow::anyhow!(
                "models.providers.{name}.request_compression = true needs a known route; name the codec (\"gzip\" or \"zstd\") this route decodes"
            )
        })?),
        Some(RequestCompressionFile::Codec(codec)) => Some(RequestCompression {
            codec,
            route: known.and_then(|known| known.route),
        }),
    };
    if compression.is_some() && (brokered || !compresses(kind)) {
        if file.is_some() && kind == ProviderKind::Oneironer {
            anyhow::bail!(
                "models.providers.{name}.request_compression: a tagger's requests go to oneironer.url; set oneironer.request_compression there"
            );
        }
        if file.is_some() {
            anyhow::bail!(
                "models.providers.{name}.request_compression applies to a generating or VoxCPM2 provider whose key is not key_secret"
            );
        }
        return Ok(None);
    }
    Ok(compression)
}

/// The Responses socket an entry holds: what it wrote, else the default its
/// origin has. Only a hosted OpenAI-compatible provider whose key is not the
/// broker's holds one.
fn responses_socket(
    name: &str,
    kind: ProviderKind,
    base_url: &str,
    brokered: bool,
    file: Option<ResponsesSocketFile>,
) -> anyhow::Result<Option<ResponsesSocket>> {
    let known = RESPONSES_SOCKET_ORIGINS
        .iter()
        .find(|(origin, _)| {
            base_url
                .strip_prefix(origin)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .map(|&(_, max_age_secs)| max_age_secs);
    let max_age_secs = match file {
        None => known,
        Some(ResponsesSocketFile::Switch(false)) => None,
        Some(ResponsesSocketFile::Switch(true)) => {
            Some(known.unwrap_or(DEFAULT_RESPONSES_SOCKET_AGE_SECS))
        }
        Some(ResponsesSocketFile::Limits { max_age_secs }) => Some(max_age_secs),
    };
    let Some(max_age_secs) = max_age_secs else {
        return Ok(None);
    };
    if kind != ProviderKind::OpenaiCompat || brokered {
        if file.is_some() {
            anyhow::bail!(
                "models.providers.{name}.responses_socket applies to an openai-compat provider whose key is not key_secret"
            );
        }
        return Ok(None);
    }
    if max_age_secs == 0 {
        anyhow::bail!(
            "models.providers.{name}.responses_socket.max_age_secs must be greater than zero"
        );
    }
    Ok(Some(ResponsesSocket { max_age_secs }))
}

/// A key the credential broker sends: one way to name the key, a generating
/// provider, and an `https` origin, the only scheme the broker sends to.
fn validate_key_secret(
    name: &str,
    kind: ProviderKind,
    base_url: &str,
    key_secret: &str,
    has_key_env: bool,
) -> anyhow::Result<()> {
    if has_key_env {
        anyhow::bail!("models.providers.{name}: set key_env or key_secret, not both");
    }
    if key_secret.is_empty()
        || key_secret.len() > 256
        || !key_secret.bytes().all(|b| b.is_ascii_graphic())
    {
        anyhow::bail!(
            "models.providers.{name}.key_secret must name a vault secret (printable ASCII, no spaces); put the key itself in the vault, never in the config file"
        );
    }
    if !kind.brokers() {
        anyhow::bail!(
            "models.providers.{name}.key_secret applies to generating and gemini providers only"
        );
    }
    if !base_url.starts_with("https://") {
        anyhow::bail!(
            "models.providers.{name}.key_secret: the credential broker sends over https only"
        );
    }
    Ok(())
}

fn validate_base_url(name: &str, kind: ProviderKind, url: &str) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|error| anyhow::anyhow!("models.providers.{name}.base_url: {error}"))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!(
            "models.providers.{name}.base_url carries credentials, a query or a fragment; use key_env and a plain URL"
        );
    }
    // The VoxCPM2 worker takes the person's raw voice with every call: its
    // own wire refuses anything but loopback HTTP on a port, so does this.
    if kind == ProviderKind::Voxcpm2
        && (parsed.scheme() != "http"
            || parsed.host_str() != Some("127.0.0.1")
            || parsed.port().is_none()
            || parsed.path() != "/")
    {
        anyhow::bail!(
            "models.providers.{name}.base_url: a voxcpm2 worker is reached at http://127.0.0.1:<port> only"
        );
    }
    // Soniox's live socket is a TLS WebSocket and nothing else; no other
    // kind takes a ws(s) origin.
    if kind == ProviderKind::Soniox {
        if parsed.scheme() != "wss" {
            anyhow::bail!(
                "models.providers.{name}.base_url: a soniox provider is reached at a wss:// URL only"
            );
        }
        return Ok(());
    }
    let near = host_is_near(&parsed);
    match (parsed.scheme(), kind) {
        ("https", _) => Ok(()),
        ("http", ProviderKind::LocalOpenaiCompat | ProviderKind::Oneironer) if near => Ok(()),
        ("http", _) if host_is_loopback(&parsed) => Ok(()),
        ("http", _) => anyhow::bail!(
            "models.providers.{name}.base_url must use https unless it is on this machine"
        ),
        (scheme, _) => {
            anyhow::bail!("models.providers.{name}.base_url scheme {scheme} is not http(s)")
        }
    }
}

enum UrlHost<'a> {
    Name(&'a str),
    Ip(std::net::IpAddr),
}

fn url_host(url: &reqwest::Url) -> Option<UrlHost<'_>> {
    let host = url.host_str()?;
    Some(
        match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
            Ok(ip) => UrlHost::Ip(ip),
            Err(_) => UrlHost::Name(host),
        },
    )
}

fn host_is_loopback(url: &reqwest::Url) -> bool {
    match url_host(url) {
        Some(UrlHost::Name(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(UrlHost::Ip(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// This machine or its private network: the hosts a local model server
/// (llama.cpp, vLLM, MLX) is reached on over plain HTTP.
fn host_is_near(url: &reqwest::Url) -> bool {
    match url_host(url) {
        Some(UrlHost::Name(host)) => {
            host.eq_ignore_ascii_case("localhost")
                || host.ends_with(".local")
                || host.ends_with(".lan")
        }
        Some(UrlHost::Ip(std::net::IpAddr::V4(ip))) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local()
        }
        Some(UrlHost::Ip(std::net::IpAddr::V6(ip))) => ip.is_loopback() || ip.is_unique_local(),
        None => false,
    }
}

fn is_env_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

pub(super) fn is_id_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
