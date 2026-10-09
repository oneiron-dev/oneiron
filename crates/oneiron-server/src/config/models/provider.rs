//! One provider entry: how to reach a model server, as data.
use std::collections::BTreeMap;

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
}

impl ProviderKind {
    /// Whether this kind answers `generate` calls on the LLM slot.
    #[must_use]
    pub fn generates(self) -> bool {
        !matches!(self, Self::Oneironer)
    }

    fn default_locality(self) -> ModelLocality {
        match self {
            Self::OpenaiCompat | Self::AnthropicCompat => ModelLocality::ThirdParty,
            Self::LocalOpenaiCompat | Self::Oneironer => ModelLocality::OwnServer,
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
            Self::LocalOpenaiCompat => {
                vec![LlmCapability::Streaming, LlmCapability::JsonResponse]
            }
            Self::AnthropicCompat => vec![
                LlmCapability::Streaming,
                LlmCapability::ToolCalling,
                LlmCapability::ToolResults,
            ],
            Self::Oneironer => Vec::new(),
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

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_CONTEXT_TOKENS: u64 = 128_000;
/// Headers that carry credentials. Keys arrive through `key_env`, never as a
/// literal in a config file.
const CREDENTIAL_HEADERS: [&str; 4] = [
    "authorization",
    "x-api-key",
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
    #[serde(default)]
    headers: BTreeMap<String, String>,
    timeout_secs: Option<u64>,
    context_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
    output_limit_field: Option<OutputLimitField>,
    capabilities: Option<Vec<LlmCapability>>,
    locality: Option<ModelLocality>,
    revision: Option<String>,
}

/// A validated provider entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    /// Origin plus any path prefix, with or without a trailing `/v1`.
    pub base_url: String,
    /// Name of the environment variable holding the key. `None` sends no key.
    pub key_env: Option<String>,
    /// Extra non-credential headers sent on every call.
    pub headers: BTreeMap<String, String>,
    pub timeout_secs: u64,
    pub context_tokens: u64,
    /// The ceiling on every call's output: filled in when a caller names no
    /// limit, and a larger one is cut to it.
    pub max_output_tokens: Option<u64>,
    /// Where an OpenAI-compatible endpoint reads that limit.
    pub output_limit_field: OutputLimitField,
    pub capabilities: Vec<LlmCapability>,
    /// Where calls to this provider run, for the engine's route checks.
    pub locality: ModelLocality,
    /// Revision stamped on every engine model id from this provider, so a
    /// change of served weights can be recorded as a new identity.
    pub revision: String,
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
        for header in self.headers.keys() {
            if CREDENTIAL_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
                anyhow::bail!(
                    "models.providers.{name}.headers.{header} would hold a credential; set key_env instead"
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
        Ok(ProviderConfig {
            kind,
            base_url,
            key_env: self.key_env,
            headers: self.headers,
            timeout_secs,
            context_tokens,
            max_output_tokens: self.max_output_tokens,
            output_limit_field: self.output_limit_field.unwrap_or_default(),
            capabilities: self
                .capabilities
                .unwrap_or_else(|| kind.default_capabilities()),
            locality: self.locality.unwrap_or_else(|| kind.default_locality()),
            revision,
        })
    }
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
