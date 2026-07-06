//! Engine-facing LLM invocation seam.
//!
//! This module defines the shared request, response, streaming, usage, error,
//! and catalog types consumed by engine callers and host-supplied adapters. It
//! intentionally contains no provider implementation or inference dependency.

mod budget;

pub use budget::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetAdmission, BudgetExhaustionPolicy, BudgetGuard, BudgetLadderEvent, BudgetPromptTemplate,
    BudgetRead, BudgetSettlement, BudgetSignalDeliveryChannel, BudgetSteeringSignal,
    BudgetThreshold, DEFAULT_BUDGET_RESERVE_UNITS,
};

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use futures_core::Stream;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::types::bytes_to_hex_lower;

pub type LlmResult<T> = std::result::Result<T, LlmError>;
pub type LlmGenerateFuture<'a> = Pin<Box<dyn Future<Output = LlmResult<LlmResponse>> + Send + 'a>>;
pub type LlmStreamResult<'a> = LlmResult<LlmStream<'a>>;

/// Stream wrapper that makes [`LlmStreamEvent::Done`] the only successful EOF.
pub struct LlmStream<'a> {
    inner: Pin<Box<dyn Stream<Item = LlmResult<LlmStreamEvent>> + Send + 'a>>,
    terminal_seen: bool,
}

impl<'a> LlmStream<'a> {
    pub fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = LlmResult<LlmStreamEvent>> + Send + 'a,
    {
        Self {
            inner: Box::pin(stream),
            terminal_seen: false,
        }
    }
}

impl Stream for LlmStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminal_seen {
            return Poll::Ready(None);
        }

        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                if matches!(event, LlmStreamEvent::Done { .. }) {
                    this.terminal_seen = true;
                }
                Poll::Ready(Some(Ok(event)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.terminal_seen = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.terminal_seen = true;
                Poll::Ready(Some(Err(RetryableLlmError::StreamCut.into())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Raw-call primitive implemented by host-injected adapters.
///
/// The required [`BudgetLease`] argument makes budget admission visible in the
/// type signature. Budget policy, retry policy, durable memoization, and agent
/// loop behavior live above this trait.
pub trait LlmBackend: Send + Sync {
    fn generate<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease)
    -> LlmGenerateFuture<'a>;

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a>;
}

/// Opaque admission token issued by the budget guard.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BudgetLease {
    pub(crate) id: String,
}

impl BudgetLease {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn issued(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn for_test(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Validated `provider/name@revision` model identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelId(String);

impl ModelId {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, ModelIdError> {
        value.into().parse()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        self.0
            .split_once('/')
            .expect("validated model id has provider separator")
            .0
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.0
            .split_once('/')
            .expect("validated model id has provider separator")
            .1
            .rsplit_once('@')
            .expect("validated model id has revision separator")
            .0
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        self.0
            .rsplit_once('@')
            .expect("validated model id has revision separator")
            .1
    }
}

impl fmt::Display for ModelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ModelId {
    type Err = ModelIdError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (provider, remainder) = value
            .split_once('/')
            .ok_or(ModelIdError::MissingProviderSeparator)?;
        let (name, revision) = remainder
            .rsplit_once('@')
            .ok_or(ModelIdError::MissingRevisionSeparator)?;

        validate_model_id_segment(provider, ModelIdSegment::Provider)?;
        validate_model_id_segment(name, ModelIdSegment::Name)?;
        validate_model_id_segment(revision, ModelIdSegment::Revision)?;

        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for ModelId {
    type Error = ModelIdError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for ModelId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ModelId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ModelIdVisitor;

        impl Visitor<'_> for ModelIdVisitor {
            type Value = ModelId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a provider/name@revision model identifier")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ModelIdVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelIdError {
    #[error("model id must contain provider/name")]
    MissingProviderSeparator,
    #[error("model id must contain @revision")]
    MissingRevisionSeparator,
    #[error("model id {segment} segment is empty")]
    EmptySegment { segment: &'static str },
    #[error("model id contains an invalid character in {segment}")]
    InvalidCharacter { segment: &'static str },
}

#[derive(Debug, Clone, Copy)]
enum ModelIdSegment {
    Provider,
    Name,
    Revision,
}

impl ModelIdSegment {
    fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Name => "name",
            Self::Revision => "revision",
        }
    }
}

fn validate_model_id_segment(
    value: &str,
    segment: ModelIdSegment,
) -> std::result::Result<(), ModelIdError> {
    if value.is_empty() {
        return Err(ModelIdError::EmptySegment {
            segment: segment.as_str(),
        });
    }

    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(ModelIdError::InvalidCharacter {
            segment: segment.as_str(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmRequest {
    pub model: ModelId,
    pub envelope: CallEnvelope,
    pub messages: Vec<LlmMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<LlmToolSpec>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, JsonValue>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_options: BTreeMap<String, JsonValue>,
}

impl LlmRequest {
    /// Canonical JSON bytes used as the durable BLAKE3 request-key input.
    ///
    /// Struct and JSON-object fields are recursively sorted by key, while
    /// arrays retain order because message, content, and tool order are
    /// semantic.
    pub fn canonical_bytes(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
        canonical_json_bytes(self)
    }

    pub fn canonical_hash(&self) -> std::result::Result<[u8; 32], serde_json::Error> {
        let bytes = self.canonical_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    pub fn canonical_hash_hex(&self) -> std::result::Result<String, serde_json::Error> {
        let bytes = self.canonical_hash()?;
        Ok(bytes_to_hex_lower(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmResponse {
    pub message: LlmMessage,
    pub usage: LlmUsage,
    pub finish_reason: FinishReason,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: LlmMessageRole,
    pub content: Vec<ContentPart>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmMessageRole {
    System,
    User,
    Assistant,
    Tool,
}

/// Bidirectional content representation shared by history-in and generation-out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentPart {
    Text {
        text: String,
    },
    Reasoning {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    ToolCall {
        call_id: String,
        name: String,
        input: JsonValue,
    },
    ToolResult {
        call_id: String,
        output: JsonValue,
        #[serde(default)]
        is_error: bool,
    },
    Image {
        media_type: String,
        image: ImageContent,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ImageContent {
    Base64 { data: String },
    Url { url: String },
}

/// Typed stream events. Deltas are transient; only [`Self::Done`] is durable.
///
/// Adapters must not emit [`Self::Done`] for a successful empty response; they
/// should report [`FatalLlmError::EmptyResponse`] instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LlmStreamEvent {
    TextStart {
        part_id: String,
    },
    TextDelta {
        part_id: String,
        text: String,
    },
    TextEnd {
        part_id: String,
    },
    ReasoningStart {
        part_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    ReasoningDelta {
        part_id: String,
        text: String,
    },
    ReasoningEnd {
        part_id: String,
    },
    ToolCallStart {
        part_id: String,
        call_id: String,
        name: String,
    },
    ToolCallDelta {
        part_id: String,
        input_fragment: String,
    },
    ToolCallEnd {
        part_id: String,
        call_id: String,
        name: String,
        input: JsonValue,
    },
    ToolResultStart {
        part_id: String,
        call_id: String,
    },
    ToolResultDelta {
        part_id: String,
        output_fragment: String,
    },
    ToolResultEnd {
        part_id: String,
        call_id: String,
        output: JsonValue,
        #[serde(default)]
        is_error: bool,
    },
    ImageStart {
        part_id: String,
        media_type: String,
    },
    ImageDelta {
        part_id: String,
        data_fragment: String,
    },
    ImageEnd {
        part_id: String,
        media_type: String,
        image: ImageContent,
    },
    Done {
        message: LlmMessage,
        usage: LlmUsage,
        finish_reason: FinishReason,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmUsage {
    pub input: LlmInputUsage,
    pub output: LlmOutputUsage,
    pub raw_provider: JsonValue,
}

impl LlmUsage {
    #[must_use]
    pub fn zero() -> Self {
        Self {
            input: LlmInputUsage::default(),
            output: LlmOutputUsage::default(),
            raw_provider: JsonValue::Null,
        }
    }
}

/// Absolute per-job input token totals, never retry deltas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LlmInputUsage {
    pub total: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

/// Absolute per-job output token totals, never retry deltas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LlmOutputUsage {
    pub total: u64,
    pub text: u64,
    pub reasoning: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallEnvelope {
    pub purpose: CallPurpose,
    pub class: CallClass,
    pub tier: TierPrecedence,
    pub response_format: ResponseFormat,
    pub locality: ModelLocality,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallPurpose {
    Extraction,
    Consolidation,
    AnswerGen,
    AutoCheck,
    ToolRouting,
    Voice,
    Eval,
    Other { name: String },
}

const ORCHESTRATOR_DEFAULT_MODEL_ID: &str = "openai/gpt-4.1@2026-07-02";
const SUBAGENT_DEFAULT_MODEL_ID: &str = "openai/gpt-4.1-mini@2026-07-02";
const SUMMARIZER_DEFAULT_MODEL_ID: &str = "openai/gpt-4.1-nano@2026-07-02";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmRole {
    Orchestrator,
    Subagent,
    Summarizer,
}

impl LlmRole {
    #[must_use]
    pub const fn default_model_id_str(self) -> &'static str {
        match self {
            Self::Orchestrator => ORCHESTRATOR_DEFAULT_MODEL_ID,
            Self::Subagent => SUBAGENT_DEFAULT_MODEL_ID,
            Self::Summarizer => SUMMARIZER_DEFAULT_MODEL_ID,
        }
    }

    #[must_use]
    pub fn default_model_id(self) -> ModelId {
        validated_static_model_id(self.default_model_id_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleModelDefaults {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<LlmRole, ModelId>,
}

impl Default for RoleModelDefaults {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleModelDefaults {
    #[must_use]
    pub fn new() -> Self {
        Self {
            overrides: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_override(mut self, role: LlmRole, model: ModelId) -> Self {
        let _ = self.set_override(role, model);
        self
    }

    pub fn set_override(&mut self, role: LlmRole, model: ModelId) -> Option<ModelId> {
        self.overrides.insert(role, model)
    }

    #[must_use]
    pub fn override_for(&self, role: LlmRole) -> Option<&ModelId> {
        self.overrides.get(&role)
    }

    #[must_use]
    pub fn resolve(&self, role: LlmRole) -> ModelId {
        self.override_for(role)
            .cloned()
            .unwrap_or_else(|| role.default_model_id())
    }
}

fn validated_static_model_id(value: &'static str) -> ModelId {
    ModelId::new(value)
        .unwrap_or_else(|error| unreachable!("hard-coded model id {value:?} is invalid: {error}"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallClass {
    Durable { fallback: DeterministicFallback },
    BestEffort,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeterministicFallback {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModelTierRef(pub String);

impl ModelTierRef {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Resolution inputs in precedence order:
/// per-call override -> vault policy manifest -> purpose default -> global.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierPrecedence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_call: Option<ModelTierRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_policy: Option<ModelTierRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_default: Option<ModelTierRef>,
    pub global_default: ModelTierRef,
}

impl TierPrecedence {
    #[must_use]
    pub fn resolved(&self) -> &ModelTierRef {
        self.per_call
            .as_ref()
            .or(self.vault_policy.as_ref())
            .or(self.purpose_default.as_ref())
            .unwrap_or(&self.global_default)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum ResponseFormat {
    Text,
    Json { schema: JsonValue },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLocality {
    OnDevice,
    OwnServer,
    ThirdParty,
}

pub const DEFAULT_SAFEGUARD_MODEL_BINDING: &str = "gpt-oss-safeguard-20b";
pub const DEFAULT_ON_DEVICE_SAFEGUARD_TIER: &str = "qwen3guard-stream-0.6b";

/// Config selector for OF-333 safeguard-class classifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum SafeguardModelBinding {
    #[default]
    GptOssSafeguard20b,
    OpenRouter {
        model: String,
    },
    Endpoint {
        url: String,
    },
    OnDevice {
        tier: String,
    },
}

impl SafeguardModelBinding {
    pub fn parse(value: &str) -> std::result::Result<Self, SafeguardModelBindingError> {
        value.parse()
    }

    #[must_use]
    pub fn selector(&self) -> String {
        match self {
            Self::GptOssSafeguard20b => DEFAULT_SAFEGUARD_MODEL_BINDING.to_owned(),
            Self::OpenRouter { model } => format!("openrouter:{model}"),
            Self::Endpoint { url } => format!("endpoint:{url}"),
            Self::OnDevice { tier } => format!("on-device:{tier}"),
        }
    }

    #[must_use]
    pub fn locality(&self) -> ModelLocality {
        match self {
            Self::GptOssSafeguard20b | Self::OpenRouter { .. } => ModelLocality::ThirdParty,
            Self::Endpoint { .. } => ModelLocality::OwnServer,
            Self::OnDevice { .. } => ModelLocality::OnDevice,
        }
    }

    #[must_use]
    pub fn tier_ref(&self) -> ModelTierRef {
        ModelTierRef(self.selector())
    }

    #[must_use]
    pub fn llm_model_id(&self) -> ModelId {
        let value = match self {
            Self::GptOssSafeguard20b => "oneiron/gpt-oss-safeguard-20b@default",
            Self::OpenRouter { .. } => "openrouter/safeguard@configured",
            Self::Endpoint { .. } => "endpoint/safeguard@configured",
            Self::OnDevice { .. } => "on-device/safeguard@configured",
        };
        validated_static_model_id(value)
    }
}

impl fmt::Display for SafeguardModelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.selector())
    }
}

impl FromStr for SafeguardModelBinding {
    type Err = SafeguardModelBindingError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed == DEFAULT_SAFEGUARD_MODEL_BINDING {
            return Ok(Self::GptOssSafeguard20b);
        }
        if let Some(model) = trimmed.strip_prefix("openrouter:") {
            if model.trim().is_empty() {
                return Err(SafeguardModelBindingError::EmptySelector {
                    prefix: "openrouter",
                });
            }
            return Ok(Self::OpenRouter {
                model: model.trim().to_owned(),
            });
        }
        if let Some(url) = trimmed.strip_prefix("endpoint:") {
            if url.trim().is_empty() {
                return Err(SafeguardModelBindingError::EmptySelector { prefix: "endpoint" });
            }
            return Ok(Self::Endpoint {
                url: url.trim().to_owned(),
            });
        }
        if trimmed == "on-device" {
            return Ok(Self::OnDevice {
                tier: DEFAULT_ON_DEVICE_SAFEGUARD_TIER.to_owned(),
            });
        }
        if let Some(tier) = trimmed.strip_prefix("on-device:") {
            if tier.trim().is_empty() {
                return Err(SafeguardModelBindingError::EmptySelector {
                    prefix: "on-device",
                });
            }
            return Ok(Self::OnDevice {
                tier: tier.trim().to_owned(),
            });
        }
        Err(SafeguardModelBindingError::UnknownSelector)
    }
}

impl Serialize for SafeguardModelBinding {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.selector())
    }
}

impl<'de> Deserialize<'de> for SafeguardModelBinding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BindingVisitor;

        impl Visitor<'_> for BindingVisitor {
            type Value = SafeguardModelBinding;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a safeguard binding selector")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(BindingVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafeguardModelBindingError {
    #[error("unknown safeguard model binding selector")]
    UnknownSelector,
    #[error("{prefix} safeguard model binding selector is empty")]
    EmptySelector { prefix: &'static str },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFiltered,
    Cancelled,
    Other { name: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, thiserror::Error)]
pub enum LlmError {
    #[error("retryable LLM error: {0}")]
    Retryable(#[from] RetryableLlmError),
    #[error("fatal LLM error: {0}")]
    Fatal(#[from] FatalLlmError),
    #[error("LLM budget denied: {0}")]
    BudgetDenied(#[from] BudgetDenied),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum RetryableLlmError {
    #[error("rate limited")]
    RateLimited {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
    },
    #[error("server error")]
    ServerError,
    #[error("timeout")]
    Timeout,
    #[error("stream cut")]
    StreamCut,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum FatalLlmError {
    #[error("invalid request")]
    InvalidRequest,
    #[error("authentication failed")]
    Auth,
    #[error("content filtered")]
    ContentFiltered,
    #[error("empty response")]
    EmptyResponse,
    #[error("unsupported capability: {0}")]
    Unsupported(UnsupportedCapability),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum BudgetDenied {
    #[error("budget exhausted")]
    Exhausted,
    #[error("lease invalid")]
    LeaseInvalid,
    #[error("admission denied")]
    AdmissionDenied,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnsupportedCapability {
    pub capability: LlmCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl fmt::Display for UnsupportedCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.capability)?;
        if let Some(model) = &self.model {
            write!(f, " for {model}")?;
        }
        if let Some(reason) = &self.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmCapability {
    Streaming,
    ToolCalling,
    ToolResults,
    ImageInput,
    JsonResponse,
    Reasoning,
    Voice,
}

impl LlmCapability {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Streaming => "streaming",
            Self::ToolCalling => "tool_calling",
            Self::ToolResults => "tool_results",
            Self::ImageInput => "image_input",
            Self::JsonResponse => "json_response",
            Self::Reasoning => "reasoning",
            Self::Voice => "voice",
        }
    }
}

impl fmt::Display for LlmCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmCatalogEntry {
    pub model: ModelId,
    pub display_name: String,
    pub locality: ModelLocality,
    pub context_window_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<LlmCatalogCost>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<LlmCapability>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, JsonValue>,
}

impl LlmCatalogEntry {
    #[must_use]
    pub fn supports(&self, capability: &LlmCapability) -> bool {
        self.capabilities.iter().any(|entry| entry == capability)
    }

    pub fn require(&self, capability: LlmCapability) -> std::result::Result<(), FatalLlmError> {
        if self.supports(&capability) {
            Ok(())
        } else {
            Err(FatalLlmError::Unsupported(UnsupportedCapability {
                capability,
                model: Some(self.model.clone()),
                reason: None,
            }))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmCatalogCost {
    pub input_per_million: String,
    pub output_per_million: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_per_million: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_per_million: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    None,
    Low,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
) -> std::result::Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&canonicalize_json(value))
}

fn canonicalize_json(value: JsonValue) -> JsonValue {
    match value {
        JsonValue::Array(values) => {
            JsonValue::Array(values.into_iter().map(canonicalize_json).collect())
        }
        JsonValue::Object(entries) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in entries {
                sorted.insert(key, canonicalize_json(value));
            }

            let mut canonical = JsonMap::new();
            for (key, value) in sorted {
                canonical.insert(key, value);
            }
            JsonValue::Object(canonical)
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    proptest! {
        #[test]
        fn content_enum_roundtrips_between_history_and_generation(part in content_part_strategy()) {
            let history = LlmMessage {
                role: LlmMessageRole::User,
                content: vec![part.clone()],
            };
            let generation = LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![part.clone()],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            };

            let history_part = serde_json::to_value(&history.content[0]).unwrap();
            let generation_part = serde_json::to_value(&generation.message.content[0]).unwrap();

            prop_assert_eq!(&history_part, &generation_part);

            let decoded_history = serde_json::from_value::<ContentPart>(history_part).unwrap();
            let decoded_generation = serde_json::from_value::<ContentPart>(generation_part).unwrap();
            prop_assert_eq!(&decoded_history, &decoded_generation);
            prop_assert_eq!(decoded_history, part);
        }
    }

    #[test]
    fn request_hash_is_order_insensitive_but_semantics_sensitive() {
        let request = sample_request();
        let reordered = sample_request_with_reordered_maps();

        assert_eq!(
            request.canonical_hash_hex().unwrap(),
            reordered.canonical_hash_hex().unwrap(),
            "canonical key must ignore JSON object insertion order"
        );

        for (name, mutated) in semantic_mutations(&request) {
            assert_ne!(
                request.canonical_hash_hex().unwrap(),
                mutated.canonical_hash_hex().unwrap(),
                "{name} must affect the canonical key"
            );
        }
    }

    #[test]
    fn model_id_requires_provider_name_and_revision() {
        let model_id = "openai/gpt-4.1@2026-07-02".parse::<ModelId>().unwrap();
        assert_eq!(model_id.provider(), "openai");
        assert_eq!(model_id.name(), "gpt-4.1");
        assert_eq!(model_id.revision(), "2026-07-02");
        assert!("gpt-4.1@2026-07-02".parse::<ModelId>().is_err());
        assert!("openai/gpt-4.1".parse::<ModelId>().is_err());
        assert!("openai/@2026-07-02".parse::<ModelId>().is_err());
    }

    #[test]
    fn role_model_defaults_resolve_default_model_for_each_role() {
        let defaults = RoleModelDefaults::default();
        let resolved: Vec<_> = [
            LlmRole::Orchestrator,
            LlmRole::Subagent,
            LlmRole::Summarizer,
        ]
        .into_iter()
        .map(|role| defaults.resolve(role).as_str().to_owned())
        .collect();

        assert_eq!(
            resolved,
            [
                "openai/gpt-4.1@2026-07-02",
                "openai/gpt-4.1-mini@2026-07-02",
                "openai/gpt-4.1-nano@2026-07-02",
            ]
        );
    }

    #[test]
    fn role_model_defaults_prefer_user_override_for_each_role() {
        let mut defaults = RoleModelDefaults::default();
        let overrides = [
            (
                LlmRole::Orchestrator,
                ModelId::new("anthropic/claude-opus@2026-07-02").unwrap(),
            ),
            (
                LlmRole::Subagent,
                ModelId::new("anthropic/claude-sonnet@2026-07-02").unwrap(),
            ),
            (
                LlmRole::Summarizer,
                ModelId::new("local/fixture@2026-07-06").unwrap(),
            ),
        ];

        for (role, model) in &overrides {
            let _ = defaults.set_override(*role, model.clone());
        }

        let resolved: Vec<_> = [
            LlmRole::Orchestrator,
            LlmRole::Subagent,
            LlmRole::Summarizer,
        ]
        .into_iter()
        .map(|role| defaults.resolve(role).as_str().to_owned())
        .collect();

        assert_eq!(
            resolved,
            overrides
                .iter()
                .map(|(_, model)| model.as_str().to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn tier_precedence_resolves_in_contract_order() {
        let global = ModelTierRef("global".to_owned());
        let purpose = ModelTierRef("purpose".to_owned());
        let vault = ModelTierRef("vault".to_owned());
        let per_call = ModelTierRef("per-call".to_owned());

        let mut precedence = TierPrecedence {
            per_call: None,
            vault_policy: None,
            purpose_default: None,
            global_default: global.clone(),
        };
        assert_eq!(precedence.resolved(), &global);

        precedence.purpose_default = Some(purpose.clone());
        assert_eq!(precedence.resolved(), &purpose);

        precedence.vault_policy = Some(vault.clone());
        assert_eq!(precedence.resolved(), &vault);

        precedence.per_call = Some(per_call.clone());
        assert_eq!(precedence.resolved(), &per_call);
    }

    #[test]
    fn call_class_uses_kind_tag_inside_envelope() {
        let envelope = sample_envelope();
        let value = serde_json::to_value(&envelope).unwrap();

        assert_eq!(value["class"]["kind"], "durable");
        assert!(value["class"].get("class").is_none());
    }

    #[test]
    fn rate_limit_error_uses_contract_retry_after_field() {
        let value = serde_json::to_value(RetryableLlmError::RateLimited {
            retry_after: Some(250),
        })
        .unwrap();
        let JsonValue::Object(error) = value else {
            panic!("error should serialize as an object");
        };
        let payload = error.get("RateLimited").expect("rate limited payload");

        assert_eq!(payload["retry_after"], json!(250));
        assert!(payload.get("retry_after_ms").is_none());
    }

    #[test]
    fn reasoning_effort_round_trips_contract_wire_values() {
        let cases = [
            (ReasoningEffort::None, "none"),
            (ReasoningEffort::Low, "low"),
            (ReasoningEffort::Medium, "medium"),
            (ReasoningEffort::High, "high"),
            (ReasoningEffort::XHigh, "xhigh"),
        ];

        for (effort, wire) in cases {
            assert_eq!(serde_json::to_value(effort).unwrap(), json!(wire));
            assert_eq!(
                serde_json::from_value::<ReasoningEffort>(json!(wire)).unwrap(),
                effort
            );
        }
    }

    #[test]
    fn unsupported_capability_display_uses_stable_capability_name() {
        let unsupported = UnsupportedCapability {
            capability: LlmCapability::ToolCalling,
            model: Some(ModelId::new("openai/gpt-4.1@2026-07-02").unwrap()),
            reason: Some("catalog entry lacks tools".to_owned()),
        };

        assert_eq!(
            unsupported.to_string(),
            "tool_calling for openai/gpt-4.1@2026-07-02: catalog entry lacks tools"
        );
    }

    #[test]
    fn stream_eof_before_done_becomes_stream_cut() {
        let mut stream = LlmStream::new(ReadyLlmStream::new([]));

        let item = poll_stream_once(&mut stream).expect("stream cut error");
        assert!(matches!(
            item,
            Err(LlmError::Retryable(RetryableLlmError::StreamCut))
        ));
        assert!(poll_stream_once(&mut stream).is_none());
    }

    #[test]
    fn stream_done_is_terminal() {
        let done = LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "done".to_owned(),
                }],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Stop,
        };
        let after_done = LlmStreamEvent::TextStart {
            part_id: "late".to_owned(),
        };
        let mut stream = LlmStream::new(ReadyLlmStream::new([Ok(done.clone()), Ok(after_done)]));

        assert_eq!(poll_stream_once(&mut stream).unwrap().unwrap(), done);
        assert!(poll_stream_once(&mut stream).is_none());
    }

    fn content_part_strategy() -> impl Strategy<Value = ContentPart> {
        prop_oneof![
            short_string().prop_map(|text| ContentPart::Text { text }),
            (short_string(), prop::option::of(short_string()))
                .prop_map(|(text, signature)| { ContentPart::Reasoning { text, signature } }),
            (id_string(), name_string(), json_value_strategy()).prop_map(
                |(call_id, name, input)| {
                    ContentPart::ToolCall {
                        call_id,
                        name,
                        input,
                    }
                }
            ),
            (id_string(), json_value_strategy(), any::<bool>()).prop_map(
                |(call_id, output, is_error)| ContentPart::ToolResult {
                    call_id,
                    output,
                    is_error,
                }
            ),
            (media_type_strategy(), image_content_strategy())
                .prop_map(|(media_type, image)| { ContentPart::Image { media_type, image } }),
        ]
    }

    fn json_value_strategy() -> impl Strategy<Value = JsonValue> {
        let leaf = prop_oneof![
            Just(JsonValue::Null),
            any::<bool>().prop_map(JsonValue::Bool),
            (0_i64..10_000).prop_map(|value| json!(value)),
            short_string().prop_map(JsonValue::String),
        ];

        leaf.prop_recursive(3, 16, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(JsonValue::Array),
                prop::collection::btree_map(name_string(), inner, 0..4).prop_map(|entries| {
                    let mut object = JsonMap::new();
                    for (key, value) in entries {
                        object.insert(key, value);
                    }
                    JsonValue::Object(object)
                }),
            ]
        })
    }

    fn image_content_strategy() -> impl Strategy<Value = ImageContent> {
        prop_oneof![
            short_string().prop_map(|data| ImageContent::Base64 { data }),
            short_string().prop_map(|path| ImageContent::Url {
                url: format!("https://example.com/{path}"),
            }),
        ]
    }

    fn short_string() -> impl Strategy<Value = String> {
        "[ -~]{0,32}".prop_map(|value| value)
    }

    fn id_string() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_.:-]{1,24}".prop_map(|value| value)
    }

    fn name_string() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9_-]{0,23}".prop_map(|value| value)
    }

    fn media_type_strategy() -> impl Strategy<Value = String> {
        prop_oneof![Just("image/png".to_owned()), Just("image/jpeg".to_owned())]
    }

    fn sample_request() -> LlmRequest {
        let mut params = BTreeMap::new();
        params.insert("temperature".to_owned(), json!(0.2));
        params.insert(
            "sampling".to_owned(),
            json!({
                "top_p": 0.8,
                "seed": 7,
            }),
        );

        let mut provider_options = BTreeMap::new();
        provider_options.insert(
            "openai".to_owned(),
            json!({
                "parallel_tool_calls": false,
                "reasoning": {
                    "effort": "medium",
                    "summary": "auto",
                },
            }),
        );

        LlmRequest {
            model: ModelId::new("openai/gpt-4.1@2026-07-02").unwrap(),
            envelope: sample_envelope(),
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: "You classify memory writes.".to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![
                        ContentPart::Text {
                            text: "Classify this claim.".to_owned(),
                        },
                        ContentPart::Image {
                            media_type: "image/png".to_owned(),
                            image: ImageContent::Url {
                                url: "https://example.com/claim.png".to_owned(),
                            },
                        },
                    ],
                },
            ],
            tools: vec![LlmToolSpec {
                name: "classify_claim".to_owned(),
                description: "Return a gate verdict".to_owned(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "verdict": { "type": "string" },
                        "score": { "type": "number" },
                    },
                    "required": ["verdict"],
                }),
            }],
            params,
            provider_options,
        }
    }

    fn sample_request_with_reordered_maps() -> LlmRequest {
        let mut request = sample_request();

        request.params.clear();
        request.params.insert(
            "sampling".to_owned(),
            json!({
                "seed": 7,
                "top_p": 0.8,
            }),
        );
        request.params.insert("temperature".to_owned(), json!(0.2));

        request.provider_options.clear();
        request.provider_options.insert(
            "openai".to_owned(),
            json!({
                "reasoning": {
                    "summary": "auto",
                    "effort": "medium",
                },
                "parallel_tool_calls": false,
            }),
        );

        request.tools[0].input_schema = json!({
            "required": ["verdict"],
            "properties": {
                "score": { "type": "number" },
                "verdict": { "type": "string" },
            },
            "type": "object",
        });

        request
    }

    fn semantic_mutations(request: &LlmRequest) -> Vec<(&'static str, LlmRequest)> {
        let mut mutations = Vec::new();

        let mut model = request.clone();
        model.model = ModelId::new("anthropic/claude-sonnet@2026-07-02").unwrap();
        mutations.push(("model", model));

        let mut purpose = request.clone();
        purpose.envelope.purpose = CallPurpose::AnswerGen;
        mutations.push(("purpose", purpose));

        let mut class = request.clone();
        class.envelope.class = CallClass::BestEffort;
        mutations.push(("class", class));

        let mut fallback_name = request.clone();
        if let CallClass::Durable { fallback } = &mut fallback_name.envelope.class {
            fallback.name = "different_fallback".to_owned();
        }
        mutations.push(("fallback_name", fallback_name));

        let mut fallback_config = request.clone();
        if let CallClass::Durable { fallback } = &mut fallback_config.envelope.class {
            fallback.config = Some(json!({ "mode": "strict" }));
        }
        mutations.push(("fallback_config", fallback_config));

        let mut tier_per_call = request.clone();
        tier_per_call.envelope.tier.per_call = Some(ModelTierRef("large".to_owned()));
        mutations.push(("tier_per_call", tier_per_call));

        let mut tier_vault = request.clone();
        tier_vault.envelope.tier.vault_policy = Some(ModelTierRef("vault-large".to_owned()));
        mutations.push(("tier_vault", tier_vault));

        let mut tier_purpose = request.clone();
        tier_purpose.envelope.tier.purpose_default = Some(ModelTierRef("purpose-large".to_owned()));
        mutations.push(("tier_purpose", tier_purpose));

        let mut tier_global = request.clone();
        tier_global.envelope.tier.global_default = ModelTierRef("global-large".to_owned());
        mutations.push(("tier_global", tier_global));

        let mut response_format = request.clone();
        response_format.envelope.response_format = ResponseFormat::Text;
        mutations.push(("response_format", response_format));

        let mut locality = request.clone();
        locality.envelope.locality = ModelLocality::OwnServer;
        mutations.push(("locality", locality));

        let mut message = request.clone();
        message.messages[1].content[0] = ContentPart::Text {
            text: "Classify a different claim.".to_owned(),
        };
        mutations.push(("messages", message));

        let mut message_role = request.clone();
        message_role.messages[1].role = LlmMessageRole::Assistant;
        mutations.push(("message_role", message_role));

        let mut message_order = request.clone();
        message_order.messages.swap(0, 1);
        mutations.push(("message_order", message_order));

        let mut content_order = request.clone();
        content_order.messages[1].content.swap(0, 1);
        mutations.push(("content_order", content_order));

        let mut tools = request.clone();
        tools.tools[0].name = "route_tool".to_owned();
        mutations.push(("tools", tools));

        let mut tool_description = request.clone();
        tool_description.tools[0].description = "Return a routing verdict".to_owned();
        mutations.push(("tool_description", tool_description));

        let mut tool_schema = request.clone();
        tool_schema.tools[0].input_schema = json!({
            "type": "object",
            "properties": {
                "verdict": { "type": "boolean" },
            },
            "required": ["verdict"],
        });
        mutations.push(("tool_schema", tool_schema));

        let mut params = request.clone();
        params.params.insert("temperature".to_owned(), json!(0.7));
        mutations.push(("params", params));

        let mut provider_options = request.clone();
        provider_options.provider_options.insert(
            "openai".to_owned(),
            json!({
                "parallel_tool_calls": true,
                "reasoning": {
                    "effort": "medium",
                    "summary": "auto",
                },
            }),
        );
        mutations.push(("provider_options", provider_options));

        mutations
    }

    fn sample_envelope() -> CallEnvelope {
        CallEnvelope {
            purpose: CallPurpose::AutoCheck,
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: "fail_closed_to_proposed".to_owned(),
                    config: None,
                },
            },
            tier: TierPrecedence {
                per_call: None,
                vault_policy: Some(ModelTierRef("cheap".to_owned())),
                purpose_default: Some(ModelTierRef("tiny".to_owned())),
                global_default: ModelTierRef("standard".to_owned()),
            },
            response_format: ResponseFormat::Json {
                schema: json!({
                    "type": "object",
                    "properties": {
                        "verdict": { "type": "string" },
                    },
                    "required": ["verdict"],
                }),
            },
            locality: ModelLocality::ThirdParty,
        }
    }

    #[test]
    fn backend_trait_requires_lease_argument() {
        struct Backend;

        impl LlmBackend for Backend {
            fn generate<'a>(
                &'a self,
                _request: LlmRequest,
                _lease: &'a BudgetLease,
            ) -> LlmGenerateFuture<'a> {
                Box::pin(async {
                    Ok(LlmResponse {
                        message: LlmMessage {
                            role: LlmMessageRole::Assistant,
                            content: vec![ContentPart::Text {
                                text: "ok".to_owned(),
                            }],
                        },
                        usage: LlmUsage::zero(),
                        finish_reason: FinishReason::Stop,
                    })
                })
            }

            fn stream<'a>(
                &'a self,
                _request: LlmRequest,
                _lease: &'a BudgetLease,
            ) -> LlmStreamResult<'a> {
                Ok(LlmStream::new(EmptyLlmStream))
            }
        }

        struct DenyingBackend;

        impl LlmBackend for DenyingBackend {
            fn generate<'a>(
                &'a self,
                _request: LlmRequest,
                _lease: &'a BudgetLease,
            ) -> LlmGenerateFuture<'a> {
                Box::pin(async { Err(BudgetDenied::AdmissionDenied.into()) })
            }

            fn stream<'a>(
                &'a self,
                _request: LlmRequest,
                _lease: &'a BudgetLease,
            ) -> LlmStreamResult<'a> {
                Err(BudgetDenied::AdmissionDenied.into())
            }
        }

        struct EmptyLlmStream;

        impl Stream for EmptyLlmStream {
            type Item = LlmResult<LlmStreamEvent>;

            fn poll_next(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                std::task::Poll::Ready(None)
            }
        }

        let backend = Backend;
        let lease = BudgetLease::for_test("lease-1");
        let _stream = backend.stream(sample_request(), &lease).unwrap();

        let setup_error = match DenyingBackend.stream(sample_request(), &lease) {
            Ok(_) => panic!("stream setup should fail"),
            Err(error) => error,
        };
        assert!(matches!(
            setup_error,
            LlmError::BudgetDenied(BudgetDenied::AdmissionDenied)
        ));

        let _backend: Box<dyn LlmBackend> = Box::new(Backend);
    }

    struct ReadyLlmStream {
        events: std::collections::VecDeque<LlmResult<LlmStreamEvent>>,
    }

    impl ReadyLlmStream {
        fn new(events: impl IntoIterator<Item = LlmResult<LlmStreamEvent>>) -> Self {
            Self {
                events: events.into_iter().collect(),
            }
        }
    }

    impl Stream for ReadyLlmStream {
        type Item = LlmResult<LlmStreamEvent>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.events.pop_front())
        }
    }

    fn poll_stream_once(stream: &mut LlmStream<'_>) -> Option<LlmResult<LlmStreamEvent>> {
        let waker: &std::task::Waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match Pin::new(stream).poll_next(&mut cx) {
            std::task::Poll::Ready(item) => item,
            std::task::Poll::Pending => panic!("test stream should not pend"),
        }
    }
}
