//! Engine-facing LLM invocation seam.
//!
//! This module defines the shared request, response, streaming, usage, error,
//! and catalog types consumed by engine callers and host-supplied adapters. It
//! intentionally contains no provider implementation or inference dependency.

mod budget;
mod step;

pub use step::{
    DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES, DREAMER_STEP_PREDICATE, DREAMER_STEP_RETRY_BACKOFF_MS,
    DREAMER_STEP_VALUE_KEYS, DREAMER_STEP_VALUE_SCHEMA_VERSION, DREAMER_TRAP_PREDICATE,
    DREAMER_TRAP_VALUE_KEYS, DREAMER_TRAP_VALUE_SCHEMA_VERSION, DreamerTrapKind, DreamerTrapState,
    DurableStepContext, DurableStepError, DurableStepResult, PeerResultWaitBinding, StepOutcome,
    StepProgression, TrapRef, call_as_step, consume_trap_signal, open_trap,
    reconcile_peer_result_signals, register_peer_result_wait, register_wait,
    send_peer_result_signal, send_trap_signal, trap_for_durable_wait, trap_park_owner,
};
pub(crate) use step::{deindex_dreamer_step_claim, index_dreamer_step_claim_for_put};

pub use budget::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetAdmission, BudgetExhaustionPolicy, BudgetGuard, BudgetLadderEvent, BudgetPromptTemplate,
    BudgetRead, BudgetSettlement, BudgetSignalDeliveryChannel, BudgetSteeringSignal,
    BudgetThreshold, DEFAULT_BUDGET_RESERVE_UNITS,
};
pub(crate) use budget::{BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable};

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

use crate::Vault;
use crate::edit_distance::routing::{RoutingScopeKey, WeightHint, routing_weight_hint};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;

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

/// Absolute per-attempt input token totals, never retry deltas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LlmInputUsage {
    pub total: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

/// Absolute per-attempt output token totals, never retry deltas.
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

    /// [`Self::resolve`], plus what ED-07's routing loop
    /// ([`crate::edit_distance::routing`]) knows about that model in
    /// `task_class`.
    ///
    /// The hint never changes the model returned. This door resolves exactly
    /// what [`Self::resolve`] resolves and hands the routing signal back
    /// beside it — the projection informs how a router WEIGHTS a candidate it
    /// is already willing to use, and there is no shape of hint that takes a
    /// role's model out of play.
    ///
    /// `None` is the default answer: a task class starts on
    /// [`RolloutRung::Shadow`] and stays there until an owner promotes it, so
    /// an engine that never touches the ladder routes exactly as it did before
    /// this door existed.
    ///
    /// [`RolloutRung::Shadow`]: crate::edit_distance::routing::RolloutRung::Shadow
    ///
    /// # Errors
    ///
    /// Storage errors reading the routing projection.
    pub fn resolve_with_routing_hint(
        &self,
        vault: &Vault,
        role: LlmRole,
        task_class: &str,
    ) -> Result<(ModelId, Option<WeightHint>)> {
        let model = self.resolve(role);
        let hint = routing_weight_hint(vault, &RoutingScopeKey::for_model(&model, task_class))?;
        Ok((model, hint))
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
        match self {
            Self::GptOssSafeguard20b => {
                validated_static_model_id("oneiron/gpt-oss-safeguard-20b@default")
            }
            Self::OpenRouter { model } => {
                dynamic_model_id("openrouter", sanitize_model_id_segment(model), "configured")
            }
            Self::Endpoint { url } => dynamic_model_id(
                "endpoint",
                sanitize_model_id_segment(&endpoint_model_identity(url)),
                "configured",
            ),
            Self::OnDevice { tier } => {
                dynamic_model_id("on-device", sanitize_model_id_segment(tier), "configured")
            }
        }
    }
}

fn dynamic_model_id(provider: &str, name: String, revision: &str) -> ModelId {
    ModelId::new(format!("{provider}/{name}@{revision}"))
        .expect("sanitized safeguard model binding produces a valid model id")
}

fn sanitize_model_id_segment(value: &str) -> String {
    let sanitized = value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
                byte as char
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim_matches('.')
        .to_owned();
    if sanitized.is_empty() {
        "configured".to_owned()
    } else {
        sanitized
    }
}

fn endpoint_model_identity(url: &str) -> String {
    let without_scheme = url
        .split_once("://")
        .map_or(url, |(_, remainder)| remainder);
    let without_fragment = without_scheme
        .split_once('#')
        .map_or(without_scheme, |(head, _)| head);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(head, _)| head);
    let slash_index = without_query.find('/').unwrap_or(without_query.len());
    let (authority, path) = without_query.split_at(slash_index);
    let authority_without_credentials = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{authority_without_credentials}{path}")
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

pub(crate) fn canonical_json_bytes<T: Serialize>(
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
mod tests;
