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
use std::sync::Arc;
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_core::Stream;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::Vault;
use crate::claim::ClaimSource;
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

/// Opt-in per-call model pin (ONE-1344): an explicit allow-list of fully
/// revisioned model ids plus the background-tier switch. There is NO default
/// policy, no environment lookup, and no catalog discovery — a caller either
/// supplies a config or runs unpinned. An empty `allowed` set is valid and
/// admits nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedModelConfig {
    pub allowed: std::collections::BTreeSet<ModelId>,
    pub background_tier_enabled: bool,
}

/// Typed refusal from [`PinnedModelConfig::admit`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinnedConfigViolation {
    #[error("model is not present in the pinned model config: {model}")]
    ModelNotPinned { model: ModelId },
    #[error("background model tier is disabled for call purpose {purpose:?}")]
    BackgroundTierDisabled { purpose: CallPurpose },
}

impl PinnedModelConfig {
    /// Pre-admission check: membership FIRST, then background-tier
    /// classification. An unpinned model is always `ModelNotPinned`, even when
    /// its purpose would also fail the tier check.
    pub fn admit(&self, request: &LlmRequest) -> std::result::Result<(), PinnedConfigViolation> {
        if !self.allowed.contains(&request.model) {
            return Err(PinnedConfigViolation::ModelNotPinned {
                model: request.model.clone(),
            });
        }
        if !self.background_tier_enabled
            && matches!(
                &request.envelope.purpose,
                CallPurpose::Consolidation | CallPurpose::Extraction
            )
        {
            return Err(PinnedConfigViolation::BackgroundTierDisabled {
                purpose: request.envelope.purpose.clone(),
            });
        }
        Ok(())
    }
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

// ---------------------------------------------------------------------------
// Auto-check seam (ONE-1296).
//
// The engine owns exactly three things here: the synchronous `AutoChecker`
// trait a host implements, the bounded wrapper that keeps a host answer from
// becoming an engine liveness problem, and the request contract an auto check
// is entitled to make. It owns no model choice, no prompt tuning and no
// verdict policy — the write gate reads only Allow / Hold / Unavailable.
// ---------------------------------------------------------------------------

/// Wall-clock bound one auto-check consult may take before the write gate
/// stops waiting for it.
///
/// A checker that has not answered by then is [`AutoCheckOutcome::Unavailable`]
/// and the write falls to Proposed. The bound is the engine's, not the host's:
/// a claim write must not be able to block on a host process at all.
pub const AUTO_CHECKER_DEADLINE_MS: u64 = 1_500;

/// Longest claim-value prefix an auto-check candidate carries.
///
/// The checker is shown a PREVIEW, never the whole value: this seam is a
/// second opinion on a candidate, not a disclosure channel.
pub const AUTO_CHECK_VALUE_PREVIEW_BYTES: usize = 512;

/// Most `Hold` reasons one verdict may put on the receipt.
const AUTO_CHECK_MAX_HOLD_REASONS: usize = 8;

/// Longest single `Hold` reason one verdict may put on the receipt.
const AUTO_CHECK_HOLD_REASON_MAX_BYTES: usize = 256;

/// The tier an auto check asks for by PURPOSE default: the cheap one. The
/// per-call and vault-policy slots stay empty so a vault that pins its own
/// tier still wins through [`TierPrecedence::resolved`].
const AUTO_CHECK_PURPOSE_DEFAULT_TIER: &str = "cheap";

/// The floor under the purpose default, used only if a caller clears it.
const AUTO_CHECK_GLOBAL_DEFAULT_TIER: &str = "standard";

/// What a `Durable` auto check falls back to when no model answers: the same
/// fail-closed verdict every other failure mode produces.
const AUTO_CHECK_DETERMINISTIC_FALLBACK: &str = "fail_closed_to_proposed";

const AUTO_CHECK_SYSTEM_PROMPT: &str = "Decide whether this candidate memory claim may be stored \
     automatically. Answer only in the requested JSON shape: `verdict` is \"allow\" or \"hold\", \
     and `reasons` carries short strings when the verdict is hold.";

/// One candidate write presented to a host checker, borrowed from the write
/// door's own state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoCheckCandidate<'a> {
    pub predicate: &'a str,
    pub value_preview: &'a str,
    pub source: ClaimSource,
    pub actor_class: &'a str,
    pub sensitivity_band: Option<u8>,
}

/// [`AutoCheckCandidate`] with every borrow resolved.
///
/// [`BoundedAutoChecker`] hands this — not the borrowed form — to the host, so
/// the host's answer can outlive the gate's deadline without the gate having
/// to keep anything alive for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoCheckCandidateOwned {
    pub predicate: String,
    pub value_preview: String,
    pub source: ClaimSource,
    pub actor_class: String,
    pub sensitivity_band: Option<u8>,
}

impl AutoCheckCandidateOwned {
    /// Borrows this candidate back into the shape the trait takes.
    #[must_use]
    pub fn borrowed(&self) -> AutoCheckCandidate<'_> {
        AutoCheckCandidate {
            predicate: &self.predicate,
            value_preview: &self.value_preview,
            source: self.source,
            actor_class: &self.actor_class,
            sensitivity_band: self.sensitivity_band,
        }
    }
}

impl From<&AutoCheckCandidate<'_>> for AutoCheckCandidateOwned {
    fn from(candidate: &AutoCheckCandidate<'_>) -> Self {
        Self {
            predicate: candidate.predicate.to_owned(),
            value_preview: candidate.value_preview.to_owned(),
            source: candidate.source,
            actor_class: candidate.actor_class.to_owned(),
            sensitivity_band: candidate.sensitivity_band,
        }
    }
}

/// A host checker's verdict on one candidate.
///
/// There is no error arm on purpose: a host maps its own failures — budget
/// denial, fatal model error, unparseable answer — onto
/// [`Self::Unavailable`], and the gate treats that exactly like a hold that
/// could not name its reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoCheckOutcome {
    Allow,
    Hold { reasons: Vec<String> },
    Unavailable,
}

impl AutoCheckOutcome {
    /// Fail-closed normalization every consumer of a host verdict applies.
    ///
    /// A `Hold` that names no surviving reason is a MALFORMED verdict, not a
    /// quiet hold: the receipt would carry a refusal nothing could explain, so
    /// it becomes [`Self::Unavailable`]. Reasons are trimmed, blank-dropped,
    /// truncated to [`AUTO_CHECK_HOLD_REASON_MAX_BYTES`] and capped at
    /// [`AUTO_CHECK_MAX_HOLD_REASONS`], so a host cannot write an unbounded
    /// gate-decision receipt.
    #[must_use]
    pub fn normalized(self) -> Self {
        let Self::Hold { reasons } = self else {
            return self;
        };
        let reasons: Vec<String> = reasons
            .iter()
            .filter_map(|reason| {
                let trimmed = reason.trim();
                (!trimmed.is_empty()).then(|| {
                    truncate_on_char_boundary(trimmed, AUTO_CHECK_HOLD_REASON_MAX_BYTES).to_owned()
                })
            })
            .take(AUTO_CHECK_MAX_HOLD_REASONS)
            .collect();
        if reasons.is_empty() {
            Self::Unavailable
        } else {
            Self::Hold { reasons }
        }
    }
}

/// The host-implemented auto-check seam.
///
/// Synchronous by design: the write gate runs inside an LMDB write
/// transaction, which is not a place to hold an async runtime open. Bound an
/// implementation with [`BoundedAutoChecker`] before injecting it.
pub trait AutoChecker: Send + Sync + 'static {
    fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome;
}

/// The wrapper that makes an arbitrary host checker safe to call from the
/// write gate.
///
/// It converts the candidate to owned data, runs the host implementation off
/// the gate's own stack, captures a panic, and stops waiting after
/// [`AUTO_CHECKER_DEADLINE_MS`]. Timeout, panic, a checker that cannot be run
/// at all, and a malformed verdict all become [`AutoCheckOutcome::Unavailable`]
/// — the gate never hangs, and nothing unwinds through it.
pub struct BoundedAutoChecker {
    inner: Arc<dyn AutoChecker>,
}

impl BoundedAutoChecker {
    #[must_use]
    pub fn new(inner: Arc<dyn AutoChecker>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for BoundedAutoChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedAutoChecker").finish_non_exhaustive()
    }
}

impl AutoChecker for BoundedAutoChecker {
    fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        let owned = AutoCheckCandidateOwned::from(candidate);
        let inner = Arc::clone(&self.inner);
        // Bounded, capacity one: the worker hands back exactly one verdict and
        // must never block doing it, including when the deadline has already
        // elapsed and nothing is listening any more.
        let (sender, receiver) = mpsc::sync_channel::<AutoCheckOutcome>(1);
        // Detached on purpose. The gate's contract is that it stops waiting
        // after the deadline; joining a host implementation that never returns
        // would reintroduce exactly the hang the deadline exists to prevent.
        if std::thread::Builder::new()
            .name("oneiron-auto-check".to_owned())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    inner.check(&owned.borrowed())
                }))
                .unwrap_or(AutoCheckOutcome::Unavailable);
                let _ = sender.try_send(outcome.normalized());
            })
            .is_err()
        {
            return AutoCheckOutcome::Unavailable;
        }

        receiver
            .recv_timeout(Duration::from_millis(AUTO_CHECKER_DEADLINE_MS))
            .unwrap_or(AutoCheckOutcome::Unavailable)
    }
}

/// The host request one auto-check consult is entitled to make.
///
/// OF-037 is the CURRENT ruling and supersedes the older BestEffort line: an
/// auto check is a [`CallClass::Durable`] [`CallPurpose::AutoCheck`] call
/// answering in a JSON schema on the purpose-default cheap tier. `BestEffort`
/// is stale canon and must not come back — a check whose answer decides
/// whether a write self-approves is memoizable, replayable work with a
/// deterministic fallback, which is exactly what `Durable` means. Failing the
/// call still fails closed to Proposed; the class says how the call is made,
/// not how a failure is read.
///
/// `checker_ref` is the manifest's OPAQUE selector. The engine picks no model:
/// it carries the host's own ref through as the request's model identity.
#[must_use]
pub fn auto_check_llm_request(checker_ref: &str, candidate: &AutoCheckCandidate<'_>) -> LlmRequest {
    LlmRequest {
        model: auto_check_model_id(checker_ref),
        envelope: CallEnvelope {
            purpose: CallPurpose::AutoCheck,
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: AUTO_CHECK_DETERMINISTIC_FALLBACK.to_owned(),
                    config: None,
                },
            },
            tier: TierPrecedence {
                per_call: None,
                vault_policy: None,
                purpose_default: Some(ModelTierRef(AUTO_CHECK_PURPOSE_DEFAULT_TIER.to_owned())),
                global_default: ModelTierRef(AUTO_CHECK_GLOBAL_DEFAULT_TIER.to_owned()),
            },
            response_format: ResponseFormat::Json {
                schema: auto_check_verdict_schema(),
            },
            // The host resolves `checker_ref` and knows where its checker
            // runs; the engine states the conservative default rather than
            // guessing a locality it cannot verify.
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: AUTO_CHECK_SYSTEM_PROMPT.to_owned(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: auto_check_candidate_text(candidate),
                }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

fn auto_check_model_id(checker_ref: &str) -> ModelId {
    dynamic_model_id(
        "auto-check",
        sanitize_model_id_segment(checker_ref),
        "configured",
    )
}

fn auto_check_verdict_schema() -> JsonValue {
    serde_json::json!({
        "type": "object",
        "properties": {
            "verdict": { "type": "string", "enum": ["allow", "hold"] },
            "reasons": { "type": "array", "items": { "type": "string" } },
        },
        "required": ["verdict"],
        "additionalProperties": false,
    })
}

fn auto_check_candidate_text(candidate: &AutoCheckCandidate<'_>) -> String {
    let sensitivity_band = match candidate.sensitivity_band {
        Some(band) => band.to_string(),
        None => "unstamped".to_owned(),
    };
    format!(
        "predicate: {}\nsource: {}\nactor_class: {}\nsensitivity_band: {}\nvalue_preview: {}",
        candidate.predicate,
        candidate.source.as_str(),
        candidate.actor_class,
        sensitivity_band,
        candidate.value_preview,
    )
}

/// Truncates `value` to at most `max_bytes`, never splitting a character.
pub(crate) fn truncate_on_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
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
