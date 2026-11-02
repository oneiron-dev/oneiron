//! The request one case sends, and what of it the row records.
//!
//! Every knob here is one the production wire already has: sampling fields
//! ride `LlmRequest::params`, which `oneiron-llm-openai` copies into the body
//! verbatim; thinking rides the envelope's `seat_effort`, which the wire turns
//! into `chat_template_kwargs` for an own server; the schema rides
//! `response_format`, which the provider's config may drop on the wire; solo
//! admission rides the host's provider options (`oneiron::llm::mark_solo`),
//! which the wire sends a `local-openai-compat` provider as `oneiron_solo`.

use std::collections::BTreeMap;

use oneiron::llm::{REASONING_BUDGET_PARAM, ReasoningEffort, mark_solo};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
};
use serde::Serialize;
use serde_json::{Value as JsonValue, json};

use super::args::Sampling;
use super::cases::Case;
use super::scoring::response_schema;

/// The thinking budget the Dreamer's reasoning binding sends beside its
/// default effort when no vault policy authored one
/// (`oneiron/src/dreamer_consolidation/roles.rs`, `DEFAULT_BUDGET_TOKENS`).
const SHIPPED_BUDGET_TOKENS: u64 = 4_096;

/// The fixed prompt of the unrecorded warmup calls.
const WARMUP_PROMPT: &str = "Reply with OK.";
const WARMUP_MAX_TOKENS: u64 = 16;

/// What a run's requests share.
pub(super) struct Shape {
    pub(super) model: ModelId,
    pub(super) locality: ModelLocality,
    pub(super) sampling: Sampling,
    pub(super) schema: bool,
    pub(super) cache_bust: bool,
    /// Whether the served catalog row takes a reasoning level, which decides
    /// the Dreamer's binding for a thinking call.
    pub(super) reasoning: bool,
    /// Whether each measured call asks to run alone (`--solo`).
    pub(super) solo: bool,
    pub(super) seed: Option<u64>,
}

/// What one request carried, as the row records it.
#[derive(Clone, Debug, Serialize)]
pub(super) struct Sent {
    pub(super) params_sent: BTreeMap<String, JsonValue>,
    pub(super) seat_effort: Option<ReasoningEffort>,
    pub(super) thinking: bool,
    pub(super) thinking_knob: &'static str,
    pub(super) schema_sent: bool,
    pub(super) max_tokens: u64,
    /// Whether the call carried the solo marker.
    pub(super) solo: bool,
}

fn sampling_params(sampling: Sampling) -> BTreeMap<String, JsonValue> {
    let pairs = match sampling {
        // The Dreamer's extraction call sets no sampling field
        // (`dreamer_consolidation/executor/extraction.rs`, `params: BTreeMap::new()`).
        Sampling::Shipped => Vec::new(),
        Sampling::Greedy => vec![("temperature", json!(0)), ("top_k", json!(1))],
        Sampling::Card => vec![
            ("temperature", json!(0.7)),
            ("top_p", json!(0.8)),
            ("top_k", json!(20)),
            ("min_p", json!(0)),
            ("presence_penalty", json!(1.5)),
        ],
    };
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// The envelope effort and the knob's name for a call that does or does not
/// think. A non-thinking call pins `none`, which the wire sends an own server
/// as `chat_template_kwargs.enable_thinking = false`. A thinking call gets
/// what the Dreamer's `bind_reasoning` gives one with no authored policy:
/// medium with a 4096-token budget on a row that takes a reasoning level,
/// `none` on one that does not.
fn thinking_knob(
    thinking: bool,
    reasoning: bool,
    params: &mut BTreeMap<String, JsonValue>,
) -> (ReasoningEffort, &'static str) {
    if !thinking {
        return (ReasoningEffort::None, "seat_effort=none");
    }
    if !reasoning {
        return (
            ReasoningEffort::None,
            "seat_effort=none (row takes no reasoning level)",
        );
    }
    params.insert(REASONING_BUDGET_PARAM.into(), SHIPPED_BUDGET_TOKENS.into());
    (
        ReasoningEffort::Medium,
        "seat_effort=medium, reasoning_budget_tokens=4096",
    )
}

fn text(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

/// Puts one nonce line before everything else the request says, at the
/// head of its system message's text (a new system message when it has
/// none), so no engine can reuse a cached prefix of another call.
fn bust_cache(messages: &mut Vec<LlmMessage>, nonce: &str) {
    let line = format!("request-nonce: {nonce}\n");
    match messages
        .first_mut()
        .filter(|first| first.role == LlmMessageRole::System)
        .and_then(|first| first.content.first_mut())
    {
        Some(ContentPart::Text { text: head }) => head.insert_str(0, &line),
        _ => messages.insert(0, text(LlmMessageRole::System, line)),
    }
}

impl Shape {
    fn request(
        &self,
        mut messages: Vec<LlmMessage>,
        max_tokens: u64,
        thinking: bool,
        schema: Option<JsonValue>,
        solo: bool,
    ) -> (LlmRequest, Sent) {
        let mut params = sampling_params(self.sampling);
        if let Some(seed) = self.seed {
            params.insert("seed".into(), seed.into());
        }
        let (effort, knob) = thinking_knob(thinking, self.reasoning, &mut params);
        params.insert("max_tokens".into(), max_tokens.into());
        if self.cache_bust {
            bust_cache(&mut messages, &oneiron::EntityId::now().to_hex());
        }
        let sent = Sent {
            params_sent: params.clone(),
            seat_effort: Some(effort),
            thinking,
            thinking_knob: knob,
            schema_sent: schema.is_some(),
            max_tokens,
            solo,
        };
        let mut request = LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: Some(effort),
                scope: Default::default(),
                purpose: CallPurpose::Eval,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Eval,
                    ModelTierRef("eval-pinned".into()),
                ),
                response_format: schema.map_or(ResponseFormat::Text, |schema| {
                    ResponseFormat::Json { schema }
                }),
                locality: self.locality,
                host_keyless: false,
            },
            messages,
            tools: Vec::new(),
            params,
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        if solo {
            mark_solo(&mut request);
        }
        (request, sent)
    }

    /// One measured case's request.
    pub(super) fn case(&self, case: &Case) -> (LlmRequest, Sent) {
        self.request(
            case.messages.clone(),
            case.max_tokens,
            case.thinking,
            self.schema.then(|| response_schema(case.scorer)),
            self.solo,
        )
    }

    /// One unrecorded warmup call: a fixed trivial prompt, no thinking, no
    /// schema, never solo, so a warmup round warms the batched path.
    pub(super) fn warmup(&self) -> LlmRequest {
        let messages = vec![text(LlmMessageRole::User, WARMUP_PROMPT.to_owned())];
        self.request(messages, WARMUP_MAX_TOKENS, false, None, false)
            .0
    }
}
