//! Turn construction and input-message mapping.
//! Entry: OpenAiResponsesTurn::create_frame.
//! Types and private mapping helpers stay in the parent; moved functions keep old-path exports.

use super::{
    ContentPart, ENCRYPTED_REASONING_INCLUDE, FatalLlmError, JsonMap, JsonValue, LlmMessage,
    LlmRequest, LlmResult, OpenAiCompatConfig, OpenAiProviderOptions, OpenAiResponsesTurn,
    REASONING_BUDGET_PARAM, ReasoningEffort, ResponseFormat, json, responses_items, responses_tool,
    validate_capabilities,
};
use crate::wire::SOLO_FIELD;
use oneiron::llm::is_solo;

impl OpenAiResponsesTurn {
    /// The `response.create` frame that chains `previous_response_id` and
    /// sends `input`.
    #[must_use]
    pub fn create_frame(
        &self,
        previous_response_id: Option<&str>,
        input: &[JsonValue],
    ) -> JsonValue {
        let mut frame = JsonMap::with_capacity(self.head.len() + 3);
        frame.insert("type".into(), "response.create".into());
        frame.extend(self.head.clone());
        if let Some(id) = previous_response_id {
            frame.insert("previous_response_id".into(), id.into());
        }
        frame.insert("input".into(), JsonValue::Array(input.to_vec()));
        JsonValue::Object(frame)
    }

    /// Whether this turn asks the provider to keep its response (`store`).
    #[must_use]
    pub fn stored(&self) -> bool {
        self.head.get("store") == Some(&JsonValue::Bool(true))
    }
}

/// Whether the Responses codec can carry `request`. Audio input has no
/// Responses item this codec builds, so such a request takes the chat path.
#[must_use]
pub fn responses_can_carry(request: &LlmRequest) -> bool {
    !request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .any(|part| matches!(part, ContentPart::Audio { .. }))
}

pub fn build_openai_responses_turn(
    config: &OpenAiCompatConfig,
    request: &LlmRequest,
    stream: bool,
) -> LlmResult<OpenAiResponsesTurn> {
    if request.route_selector_override().is_some() || !responses_can_carry(request) {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let catalog = config.catalog_entry(&request.model)?;
    let provider_options = OpenAiProviderOptions::from_request(request)?;
    validate_capabilities(catalog, request, &provider_options, stream)?;

    let mut head = JsonMap::new();
    for (key, value) in &request.params {
        // The chat names of the output cap are one Responses field.
        let key = match key.as_str() {
            "max_tokens" | "max_completion_tokens" => "max_output_tokens",
            other => other,
        };
        head.insert(key.to_owned(), value.clone());
    }
    for (key, value) in provider_options.to_wire_fields() {
        head.insert(key, value);
    }
    // A call the host marked solo runs alone on an own server that admits
    // calls so. Only such a provider's config sends the field; any other
    // provider never sees it.
    if config.solo_admission() && is_solo(request) {
        head.insert(SOLO_FIELD.to_owned(), JsonValue::Bool(true));
    }
    let mut reasoning = match head.remove("reasoning") {
        Some(JsonValue::Object(options)) => options,
        Some(_) => return Err(FatalLlmError::InvalidRequest.into()),
        None => JsonMap::new(),
    };
    // Chat's flat effort is `reasoning.effort` here.
    if let Some(effort) = head.remove("reasoning_effort") {
        reasoning.insert("effort".into(), effort);
    }
    for key in [
        "thinking",
        "output_config",
        "chat_template_kwargs",
        REASONING_BUDGET_PARAM,
    ] {
        head.remove(key);
    }
    if let Some(effort) = request.envelope.seat_effort {
        // The seat pin wins, as on the chat wire; no effort leaves no
        // reasoning controls at all.
        if effort == ReasoningEffort::None {
            reasoning.clear();
        } else {
            reasoning.insert("effort".into(), json!(effort));
        }
    }
    if !reasoning.is_empty() {
        head.insert("reasoning".into(), JsonValue::Object(reasoning));
    }
    let wire_model = catalog
        .metadata
        .get("wire_model")
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| request.model.name())
        .to_owned();
    head.insert("model".to_owned(), JsonValue::String(wire_model.clone()));
    // The chain lives on the socket alone; the vault keeps the transcript.
    // The host sets `store` when its owner turned it on (OF-602).
    head.insert("store".into(), JsonValue::Bool(false));
    // A reasoning model's items come back with their encrypted content, so a
    // whole replay sends the model its own earlier reasoning with nothing
    // stored.
    if catalog
        .capabilities
        .contains(&oneiron::LlmCapability::Reasoning)
    {
        let include = head.entry("include").or_insert_with(|| json!([]));
        if let Some(list) = include.as_array_mut()
            && !list
                .iter()
                .any(|value| value == ENCRYPTED_REASONING_INCLUDE)
        {
            list.push(json!(ENCRYPTED_REASONING_INCLUDE));
        }
    }
    for key in [
        "stream",
        "stream_options",
        "background",
        "input",
        "previous_response_id",
    ] {
        head.remove(key);
    }
    if !request.tools.is_empty() {
        head.insert(
            "tools".to_owned(),
            JsonValue::Array(request.tools.iter().map(responses_tool).collect()),
        );
    }
    if let ResponseFormat::Json { schema } = &request.envelope.response_format {
        head.insert(
            "text".to_owned(),
            json!({
                "format": {
                    "type": "json_schema",
                    "name": "oneiron_response",
                    "schema": schema,
                },
            }),
        );
    }

    Ok(OpenAiResponsesTurn {
        head,
        items: request
            .messages
            .iter()
            .flat_map(|message| responses_items(message, Some(&wire_model)))
            .collect(),
    })
}

/// One message as Responses input items. A reasoning part this codec read
/// with its encrypted content goes back as its reasoning item; any other is
/// left out (on a chained turn the socket keeps it).
#[must_use]
pub fn openai_responses_items(message: &LlmMessage) -> Vec<JsonValue> {
    responses_items(message, None)
}
