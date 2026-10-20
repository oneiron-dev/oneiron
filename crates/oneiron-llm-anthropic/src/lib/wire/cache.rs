//! Prompt-cache boundaries on the Messages wire (FIX 4465 C): the host's
//! descriptor, rendered as `cache_control: {type: ephemeral}` on each marked
//! system block, tool definition or message part, at its place in the
//! request as its rung sends it. The provider's default lifetime holds and
//! no lifetime is sent, unless the request's own options ask for the one
//! hour tier (FIX 6029): then every marked block carries it alike. A request
//! with no descriptor is built as before.

use oneiron::code_run::{CacheBoundary, cache_boundaries};
use oneiron::{ContentPart, FatalLlmError, LlmMessageRole, LlmRequest, LlmResult};
use serde_json::{Map as JsonMap, Value as JsonValue, json};

use super::text_content;
use crate::AnthropicCacheTier;

/// Marks `body`, the Messages body `request` was built into, at each cache
/// boundary the request's host descriptor names, at `tier` (the request's
/// own, as [`crate::AnthropicProviderOptions::cache_tier`] reads it). A
/// boundary on a part this wire cannot mark (a reasoning or audio part)
/// makes the request invalid.
pub(super) fn mark(
    request: &LlmRequest,
    body: &mut JsonMap<String, JsonValue>,
    tier: Option<AnthropicCacheTier>,
) -> LlmResult<()> {
    let control = cache_control(tier);
    let boundaries = cache_boundaries(request)?;
    let mut system = Vec::new();
    for boundary in boundaries {
        match boundary {
            CacheBoundary::Tool { tool } => mark_block(
                body.get_mut("tools")
                    .and_then(JsonValue::as_array_mut)
                    .and_then(|tools| tools.get_mut(tool)),
                &control,
            )?,
            CacheBoundary::Message { message, part } => {
                let Some(held) = request.messages.get(message) else {
                    return Err(FatalLlmError::InvalidRequest.into());
                };
                if held.role == LlmMessageRole::System {
                    system.push((message, part));
                    continue;
                }
                if matches!(held.content.get(part), Some(ContentPart::Reasoning { .. })) {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
                // The wire's messages hold every message but the system ones.
                let index = request.messages[..message]
                    .iter()
                    .filter(|earlier| earlier.role != LlmMessageRole::System)
                    .count();
                mark_block(
                    body.get_mut("messages")
                        .and_then(JsonValue::as_array_mut)
                        .and_then(|messages| messages.get_mut(index))
                        .and_then(|message| message.get_mut("content"))
                        .and_then(JsonValue::as_array_mut)
                        .and_then(|content| content.get_mut(part)),
                    &control,
                )?;
            }
        }
    }
    if !system.is_empty() {
        body.insert(
            "system".to_owned(),
            system_blocks(request, &system, &control)?,
        );
    }
    Ok(())
}

/// The marker a block carries at `tier`: the bare marker the wire always
/// sent, with a lifetime only for the one hour tier a request asked for.
fn cache_control(tier: Option<AnthropicCacheTier>) -> JsonValue {
    match tier {
        Some(AnthropicCacheTier::OneHour) => json!({ "type": "ephemeral", "ttl": "1h" }),
        Some(AnthropicCacheTier::FiveMinutes) | None => json!({ "type": "ephemeral" }),
    }
}

fn mark_block(block: Option<&mut JsonValue>, control: &JsonValue) -> LlmResult<()> {
    let block = block
        .and_then(JsonValue::as_object_mut)
        .ok_or(FatalLlmError::InvalidRequest)?;
    block.insert("cache_control".to_owned(), control.clone());
    Ok(())
}

/// The system text as text blocks, one ending at each marked part, which
/// carries the marker. Their texts in order are the plain system string: the
/// same parts, joined the same way.
fn system_blocks(
    request: &LlmRequest,
    marks: &[(usize, usize)],
    control: &JsonValue,
) -> LlmResult<JsonValue> {
    let mut blocks = Vec::new();
    let mut text = String::new();
    let mut first = true;
    for (index, message) in request.messages.iter().enumerate() {
        if message.role != LlmMessageRole::System {
            continue;
        }
        for (part, content) in message.content.iter().enumerate() {
            let marked = marks.contains(&(index, part));
            let Some(words) = text_content(content) else {
                if marked {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
                continue;
            };
            if !first {
                text.push_str("\n\n");
            }
            first = false;
            text.push_str(&words);
            if marked {
                blocks.push(json!({
                    "type": "text",
                    "text": std::mem::take(&mut text),
                    "cache_control": control,
                }));
            }
        }
    }
    if !text.is_empty() {
        blocks.push(json!({ "type": "text", "text": text }));
    }
    Ok(JsonValue::Array(blocks))
}
