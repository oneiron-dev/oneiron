//! The protocol bodies the scripted provider answers with: OpenAI-compatible
//! chat completions and Anthropic-compatible messages, each buffered (one
//! JSON body) or streamed (server-sent events). The shapes match what the
//! engine's decoders read and what `tests/e2e/support/providers.ts`
//! (`openaiText`, `openaiStream`, `anthropicText`, `anthropicStream`) sends.

use serde_json::{Value, json};

/// Which wire protocol a request came in on, by its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// `POST /v1/chat/completions`.
    OpenAi,
    /// `POST /v1/messages`.
    Anthropic,
}

/// Token counts a reply declares. Declared by the script, never estimated
/// from the engine's prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl Default for Usage {
    fn default() -> Self {
        Self {
            input_tokens: 11,
            output_tokens: 7,
        }
    }
}

fn event(data: &Value, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("event: {name}\ndata: {data}\n\n"),
        None => format!("data: {data}\n\n"),
    }
}

/// A buffered answer carrying `text`.
pub(crate) fn json_reply(
    protocol: Protocol,
    id: &str,
    model: &str,
    text: &str,
    usage: Option<Usage>,
) -> Value {
    match protocol {
        Protocol::OpenAi => json!({
            "id": id,
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop"
            }],
            "usage": usage.map_or(Value::Null, |usage| json!({
                "prompt_tokens": usage.input_tokens,
                "completion_tokens": usage.output_tokens,
                "total_tokens": usage.input_tokens + usage.output_tokens
            }))
        }),
        Protocol::Anthropic => json!({
            "id": id,
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "usage": usage.map_or(Value::Null, |usage| json!({
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens
            }))
        }),
    }
}

/// The delta events of a streamed answer, without its closing events.
pub(crate) fn delta_events(protocol: Protocol, id: &str, model: &str, deltas: &[String]) -> Vec<String> {
    match protocol {
        Protocol::OpenAi => deltas
            .iter()
            .map(|delta| {
                event(
                    &json!({
                        "id": id,
                        "object": "chat.completion.chunk",
                        "model": model,
                        "choices": [{"index": 0, "delta": {"content": delta}, "finish_reason": null}]
                    }),
                    None,
                )
            })
            .collect(),
        Protocol::Anthropic => deltas
            .iter()
            .map(|delta| {
                event(
                    &json!({
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": delta}
                    }),
                    Some("content_block_delta"),
                )
            })
            .collect(),
    }
}

/// The events that open a streamed answer (Anthropic only; OpenAI opens
/// with its first delta).
pub(crate) fn opening_events(protocol: Protocol, id: &str, model: &str, usage: Option<Usage>) -> Vec<String> {
    match protocol {
        Protocol::OpenAi => Vec::new(),
        Protocol::Anthropic => {
            let mut message = json!({
                "id": id, "type": "message", "role": "assistant", "model": model, "content": []
            });
            if let Some(usage) = usage {
                message["usage"] = json!({"input_tokens": usage.input_tokens, "output_tokens": 1});
            }
            vec![
                event(
                    &json!({"type": "message_start", "message": message}),
                    Some("message_start"),
                ),
                event(
                    &json!({
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": {"type": "text", "text": ""}
                    }),
                    Some("content_block_start"),
                ),
            ]
        }
    }
}

/// The events that close a streamed answer: the stop, the usage when the
/// reply declares one, and OpenAI's `[DONE]`.
pub(crate) fn closing_events(protocol: Protocol, id: &str, model: &str, usage: Option<Usage>) -> Vec<String> {
    match protocol {
        Protocol::OpenAi => {
            let mut events = vec![event(
                &json!({
                    "id": id,
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                }),
                None,
            )];
            if let Some(usage) = usage {
                events.push(event(
                    &json!({
                        "id": id,
                        "object": "chat.completion.chunk",
                        "model": model,
                        "choices": [],
                        "usage": {
                            "prompt_tokens": usage.input_tokens,
                            "completion_tokens": usage.output_tokens,
                            "total_tokens": usage.input_tokens + usage.output_tokens
                        }
                    }),
                    None,
                ));
            }
            events.push("data: [DONE]\n\n".to_owned());
            events
        }
        Protocol::Anthropic => {
            let mut stop = json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}});
            if let Some(usage) = usage {
                stop["usage"] = json!({"output_tokens": usage.output_tokens});
            }
            vec![
                event(
                    &json!({"type": "content_block_stop", "index": 0}),
                    Some("content_block_stop"),
                ),
                event(&stop, Some("message_delta")),
                event(&json!({"type": "message_stop"}), Some("message_stop")),
            ]
        }
    }
}

/// A protocol-shaped error body for an answer with `status`, whose message
/// names the testkit, so a log line read later says where it came from. A
/// 4xx reads as the caller's error, which the engine does not retry; a 5xx
/// as the provider's.
pub(crate) fn error_body(protocol: Protocol, status: u16, message: &str) -> Value {
    let client = (400..500).contains(&status);
    match protocol {
        Protocol::OpenAi => {
            let kind = if client { "invalid_request_error" } else { "server_error" };
            json!({"error": {"message": message, "type": kind}})
        }
        Protocol::Anthropic => {
            let kind = if client { "invalid_request_error" } else { "api_error" };
            json!({"type": "error", "error": {"type": kind, "message": message}})
        }
    }
}

/// An OpenAI-compatible embeddings answer.
pub(crate) fn embeddings_reply(model: &str, vectors: &[Vec<f32>], input_tokens: u64) -> Value {
    json!({
        "object": "list",
        "model": model,
        "data": vectors
            .iter()
            .enumerate()
            .map(|(index, embedding)| json!({"object": "embedding", "index": index, "embedding": embedding}))
            .collect::<Vec<_>>(),
        "usage": {"prompt_tokens": input_tokens, "total_tokens": input_tokens}
    })
}
