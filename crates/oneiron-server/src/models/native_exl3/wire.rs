//! Codec v1 of the house EXL3 worker's native channel (`exl3_ipc.py`): each
//! frame is a u64 big-endian payload length, then that many bytes of UTF-8
//! JSON, the envelope `{v, op, request_id, epoch?, seq?, body}`. Request ids
//! and sequence numbers are u64; the epoch is the worker's 32-hex
//! incarnation. Nothing caps a frame's length: a frame is read as it comes.
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

/// The codec both sides speak.
pub(super) const SCHEMA_VERSION: u64 = 1;

/// A frame's length prefix.
pub(super) const HEADER_BYTES: usize = 8;

/// The one input encoding v1 sends: `{messages, tools?}` as UTF-8 JSON,
/// which the worker renders and tokenizes itself.
pub(super) const CHAT_JSON: &str = "chat_json";

/// The request fields that ride in the input region, not in `params`.
const CONVERSATION_FIELDS: [&str; 2] = ["messages", "tools"];

/// The HTTP route's own fields, which a native call carries in its frame
/// instead (`stream`) or not at all.
const ROUTE_FIELDS: [&str; 2] = ["stream", "stream_options"];

/// One frame this side sends.
#[derive(Serialize)]
pub(super) struct Outgoing<'a> {
    pub(super) v: u64,
    pub(super) op: &'a str,
    pub(super) request_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) epoch: Option<&'a str>,
    pub(super) body: JsonValue,
}

/// One frame the worker sent.
#[derive(Debug, Deserialize)]
pub(super) struct Incoming {
    pub(super) v: u64,
    pub(super) op: String,
    pub(super) request_id: u64,
    #[serde(default)]
    pub(super) body: JsonValue,
}

/// `frame` as its bytes on the wire: the length prefix, then the JSON.
pub(super) fn encode(frame: &Outgoing<'_>) -> serde_json::Result<Vec<u8>> {
    let payload = serde_json::to_vec(frame)?;
    let length = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// A payload as a frame of this codec; `None` for anything else.
pub(super) fn decode(payload: &[u8]) -> Option<Incoming> {
    serde_json::from_slice::<Incoming>(payload)
        .ok()
        .filter(|frame| frame.v == SCHEMA_VERSION)
}

/// A chat request body split for the native call: the conversation the
/// input region carries (`messages`, and `tools` when the call names them),
/// and every other field as the HTTP route takes it, less the route's own.
pub(super) fn split_request(body: &JsonValue) -> (JsonValue, JsonValue) {
    let mut conversation = serde_json::Map::new();
    let mut params = serde_json::Map::new();
    if let Some(fields) = body.as_object() {
        for (key, value) in fields {
            if CONVERSATION_FIELDS.contains(&key.as_str()) {
                conversation.insert(key.clone(), value.clone());
            } else if !ROUTE_FIELDS.contains(&key.as_str()) {
                params.insert(key.clone(), value.clone());
            }
        }
    }
    (JsonValue::Object(conversation), JsonValue::Object(params))
}

/// The `generate` body: the input region's description and the call's
/// fields. `buffer_id` names the region on this connection.
pub(super) fn generate_body(
    buffer_id: u64,
    length: u64,
    params: JsonValue,
    stream: bool,
) -> JsonValue {
    json!({
        "input": {
            "buffer_id": buffer_id,
            "fd_index": 0,
            "offset": 0,
            "length": length,
            "encoding": CHAT_JSON,
        },
        "params": params,
        "stream": stream,
    })
}

/// A `refused` body's code.
pub(super) fn refusal_code(body: &JsonValue) -> &str {
    body.get("code").and_then(JsonValue::as_str).unwrap_or("")
}

/// Whether a refusal says the request itself is wrong, which no retry
/// mends; any other refusal (another incarnation, a drain) is the worker's
/// state, and the call ran nowhere.
pub(super) fn refusal_is_request(code: &str) -> bool {
    matches!(
        code,
        "invalid_request" | "invalid_input" | "unsupported_encoding"
    )
}

/// The HTTP status a worker's error stands for: 400 for a request the
/// worker refused as invalid, 500 otherwise.
pub(super) fn error_status(error: &JsonValue) -> u16 {
    if error.get("type").and_then(JsonValue::as_str) == Some("invalid_request_error") {
        400
    } else {
        500
    }
}
