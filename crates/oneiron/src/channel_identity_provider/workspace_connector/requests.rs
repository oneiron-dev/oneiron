//! Input checks the workspace modules share (L3-17): a Google file id, a
//! batch of requests passed through as written, a revision a write may pin,
//! and the typed decode of a tool's arguments.

use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use super::ARGUMENTS_INVALID;

/// The most requests one batch update carries.
const MAX_REQUESTS: usize = 500;
/// The longest file id; Google's are 44 bytes.
const MAX_FILE_ID_BYTES: usize = 128;
/// The longest revision id a write may pin.
const MAX_REVISION_ID_BYTES: usize = 256;

/// `arguments` read as one tool's typed input, or [`ARGUMENTS_INVALID`].
pub(super) fn decode<T: DeserializeOwned>(arguments: &Value) -> Result<T, &'static str> {
    T::deserialize(arguments).map_err(|_| ARGUMENTS_INVALID)
}

/// Google's file id alphabet: letters, digits, `-` and `_`, within
/// [`MAX_FILE_ID_BYTES`]. Only such an id goes into a request path.
pub(super) fn plain_file_id(id: &str) -> bool {
    (1..=MAX_FILE_ID_BYTES).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// 1 to [`MAX_REQUESTS`] requests, each one key, the request kind in
/// letters, holding one object.
pub(super) fn requests_fit(requests: &[Map<String, Value>]) -> bool {
    (1..=MAX_REQUESTS).contains(&requests.len()) && requests.iter().all(one_request)
}

/// One request: one key, the request kind in letters, holding one object.
fn one_request(request: &Map<String, Value>) -> bool {
    request.len() == 1
        && request.iter().all(|(kind, body)| {
            !kind.is_empty()
                && kind.bytes().all(|byte| byte.is_ascii_alphabetic())
                && body.is_object()
        })
}

/// Each request's kind, in order: what a write's preview shows of a batch.
pub(super) fn request_kinds(requests: &[Map<String, Value>]) -> Value {
    let kinds: Vec<&str> = requests
        .iter()
        .filter_map(|request| request.keys().next().map(String::as_str))
        .collect();
    json!(kinds)
}

/// A revision id a write pins: not blank, within
/// [`MAX_REVISION_ID_BYTES`], and free of control characters. It goes in
/// the JSON body, never in a path.
pub(super) fn plain_revision_id(id: &str) -> bool {
    !id.trim().is_empty() && id.len() <= MAX_REVISION_ID_BYTES && !id.chars().any(char::is_control)
}

/// The input schema of a file id: `description` says where its URL shows
/// it.
pub(super) fn file_id_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_FILE_ID_BYTES,
        "description": description
    })
}

/// The input schema of a batch's requests, passed through as written: `api`
/// names the REST API and `example` one of its request kinds.
pub(super) fn requests_schema(api: &str, example: &str) -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "maxItems": MAX_REQUESTS,
        "items": {
            "type": "object",
            "minProperties": 1,
            "maxProperties": 1,
            "description": format!(
                "One {api} request, such as {{\"{example}\": {{...}}}}, passed through as written."
            )
        }
    })
}

/// The input schema of a revision id a write pins.
pub(super) fn revision_id_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_REVISION_ID_BYTES,
        "description": description
    })
}
