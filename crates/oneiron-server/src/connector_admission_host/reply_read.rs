//! Reading one admission reply body, JSON or an event stream, until the
//! response that answers a request.

use std::io::{BufRead, BufReader, Read};

use super::{CONTENT_TYPE, Response, Value};

const UNREADABLE: &str = "the connector's reply is unreadable";

/// Reads one reply body, JSON or an event stream, until the response that
/// answers `id`, whatever its size (FIX 9281): only a body that does not
/// parse is unreadable. Server requests on a stream go to `refuse`;
/// notifications are dropped.
pub(super) fn read_reply(
    response: Response,
    id: &Value,
    refuse: &mut dyn FnMut(&Value),
) -> Result<Value, &'static str> {
    let stream = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("text/event-stream"));
    let mut body = response;
    if !stream {
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).map_err(|_| UNREADABLE)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| UNREADABLE)?;
        let found = match value {
            Value::Array(batch) => batch.into_iter().find(|message| answers(message, id)),
            message => answers(&message, id).then_some(message),
        };
        return found.ok_or(UNREADABLE);
    }
    let mut reader = BufReader::new(body);
    let mut data = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|_| UNREADABLE)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if n == 0 || trimmed.is_empty() {
            if let Some(message) = finished_event(&mut data, id, refuse) {
                return Ok(message);
            }
            if n == 0 {
                return Err(UNREADABLE);
            }
            continue;
        }
        if let Some(field) = trimmed.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(field.strip_prefix(' ').unwrap_or(field));
        }
    }
}

/// One finished event: the answer to `id`, else nothing. A server request
/// in it is refused.
fn finished_event(data: &mut String, id: &Value, refuse: &mut dyn FnMut(&Value)) -> Option<Value> {
    if data.is_empty() {
        return None;
    }
    let message = serde_json::from_str::<Value>(&std::mem::take(data)).ok()?;
    if answers(&message, id) {
        return Some(message);
    }
    if message.get("method").is_some() && message.get("id").is_some() {
        refuse(&message);
    }
    None
}

/// A response (not a request) carrying exactly this id.
fn answers(message: &Value, id: &Value) -> bool {
    message.get("method").is_none()
        && message.get("id") == Some(id)
        && (message.get("result").is_some() || message.get("error").is_some())
}
