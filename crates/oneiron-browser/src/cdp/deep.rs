//! A CDP message nested past serde_json's recursion limit (FIX 6963): a
//! `DOM.getDocument` at `depth: -1` of a page nested deeper than about 60
//! elements writes two JSON levels for each. The pipe reads such a message
//! with an explicit stack instead ([`parse`]), however deep it nests, and a
//! value it read that way is taken apart the same way ([`dismantle`]), never
//! by a recursion that grows with its depth. No depth ceiling replaces the
//! limit: the nesting a message has is the nesting it is read with.

use serde_json::{Map, Value};

/// Whether serde_json stopped reading a message at its recursion limit:
/// its only error that a valid message gives.
pub(super) fn nested_past_limit(error: &serde_json::Error) -> bool {
    error.to_string().starts_with("recursion limit exceeded")
}

/// A container the reader is inside, with what it read of it so far.
enum Open {
    Array(Vec<Value>),
    /// An object, and the key of the value it waits for.
    Object(Map<String, Value>, String),
}

/// Reads `bytes` as one JSON value with an explicit stack. Each string,
/// number and literal is read by serde_json itself, which never nests for
/// one; only the containers are this reader's.
pub(super) fn parse(bytes: &[u8]) -> Result<Value, String> {
    let mut stack: Vec<Open> = Vec::new();
    let mut at = 0;
    loop {
        at = blank(bytes, at);
        let mut value = match bytes.get(at) {
            Some(b'{') => {
                at = blank(bytes, at + 1);
                if bytes.get(at) == Some(&b'}') {
                    at += 1;
                    Value::Object(Map::new())
                } else {
                    let (key, after) = key(bytes, at)?;
                    at = after;
                    stack.push(Open::Object(Map::new(), key));
                    continue;
                }
            }
            Some(b'[') => {
                at = blank(bytes, at + 1);
                if bytes.get(at) == Some(&b']') {
                    at += 1;
                    Value::Array(Vec::new())
                } else {
                    stack.push(Open::Array(Vec::new()));
                    continue;
                }
            }
            Some(_) => {
                let (value, after) = scalar(bytes, at)?;
                at = after;
                value
            }
            None => return Err(cut(at)),
        };
        // The value read goes into the container it is in; each container
        // its last value ends is closed, and goes into its own.
        loop {
            let Some(open) = stack.last_mut() else {
                return if blank(bytes, at) == bytes.len() {
                    Ok(value)
                } else {
                    Err(format!("bytes follow the message at {at}"))
                };
            };
            at = blank(bytes, at);
            let next = bytes.get(at).copied();
            match open {
                Open::Array(items) => {
                    items.push(value);
                    match next {
                        Some(b',') => {
                            at += 1;
                            break;
                        }
                        Some(b']') => at += 1,
                        _ => return Err(cut(at)),
                    }
                }
                Open::Object(map, key_now) => {
                    map.insert(std::mem::take(key_now), value);
                    match next {
                        Some(b',') => {
                            let (key, after) = key(bytes, blank(bytes, at + 1))?;
                            *key_now = key;
                            at = after;
                            break;
                        }
                        Some(b'}') => at += 1,
                        _ => return Err(cut(at)),
                    }
                }
            }
            value = match stack.pop() {
                Some(Open::Array(items)) => Value::Array(items),
                Some(Open::Object(map, _)) => Value::Object(map),
                None => return Err(cut(at)),
            };
        }
    }
}

/// Takes `value` apart with an explicit stack: each container gives up its
/// values before it is dropped, so dropping it never nests.
pub(crate) fn dismantle(value: Value) {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Array(items) => stack.extend(items),
            Value::Object(map) => stack.extend(map.into_iter().map(|(_, value)| value)),
            _ => {}
        }
    }
}

/// An object's key at `at` and its `:`: the key, and where its value
/// starts.
fn key(bytes: &[u8], at: usize) -> Result<(String, usize), String> {
    let end = string_end(bytes, at).ok_or_else(|| cut(at))?;
    let key = serde_json::from_slice::<String>(&bytes[at..end]).map_err(|e| e.to_string())?;
    let colon = blank(bytes, end);
    if bytes.get(colon) != Some(&b':') {
        return Err(cut(colon));
    }
    Ok((key, colon + 1))
}

/// The string, number or literal at `at`, read by serde_json, and where it
/// ends.
fn scalar(bytes: &[u8], at: usize) -> Result<(Value, usize), String> {
    let end = if bytes.get(at) == Some(&b'"') {
        string_end(bytes, at).ok_or_else(|| cut(at))?
    } else {
        let len = bytes[at..]
            .iter()
            .position(|byte| matches!(byte, b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n'))
            .unwrap_or(bytes.len() - at);
        at + len
    };
    let value = serde_json::from_slice::<Value>(&bytes[at..end]).map_err(|e| e.to_string())?;
    Ok((value, end))
}

/// Past the closing quote of the string whose opening quote is at `at`.
fn string_end(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'"') {
        return None;
    }
    let mut escaped = false;
    for (offset, &byte) in bytes.get(at + 1..)?.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some(at + offset + 2);
        }
    }
    None
}

/// Past the blanks JSON allows at `at`.
fn blank(bytes: &[u8], at: usize) -> usize {
    let blanks = bytes.get(at..).map_or(0, |rest| {
        rest.iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .count()
    });
    at + blanks
}

/// The message ends, or reads wrong, at `at`.
fn cut(at: usize) -> String {
    format!("the message does not read as JSON at {at}")
}
