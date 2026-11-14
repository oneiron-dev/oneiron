//! One call of a tool translated from an API document (L8-31 D7): the
//! request its stamped [`HttpOperation`] and the frozen arguments make.
//!
//! The call goes to the installed endpoint and nowhere else: the operation's
//! path is appended under the endpoint's own path, each path argument fills
//! its place as one percent-encoded segment, and the URL that results is
//! checked to keep the endpoint's origin and path. The JSON body is the
//! `body` member's own bytes in the consent-bound argument buffer, never a
//! re-serialization of it.

use std::collections::BTreeMap;

use oneiron::connector_key::{HttpMethod, HttpOperation};
use reqwest::Url;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::connector_translate::BODY_ARGUMENT;

/// The request one call sends, before its headers.
#[derive(Debug)]
pub(super) struct HttpCallRequest {
    pub(super) method: HttpMethod,
    pub(super) url: Url,
    /// The JSON request body, when the operation takes one and the call
    /// gives it.
    pub(super) body: Option<Vec<u8>>,
}

/// The request for `arguments` (the frozen call's JSON object) under
/// `endpoint`. A refusal names the argument; nothing has been sent.
pub(super) fn http_call_request(
    endpoint: &str,
    operation: &HttpOperation,
    arguments: &[u8],
) -> Result<HttpCallRequest, String> {
    let base =
        Url::parse(endpoint).map_err(|_| "the installed endpoint is not a URL".to_owned())?;
    let members: BTreeMap<String, &RawValue> = serde_json::from_slice(arguments)
        .map_err(|_| "the call's arguments are not a JSON object".to_owned())?;
    let value = |name: &str| -> Result<Option<Value>, String> {
        members
            .get(name)
            .map(|raw| serde_json::from_str::<Value>(raw.get()))
            .transpose()
            .map_err(|_| format!("argument {name} is not JSON"))
    };

    let mut path = String::new();
    let mut rest = operation.path.as_str();
    while let Some(open) = rest.find('{') {
        path.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after
            .find('}')
            .ok_or_else(|| "the stamped path has an unclosed `{`".to_owned())?;
        let name = &after[..close];
        let text = match value(name)? {
            Some(argument) => scalar_text(&argument).ok_or_else(|| {
                format!("path argument {name} is not a string, number or boolean")
            })?,
            None => return Err(format!("path argument {name} is missing")),
        };
        if text.is_empty() || text == "." || text == ".." {
            return Err(format!(
                "path argument {name} is {text:?}, which is no path segment"
            ));
        }
        path.push_str(&encode_segment(&text));
        rest = &after[close + 1..];
    }
    path.push_str(rest);

    let base_path = base.path().trim_end_matches('/');
    let mut url = base.clone();
    url.set_path(&format!("{base_path}{path}"));
    url.set_query(None);
    url.set_fragment(None);
    let mut pairs = Vec::new();
    for name in &operation.query {
        match value(name)? {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in &items {
                    let text = scalar_text(item).ok_or_else(|| {
                        format!("query argument {name} holds a value that is not a scalar")
                    })?;
                    pairs.push((name.as_str(), text));
                }
            }
            Some(argument) => {
                let text = scalar_text(&argument).ok_or_else(|| {
                    format!("query argument {name} is not a scalar or a list of scalars")
                })?;
                pairs.push((name.as_str(), text));
            }
        }
    }
    if !pairs.is_empty() {
        url.query_pairs_mut().extend_pairs(pairs);
    }
    if url.origin() != base.origin() || !url.path().starts_with(base_path) {
        return Err("the call's URL would leave the installed endpoint".to_owned());
    }

    let body = if operation.json_body {
        members
            .get(BODY_ARGUMENT)
            .map(|raw| raw.get().as_bytes().to_vec())
    } else {
        None
    };
    Ok(HttpCallRequest {
        method: operation.method,
        url,
        body,
    })
}

/// A string as itself, a number or a boolean as JSON writes it.
fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Every byte but RFC 3986's unreserved ones percent-encoded, so a value
/// is one segment whatever it holds (`/`, `?`, `#`, `%`).
fn encode_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(method: HttpMethod, path: &str, query: &[&str], json_body: bool) -> HttpOperation {
        HttpOperation {
            method,
            path: path.to_owned(),
            query: query.iter().map(|name| (*name).to_owned()).collect(),
            idempotency_header: None,
            json_body,
        }
    }

    #[test]
    fn a_path_argument_is_one_segment_under_the_endpoint() {
        let request = http_call_request(
            "http://127.0.0.1:9/api/",
            &operation(HttpMethod::Get, "/notes/{id}", &[], false),
            br#"{"id":"n 1/../x?y#z"}"#,
        )
        .unwrap();
        assert_eq!(
            request.url.as_str(),
            "http://127.0.0.1:9/api/notes/n%201%2F..%2Fx%3Fy%23z"
        );
        assert!(request.body.is_none());
    }

    #[test]
    fn a_dot_segment_or_a_missing_path_argument_is_refused() {
        let get = operation(HttpMethod::Get, "/notes/{id}", &[], false);
        for arguments in [r#"{"id":".."}"#, r#"{"id":"."}"#, r#"{"id":""}"#, r#"{}"#] {
            assert!(
                http_call_request("http://127.0.0.1:9/api", &get, arguments.as_bytes()).is_err(),
                "{arguments}"
            );
        }
    }

    #[test]
    fn query_arguments_go_in_order_and_the_body_is_its_own_bytes() {
        let request = http_call_request(
            "https://api.example.com",
            &operation(HttpMethod::Post, "/notes", &["tag", "limit", "skip"], true),
            br#"{"tag":["a b","c&d"],"limit":5,"skip":null,"body":{"z": 1,  "a":[true]}}"#,
        )
        .unwrap();
        assert_eq!(
            request.url.as_str(),
            "https://api.example.com/notes?tag=a+b&tag=c%26d&limit=5"
        );
        assert_eq!(
            request.body.as_deref(),
            Some(&br#"{"z": 1,  "a":[true]}"#[..])
        );
    }
}
