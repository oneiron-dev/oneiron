//! One call of a tool translated from an API document (L8-31 D7): the
//! request its stamped [`HttpOperation`] and the frozen arguments make, sent
//! once inside the credential door.
//!
//! The operation is the one the owner stamped: the tool's row on the
//! governing key's routing slate, read at the send. The call goes to the
//! installed endpoint and nowhere else: the operation's path is appended
//! under the endpoint's own path, each path argument fills its place as one
//! percent-encoded segment, and the URL that results is checked to keep the
//! endpoint's origin and path. The JSON body is the `body` member's bytes as
//! the frozen call encodes its arguments; that encoding is canonical (the
//! view's decode re-encodes it byte for byte), so these are the bytes
//! consent was given on, never a re-serialization of a changed value.
//!
//! The credential goes in the `Authorization` header the door builds, as an
//! MCP send's does, and the operation's idempotency header carries the
//! call's intent key, so a recovery that sends again sends the same key.
//! The reply is the tool's foreign reply, read up to a bound: a 2xx JSON
//! object is its structured content, the body's text its content, and a
//! status outside 2xx an error naming it. A 5xx may have acted, so it is
//! ambiguous; a 429 keeps the provider's wait. Everything the API said is
//! cleared of the presented value before it leaves.

use std::collections::BTreeMap;
use std::io::Read;

use oneiron::EntityId;
use oneiron::connector_key::{HttpMethod, HttpOperation};
use oneiron::outbound_consent::{FrozenToolCallView, RawOutboundBody, UntrustedToolResult};
use oneiron::outbound_intent_ledger::{FrozenOutboundCall, OutboundFailureKind};
use oneiron::secret_custody::{SentPresentation, SentValue};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode, Url};
use serde_json::value::RawValue;
use serde_json::{Value, json};

use super::presenting::{CallExchange, Presenting};
use super::{CALL_TIMEOUT, Sent, ServedConnectorCallHost};
use crate::connector_translate::BODY_ARGUMENT;

/// The most of a reply body the host reads. A longer one is unreadable,
/// and the call, which went, is ambiguous.
const REPLY_BOUND: u64 = 16 * 1024 * 1024;

impl ServedConnectorCallHost {
    /// Sends `call` to the HTTP API installed under its server name, through
    /// `presenting`'s door. Nothing leaves when the stamped row names no
    /// operation, the arguments do not fill it, or the operation's
    /// idempotency header has no intent key to carry.
    pub(super) fn send_http_operation(
        &self,
        call: &FrozenOutboundCall,
        view: &FrozenToolCallView,
        presenting: Option<Presenting>,
        presented: &mut Option<SentPresentation>,
    ) -> Sent {
        let Some(key_ref) = view.key_ref().and_then(|hex| EntityId::from_hex(hex).ok()) else {
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        };
        let Some(operation) = self.stamped_operation(&key_ref, view.server(), view.tool()) else {
            return Sent::not_sent(OutboundFailureKind::Rejected, None);
        };
        let Ok(arguments) = serde_json::to_vec(view.arguments()) else {
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        };
        let request = match http_call_request(view.endpoint(), &operation, &arguments) {
            Ok(request) => request,
            Err(reason) => {
                tracing::info!(tool = view.tool(), %reason, "connector API call not sent");
                return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
            }
        };
        let Some(headers) = request_headers(view, &operation, call.idempotency_key()) else {
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        };
        let Some(presenting) = presenting else {
            return Sent::not_sent(OutboundFailureKind::Rejected, None);
        };
        let exchange = HttpApiExchange {
            client: &self.client,
            request,
            headers,
        };
        // The door reads the call's issuer binding again (FIX 9303).
        presenting.send(
            &self.vault,
            &exchange,
            Some((&key_ref, view.tool())),
            presented,
        )
    }

    /// The operation the owner stamped for `tool`: its row on the governing
    /// key's slate, else on the catalog key's, as the call's class is read.
    fn stamped_operation(
        &self,
        key_ref: &EntityId,
        server: &str,
        tool: &str,
    ) -> Option<HttpOperation> {
        let governing = self.vault.get_connector_key(key_ref).ok().flatten();
        let catalog = self
            .vault
            .route_connector_call(server)
            .ok()
            .flatten()
            .and_then(|route| self.vault.get_connector_key(&route.key_ref).ok().flatten());
        [governing, catalog]
            .into_iter()
            .flatten()
            .filter_map(|key| key.slate_ref)
            .find_map(|slate_ref| {
                let slate = self.vault.connector_slate(slate_ref).ok().flatten()?;
                slate.tool(tool).map(|row| row.http.clone())
            })
            .flatten()
    }
}

/// The call's own headers: each header argument the frozen call separated
/// out, and the intent key in the operation's idempotency header. `None`
/// when a value is no header, an argument names a header the request sets
/// itself, or the idempotency header has no key to carry.
fn request_headers(
    view: &FrozenToolCallView,
    operation: &HttpOperation,
    idempotency_key: Option<&str>,
) -> Option<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in view.headers() {
        if name == "accept" {
            return None;
        }
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).ok()?,
            HeaderValue::from_str(value).ok()?,
        );
    }
    if let Some(header) = &operation.idempotency_header {
        let name = HeaderName::from_bytes(header.as_bytes()).ok()?;
        if headers.contains_key(&name) {
            return None;
        }
        headers.insert(name, HeaderValue::from_str(idempotency_key?).ok()?);
    }
    Some(headers)
}

/// One API request, built before the door opens.
struct HttpApiExchange<'a> {
    client: &'a reqwest::blocking::Client,
    request: HttpCallRequest,
    headers: HeaderMap,
}

impl CallExchange for HttpApiExchange<'_> {
    fn run(&self, auth: Option<HeaderValue>, value: Option<&SentValue<'_>>) -> Sent {
        let mut request = self
            .client
            .request(method(self.request.method), self.request.url.clone())
            .timeout(CALL_TIMEOUT)
            .headers(self.headers.clone())
            .header(ACCEPT, "application/json");
        if let Some(auth) = auth {
            request = request.header(AUTHORIZATION, auth);
        }
        if let Some(body) = &self.request.body {
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone());
        }
        match request.send() {
            Ok(response) => answered(response, value),
            // A refused connection never reached the API.
            Err(error) if error.is_connect() || error.is_builder() => {
                Sent::not_sent(OutboundFailureKind::TransportNotStarted, None)
            }
            Err(_) => Sent::ambiguous("connector_no_reply"),
        }
    }
}

fn method(method: HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Head => Method::HEAD,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
    }
}

/// What the API answered, read up to [`REPLY_BOUND`] and cleared of
/// `value`.
fn answered(response: reqwest::blocking::Response, value: Option<&SentValue<'_>>) -> Sent {
    let status = response.status();
    if status.is_server_error() {
        // The API may have acted before it failed.
        return Sent::ambiguous("connector_server_error");
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        // Refused for rate before it acted: the send waits (FIX 11025).
        return Sent::refused_status(status, response.headers());
    }
    let mut bytes = Vec::new();
    if response
        .take(REPLY_BOUND + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > REPLY_BOUND
    {
        zeroize::Zeroize::zeroize(&mut bytes);
        return Sent::ambiguous("connector_reply_unreadable");
    }
    if let Some(value) = value {
        value.clear_bytes(&mut bytes);
    }
    let reply = http_reply(status, &bytes);
    Sent::acked(Some(reply), RawOutboundBody::from_bytes(bytes))
}

/// The reply as the tool's foreign reply: the body's text as its content, a
/// 2xx JSON object as its structured content, and a status outside 2xx as
/// an error whose first block names it.
fn http_reply(status: StatusCode, bytes: &[u8]) -> UntrustedToolResult {
    let success = status.is_success();
    let mut content = Vec::new();
    if !success {
        content.push(json!({"type": "text", "text": format!("HTTP {}", status.as_u16())}));
    }
    if !bytes.is_empty() {
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text.to_owned(),
            Err(_) => format!("({} bytes that are not text)", bytes.len()),
        };
        content.push(json!({"type": "text", "text": text}));
    }
    let structured_content = success
        .then(|| serde_json::from_slice::<Value>(bytes).ok())
        .flatten()
        .filter(Value::is_object);
    UntrustedToolResult {
        content: Value::Array(content),
        structured_content,
        is_error: !success,
        rpc_error: None,
    }
}

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
    #[test]
    fn a_2xx_object_is_structured_content_and_a_4xx_is_an_error_naming_its_status() {
        let ok = http_reply(StatusCode::OK, br#"{"id":"n1","text":"hi"}"#);
        assert!(!ok.is_error);
        assert_eq!(
            ok.structured_content,
            Some(json!({"id": "n1", "text": "hi"}))
        );
        assert_eq!(ok.content[0]["text"], r#"{"id":"n1","text":"hi"}"#);

        let list = http_reply(StatusCode::OK, br#"[1,2]"#);
        assert_eq!(list.structured_content, None);
        assert_eq!(list.content[0]["text"], "[1,2]");

        let missing = http_reply(StatusCode::NOT_FOUND, br#"{"error":"no note"}"#);
        assert!(missing.is_error);
        assert_eq!(missing.structured_content, None);
        assert_eq!(missing.content[0]["text"], "HTTP 404");
        assert_eq!(missing.content[1]["text"], r#"{"error":"no note"}"#);

        let empty = http_reply(StatusCode::NO_CONTENT, b"");
        assert_eq!(empty.content, json!([]));
        assert!(!empty.is_error);
    }
}
