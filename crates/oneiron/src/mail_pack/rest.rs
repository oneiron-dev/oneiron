//! What the mail pack's REST wires share (Gmail, Microsoft Graph): one
//! HTTPS client shape, one bounded JSON read, the Bearer header for an
//! injected credential, and the text helpers a message body needs.

use std::io::Read;
use std::time::Duration;

use dom_query::Document;
use reqwest::header::HeaderValue;
use serde_json::Value;

use crate::error::{Error, Result};

/// The largest provider answer read: a whole message with its inline parts.
const MAX_REST_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
/// HTML elements whose text is not the message's.
const HTML_IGNORED: [&str; 6] = ["head", "script", "style", "template", "noscript", "title"];
/// HTML elements that start a new line of text.
const HTML_BLOCKS: [&str; 18] = [
    "p",
    "div",
    "br",
    "tr",
    "li",
    "ul",
    "ol",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "blockquote",
    "pre",
    "hr",
    "section",
];

/// One provider answer: its JSON, or a failure status with the provider's
/// error code when its body names one (`error.code`).
pub(super) enum RestAnswer {
    Found(Value),
    Failed { status: u16, code: Option<String> },
}

impl RestAnswer {
    /// The JSON, `None` for the provider's "not found", else an error named
    /// `{wire}_status_{status}`.
    pub(super) fn found_or_gone(self, wire: &str) -> Result<Option<Value>> {
        match self {
            Self::Found(value) => Ok(Some(value)),
            Self::Failed { status: 404, .. } => Ok(None),
            Self::Failed { status, .. } => Err(Error::InvalidConfig(format!(
                "{wire}_status_{status}"
            ))),
        }
    }
}

/// The client every REST wire uses: HTTPS only, no redirects, a 60 s
/// timeout.
pub(super) fn https_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|_| refused("mail_wire_http_client_setup_failed"))
}

/// Sends `request` and reads its answer, bounded.
pub(super) fn send(request: reqwest::blocking::RequestBuilder) -> Result<RestAnswer> {
    let response = request
        .send()
        .map_err(|_| refused("mail_wire_transport_failed"))?;
    let status = response.status();
    let body = read_bounded_json(response);
    if status.is_success() {
        return body
            .map(RestAnswer::Found)
            .ok_or_else(|| refused("mail_wire_response_unreadable"));
    }
    let code = body
        .as_ref()
        .and_then(|body| body.pointer("/error/code"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(RestAnswer::Failed {
        status: status.as_u16(),
        code,
    })
}

fn read_bounded_json(response: reqwest::blocking::Response) -> Option<Value> {
    let mut bytes = Vec::new();
    response
        .take(MAX_REST_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_REST_RESPONSE_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// The sensitive `Authorization: Bearer` value for one injected credential:
/// the bare OAuth access token, or JSON carrying `access_token`.
pub(super) fn bearer_header(token: &[u8]) -> Result<HeaderValue> {
    let invalid = || refused("mail_wire_credential_not_an_access_token");
    let text = std::str::from_utf8(token).map_err(|_| invalid())?.trim();
    let access_token = if text.starts_with('{') {
        let value: Value = serde_json::from_str(text).map_err(|_| invalid())?;
        value
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?
            .trim()
            .to_owned()
    } else {
        text.to_owned()
    };
    if access_token.is_empty() {
        return Err(invalid());
    }
    let mut value =
        HeaderValue::from_str(&format!("Bearer {access_token}")).map_err(|_| invalid())?;
    value.set_sensitive(true);
    Ok(value)
}

pub(super) fn refused(code: &str) -> Error {
    Error::InvalidConfig(code.to_owned())
}

/// The array field `key` of `value`, empty when absent.
pub(super) fn array<'v>(value: &'v Value, key: &str) -> &'v [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// A nonempty string field.
pub(super) fn text_of(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// The value of the header `name` in a `[{name, value}]` header list (a
/// Gmail payload's, a Graph message's `internetMessageHeaders`), if any.
pub(super) fn header_value<'v>(headers: Option<&'v Value>, name: &str) -> Option<&'v str> {
    headers?
        .as_array()?
        .iter()
        .find(|header| {
            header
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|held| held.eq_ignore_ascii_case(name))
        })?
        .get("value")?
        .as_str()
}

/// The visible text of an HTML body, a line per block.
pub(super) fn html_text(html: &str) -> String {
    let document = Document::from(html);
    let mut out = String::new();
    let mut pending = vec![document.root()];
    while let Some(node) = pending.pop() {
        if node.is_text() {
            out.push_str(&node.text());
            continue;
        }
        if let Some(name) = node.node_name() {
            let name = name.to_ascii_lowercase();
            if HTML_IGNORED.contains(&name.as_str()) {
                continue;
            }
            if HTML_BLOCKS.contains(&name.as_str()) && !out.ends_with('\n') {
                out.push('\n');
            }
        }
        let children = node.children_it(false).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    tidy_text(&out)
}

/// Text with each line's runs of whitespace made one space and no more than
/// one blank line in a row.
pub(super) fn tidy_text(text: &str) -> String {
    let mut out = String::new();
    let mut blank = false;
    for line in text.lines() {
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.is_empty() {
            if blank || out.is_empty() {
                continue;
            }
            blank = true;
        } else {
            blank = false;
        }
        out.push_str(&line);
        out.push('\n');
    }
    out.trim_end().to_owned()
}
