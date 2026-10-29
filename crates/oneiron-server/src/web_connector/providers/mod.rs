//! One adapter per provider: one HTTPS request per call, its answer shaped
//! into search hits or one page, with the provider-reported cost and request
//! id when the response carries them. Each adapter module has `search` and,
//! when its profile reads pages itself, `fetch`, with the signatures of
//! [`tavily`], the reference adapter.
mod brave;
mod context_dev;
mod exa;
mod octen;
mod tavily;
mod tinyfish;

use std::time::Duration;

use oneiron::web_connector::{
    SNIPPET_MAX_CHARS, WebFetchInput, WebProvider, WebSearchHit, WebSearchInput, cut_chars,
};
use reqwest::blocking::Client;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::Value;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// A provider error message's length cap in characters.
const ERROR_MESSAGE_MAX_CHARS: usize = 200;

/// What a provider answered for one call.
pub(super) struct ProviderAnswer {
    pub(super) body: ProviderBody,
    /// The provider-reported cost in micro-USD, when the response carries one.
    pub(super) cost_micro_usd: Option<u64>,
    /// The provider's own id for the request, when the response names one.
    pub(super) request_id: Option<String>,
}

/// Search hits, or one fetched page.
pub(super) enum ProviderBody {
    Hits(Vec<WebSearchHit>),
    Page {
        url: String,
        title: Option<String>,
        content: String,
    },
}

impl ProviderBody {
    /// The result count a usage row records: the hits, or 1 for a page.
    pub(super) fn result_count(&self) -> u32 {
        match self {
            Self::Hits(hits) => u32::try_from(hits.len()).unwrap_or(u32::MAX),
            Self::Page { .. } => 1,
        }
    }
}

/// Why a provider call failed. The message never carries the key.
#[derive(Debug)]
pub(super) struct ProviderError {
    /// The provider's HTTP status, when it answered with one.
    pub(super) status: Option<u16>,
    pub(super) message: String,
}

impl ProviderError {
    pub(super) fn message(message: &str) -> Self {
        Self {
            status: None,
            message: cut_chars(message, ERROR_MESSAGE_MAX_CHARS),
        }
    }

    /// The reason code a usage row records.
    pub(super) fn reason_code(&self) -> String {
        match self.status {
            Some(401 | 403) => "web_provider_key_refused".to_owned(),
            Some(402 | 432 | 433) => "web_provider_out_of_credit".to_owned(),
            Some(429) => "web_provider_rate_limited".to_owned(),
            Some(status) => format!("web_provider_http_{status}"),
            None => "web_provider_unreachable".to_owned(),
        }
    }
}

/// How a provider takes its key.
#[derive(Clone, Copy)]
pub(super) enum Auth {
    /// `Authorization: Bearer <key>`.
    Bearer,
    /// The key as the value of this header.
    Header(&'static str),
}

/// The blocking client every web call sends with: no redirects, no proxy,
/// bounded connect and call time, as the MCP connector host's.
pub(super) fn client() -> Result<Client, ProviderError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(CALL_TIMEOUT)
        .build()
        .map_err(|error| ProviderError::message(&error.to_string()))
}

/// One search on `provider`.
pub(super) fn search(
    provider: WebProvider,
    client: &Client,
    key: &str,
    input: &WebSearchInput,
) -> Result<ProviderAnswer, ProviderError> {
    match provider {
        WebProvider::Tavily => tavily::search(client, key, input),
        WebProvider::Exa => exa::search(client, key, input),
        WebProvider::Brave => brave::search(client, key, input),
        WebProvider::Tinyfish => tinyfish::search(client, key, input),
        WebProvider::ContextDev => context_dev::search(client, key, input),
        WebProvider::Octen => octen::search(client, key, input),
    }
}

/// One page read on `provider`'s own endpoint. Brave has none: its profile
/// sends `fetch` to our own reader, so it never comes here.
pub(super) fn fetch(
    provider: WebProvider,
    client: &Client,
    key: &str,
    input: &WebFetchInput,
) -> Result<ProviderAnswer, ProviderError> {
    match provider {
        WebProvider::Tavily => tavily::fetch(client, key, input),
        WebProvider::Exa => exa::fetch(client, key, input),
        WebProvider::Brave => Err(ProviderError::message("brave has no page reader")),
        WebProvider::Tinyfish => tinyfish::fetch(client, key, input),
        WebProvider::ContextDev => context_dev::fetch(client, key, input),
        WebProvider::Octen => octen::fetch(client, key, input),
    }
}

/// POSTs `body` as JSON to `url` with the key, and reads the JSON answer.
pub(super) fn post_json(
    client: &Client,
    url: &str,
    auth: Auth,
    key: &str,
    body: &Value,
) -> Result<Value, ProviderError> {
    let request = client.post(url).json(body);
    send(with_key(request, auth, key)?)
}

/// GETs `url` with `query` and the key, and reads the JSON answer.
pub(super) fn get_json(
    client: &Client,
    url: &str,
    auth: Auth,
    key: &str,
    query: &[(&str, String)],
) -> Result<Value, ProviderError> {
    let request = client.get(url).query(query);
    send(with_key(request, auth, key)?)
}

fn with_key(
    request: reqwest::blocking::RequestBuilder,
    auth: Auth,
    key: &str,
) -> Result<reqwest::blocking::RequestBuilder, ProviderError> {
    let not_a_header = |_: reqwest::header::InvalidHeaderValue| {
        ProviderError::message("the provider key is not a header value")
    };
    let (name, value) = match auth {
        Auth::Bearer => (
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {key}")),
        ),
        Auth::Header(name) => (
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                ProviderError::message("the provider key header is not a header name")
            })?,
            HeaderValue::from_str(key),
        ),
    };
    let mut value = value.map_err(not_a_header)?;
    value.set_sensitive(true);
    Ok(request
        .header(name, value)
        .header(reqwest::header::ACCEPT, "application/json"))
}

fn send(request: reqwest::blocking::RequestBuilder) -> Result<Value, ProviderError> {
    let response = request
        .send()
        .map_err(|error| ProviderError::message(&error.without_url().to_string()))?;
    let status = response.status();
    let body: Value = response.json().unwrap_or(Value::Null);
    if status.is_success() {
        return Ok(body);
    }
    let message = ["error", "message", "detail"]
        .iter()
        .find_map(|field| match body.get(*field) {
            Some(Value::String(text)) => Some(text.clone()),
            Some(Value::Object(inner)) => ["error", "message", "detail"]
                .iter()
                .find_map(|field| inner.get(*field).and_then(Value::as_str))
                .map(str::to_owned),
            _ => None,
        })
        .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
    Err(ProviderError {
        status: Some(status.as_u16()),
        message: cut_chars(&message, ERROR_MESSAGE_MAX_CHARS),
    })
}

/// One search hit, its snippet cut to [`SNIPPET_MAX_CHARS`].
pub(super) fn hit(title: &str, url: &str, snippet: &str) -> WebSearchHit {
    WebSearchHit {
        title: title.trim().to_owned(),
        url: url.trim().to_owned(),
        snippet: cut_chars(snippet.trim(), SNIPPET_MAX_CHARS),
    }
}

/// The string at `field` of `value`, or "".
pub(super) fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or("")
}

/// The non-empty string at `field` of `value`.
pub(super) fn text_opt(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// `usd` as micro-USD, `None` unless it is a finite non-negative amount.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(super) fn usd_micro(usd: Option<f64>) -> Option<u64> {
    usd.filter(|usd| usd.is_finite() && *usd >= 0.0)
        .map(|usd| (usd * 1_000_000.0).round() as u64)
}
