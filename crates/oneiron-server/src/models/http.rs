//! The HTTP leg every provider kind shares: one client per provider entry,
//! and the server-sent-events splitter that streamed replies arrive in.
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use futures_util::Stream;
use serde_json::Value as JsonValue;

use crate::config::models::ProviderConfig;

/// How a provider expects its key.
#[derive(Clone, Copy, Debug)]
pub(super) enum KeyStyle {
    /// `Authorization: Bearer <key>` (OpenAI-compatible servers).
    Bearer,
    /// `x-api-key: <key>` (Anthropic-compatible servers).
    ApiKeyHeader,
}

/// Why an HTTP exchange failed before any provider status arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HttpFailure {
    Timeout,
    Connection,
    StreamCut,
    /// The reply was not the JSON the protocol promises.
    Malformed,
}

impl From<reqwest::Error> for HttpFailure {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_decode() || error.is_body() {
            Self::StreamCut
        } else {
            Self::Connection
        }
    }
}

/// A finished, non-streamed exchange.
pub(super) struct JsonReply {
    pub(super) status: u16,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) body: JsonValue,
}

/// One provider's client: base URL, default headers and its timeout.
#[derive(Clone)]
pub(super) struct ProviderHttp {
    client: reqwest::Client,
    base_url: String,
}

impl ProviderHttp {
    /// Builds the client. A configured `key_env` that is unset or empty is a
    /// refusal here, so a seat never runs half-authenticated.
    pub(super) fn new(provider: &ProviderConfig, style: KeyStyle) -> anyhow::Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &provider.headers {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
                reqwest::header::HeaderValue::from_str(value)?,
            );
        }
        if let Some(env) = &provider.key_env {
            let key = std::env::var(env)
                .ok()
                .filter(|key| !key.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("{env} is not set"))?;
            let (name, value) = match style {
                KeyStyle::Bearer => (reqwest::header::AUTHORIZATION, format!("Bearer {key}")),
                KeyStyle::ApiKeyHeader => {
                    (reqwest::header::HeaderName::from_static("x-api-key"), key)
                }
            };
            let mut value = reqwest::header::HeaderValue::from_str(&value)?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(provider.timeout_secs.min(30)))
            .timeout(Duration::from_secs(provider.timeout_secs))
            .build()?;
        Ok(Self {
            client,
            base_url: provider.base_url.clone(),
        })
    }

    /// Joins the base URL and a protocol path. A base that already ends in
    /// `/v1` absorbs the path's own `/v1`, so both spellings of a base work.
    pub(super) fn url(&self, path: &str) -> String {
        match (self.base_url.strip_suffix("/v1"), path.strip_prefix("/v1/")) {
            (Some(base), Some(rest)) => format!("{base}/v1/{rest}"),
            _ => format!("{}{path}", self.base_url),
        }
    }

    fn post(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
    ) -> reqwest::RequestBuilder {
        let mut request = self.client.post(self.url(path)).json(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        request
    }

    pub(super) async fn post_json(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
    ) -> Result<JsonReply, HttpFailure> {
        let response = self.post(path, headers, body).send().await?;
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let bytes = response.bytes().await?;
        let body = if bytes.is_empty() {
            JsonValue::Null
        } else {
            match serde_json::from_slice(&bytes) {
                Ok(body) => body,
                Err(_) if !(200..300).contains(&status) => JsonValue::Null,
                Err(_) => return Err(HttpFailure::Malformed),
            }
        };
        Ok(JsonReply {
            status,
            headers,
            body,
        })
    }

    /// Starts a streamed exchange. A non-2xx answer arrives as one
    /// [`SseItem::Status`]; a 2xx answer as its events, in order.
    pub(super) fn post_sse(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
    ) -> impl Stream<Item = Result<SseItem, HttpFailure>> + Send + 'static {
        let request = self.post(path, headers, body);
        futures_util::stream::unfold(SseState::Start(request), next_sse)
    }
}

fn reply_headers(response: &reqwest::Response) -> BTreeMap<String, String> {
    response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

/// One unit of a streamed exchange.
pub(super) enum SseItem {
    Status(JsonReply),
    Event(SseEvent),
}

/// One server-sent event: its optional `event:` name and its joined data.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SseEvent {
    pub(super) event: Option<String>,
    pub(super) data: String,
}

enum SseState {
    Start(reqwest::RequestBuilder),
    Reading {
        response: reqwest::Response,
        buffer: Vec<u8>,
        ready: VecDeque<SseEvent>,
    },
    Done,
}

async fn next_sse(state: SseState) -> Option<(Result<SseItem, HttpFailure>, SseState)> {
    match state {
        SseState::Done => None,
        SseState::Start(request) => {
            let response = match request.send().await {
                Ok(response) => response,
                Err(error) => return Some((Err(error.into()), SseState::Done)),
            };
            if !response.status().is_success() {
                let status = response.status().as_u16();
                let headers = reply_headers(&response);
                let body = response
                    .bytes()
                    .await
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                    .unwrap_or(JsonValue::Null);
                return Some((
                    Ok(SseItem::Status(JsonReply {
                        status,
                        headers,
                        body,
                    })),
                    SseState::Done,
                ));
            }
            Box::pin(next_sse(SseState::Reading {
                response,
                buffer: Vec::new(),
                ready: VecDeque::new(),
            }))
            .await
        }
        SseState::Reading {
            mut response,
            mut buffer,
            mut ready,
        } => loop {
            if let Some(event) = ready.pop_front() {
                return Some((
                    Ok(SseItem::Event(event)),
                    SseState::Reading {
                        response,
                        buffer,
                        ready,
                    },
                ));
            }
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    buffer.extend_from_slice(&chunk);
                    ready.extend(split_events(&mut buffer));
                }
                Ok(None) => {
                    // A final event without its blank line still counts.
                    buffer.extend_from_slice(b"\n\n");
                    let tail = split_events(&mut buffer);
                    if tail.is_empty() {
                        return None;
                    }
                    ready.extend(tail);
                    let event = ready.pop_front()?;
                    return Some((
                        Ok(SseItem::Event(event)),
                        SseState::Reading {
                            response,
                            buffer,
                            ready,
                        },
                    ));
                }
                Err(error) => return Some((Err(error.into()), SseState::Done)),
            }
        },
    }
}

/// Removes every complete event (a block ending in a blank line) from
/// `buffer`. Comments and fields other than `event` and `data` are dropped.
pub(super) fn split_events(buffer: &mut Vec<u8>) -> Vec<SseEvent> {
    let mut events = Vec::new();
    loop {
        let normalized = buffer.windows(2).position(|pair| pair == b"\n\n");
        let crlf = buffer.windows(4).position(|quad| quad == b"\r\n\r\n");
        let (end, skip) = match (normalized, crlf) {
            (Some(lf), Some(cr)) if cr < lf => (cr, 4),
            (Some(lf), _) => (lf, 2),
            (None, Some(cr)) => (cr, 4),
            (None, None) => return events,
        };
        let block: Vec<u8> = buffer.drain(..end + skip).take(end).collect();
        let block = String::from_utf8_lossy(&block);
        let mut event = None;
        let mut data: Vec<&str> = Vec::new();
        for line in block.lines() {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "event" => event = Some(value.to_owned()),
                "data" => data.push(value),
                _ => {}
            }
        }
        if !data.is_empty() {
            events.push(SseEvent {
                event,
                data: data.join("\n"),
            });
        }
    }
}
