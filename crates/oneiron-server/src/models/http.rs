//! The HTTP leg every provider kind shares: one client per provider entry,
//! and the server-sent-events splitter that streamed replies arrive in.
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use futures_util::Stream;
use serde_json::Value as JsonValue;

use super::sse::{EventTooLarge, SseDecoder, SseEvent};
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
    /// A streamed event grew past the decoder's bound before it ended.
    EventTooLarge,
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

enum SseState {
    Start(reqwest::RequestBuilder),
    Reading {
        response: reqwest::Response,
        decoder: SseDecoder,
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
                decoder: SseDecoder::default(),
                ready: VecDeque::new(),
            }))
            .await
        }
        SseState::Reading {
            mut response,
            mut decoder,
            mut ready,
        } => loop {
            if let Some(event) = ready.pop_front() {
                return Some((
                    Ok(SseItem::Event(event)),
                    SseState::Reading {
                        response,
                        decoder,
                        ready,
                    },
                ));
            }
            match response.chunk().await {
                Ok(Some(chunk)) => match decoder.push(&chunk) {
                    Ok(events) => ready.extend(events),
                    Err(EventTooLarge) => {
                        return Some((Err(HttpFailure::EventTooLarge), SseState::Done));
                    }
                },
                Ok(None) => {
                    ready.extend(decoder.finish());
                    let event = ready.pop_front()?;
                    return Some((
                        Ok(SseItem::Event(event)),
                        SseState::Reading {
                            response,
                            decoder,
                            ready,
                        },
                    ));
                }
                Err(error) => return Some((Err(error.into()), SseState::Done)),
            }
        },
    }
}
