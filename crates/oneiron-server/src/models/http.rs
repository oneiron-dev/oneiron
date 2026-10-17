//! The HTTP leg every provider kind shares: one client per provider entry,
//! and the server-sent-events splitter that streamed replies arrive in.
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::Stream;
use serde_json::Value as JsonValue;

use super::sse::{EventTooLarge, SseDecoder, SseEvent};
use crate::config::models::{ProviderConfig, RequestCodec, RequestCompression};

/// The smallest request body worth compressing (ARCH-0081 §6).
const MIN_COMPRESSED_BYTES: usize = 16 * 1024;
const GZIP_LEVEL: u32 = 1;
const ZSTD_LEVEL: i32 = 3;

/// How a provider expects its key.
#[derive(Clone, Copy, Debug)]
pub(super) enum KeyStyle {
    /// `Authorization: Bearer <key>` (OpenAI-compatible servers).
    Bearer,
    /// `x-api-key: <key>` (Anthropic-compatible servers, Cartesia).
    ApiKeyHeader,
    /// The key under a header of the provider's own name (ElevenLabs'
    /// `xi-api-key`).
    Named(&'static str),
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
    /// A reply body grew past [`MAX_REPLY_BYTES`] before it ended.
    BodyTooLarge,
}

/// The most one whole reply body may hold: a JSON reply, or the body of a
/// streamed call's error status. Far above any reply a provider sends (a
/// whole long answer with its usage), so only a broken provider or proxy
/// reaches it.
pub(super) const MAX_REPLY_BYTES: usize = 16 << 20;

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

/// The largest reply one media exchange may carry: a generated clip.
pub(super) const MAX_MEDIA_REPLY_BYTES: usize = 512 << 20;

/// A finished exchange whose body is whatever the protocol sends: JSON, or
/// media bytes.
pub(super) struct BytesReply {
    pub(super) status: u16,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) body: Vec<u8>,
}

/// What one media exchange sends.
pub(super) enum MediaSend {
    Get,
    Delete,
    Json(JsonValue),
    Multipart(reqwest::multipart::Form),
    /// A framed binary body (`application/octet-stream`).
    Octets(Vec<u8>),
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
    /// The same client with no provider header and no key: what a file the
    /// provider redirects to elsewhere is fetched with.
    bare: reqwest::Client,
    base_url: String,
    /// How JSON request bodies go, shared by every clone of this client.
    compression: Option<Arc<Compressor>>,
}

/// One provider's request compression, on until the provider refuses an
/// encoded body: a 400 or 415 that a plain resend does not repeat turns it
/// off for this process.
struct Compressor {
    compression: RequestCompression,
    on: AtomicBool,
}

impl Compressor {
    /// `plain` in this provider's codec, for a post to `path`: `None` when
    /// it is off, the route is not one it decodes on, the body is under
    /// [`MIN_COMPRESSED_BYTES`], or encoding would not make it smaller.
    fn encode(&self, path: &str, plain: &[u8]) -> Option<Vec<u8>> {
        if !self.on.load(Ordering::Relaxed)
            || self.compression.route.is_some_and(|route| route != path)
            || plain.len() < MIN_COMPRESSED_BYTES
        {
            return None;
        }
        let encoded = match self.compression.codec {
            RequestCodec::Gzip => {
                let mut encoder = flate2::write::GzEncoder::new(
                    Vec::with_capacity(plain.len() / 2),
                    flate2::Compression::new(GZIP_LEVEL),
                );
                encoder.write_all(plain).ok()?;
                encoder.finish().ok()?
            }
            RequestCodec::Zstd => zstd::stream::encode_all(plain, ZSTD_LEVEL).ok()?,
        };
        (encoded.len() < plain.len()).then_some(encoded)
    }

    fn token(&self) -> &'static str {
        match self.compression.codec {
            RequestCodec::Gzip => "gzip",
            RequestCodec::Zstd => "zstd",
        }
    }
}

/// One JSON post in flight, owning all it sends.
type Sending = Pin<Box<dyn Future<Output = Result<reqwest::Response, reqwest::Error>> + Send>>;

impl ProviderHttp {
    /// Builds the client. A configured `key_env` that is unset or empty is a
    /// refusal here, so a seat never runs half-authenticated.
    pub(super) fn new(provider: &ProviderConfig, style: KeyStyle) -> anyhow::Result<Self> {
        Self::build(provider, style, false)
    }

    /// Builds a client that never goes through an environment proxy: a
    /// loopback URL is only a loopback destination when no proxy applies.
    pub(super) fn direct(provider: &ProviderConfig, style: KeyStyle) -> anyhow::Result<Self> {
        Self::build(provider, style, true)
    }

    fn build(provider: &ProviderConfig, style: KeyStyle, direct: bool) -> anyhow::Result<Self> {
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
                KeyStyle::Named(name) => (reqwest::header::HeaderName::from_static(name), key),
            };
            let mut value = reqwest::header::HeaderValue::from_str(&value)?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        // One request per call (`SingleSend`): a redirect is answered, never
        // followed, and nothing is sent twice. reqwest's default policy would
        // resend a request an HTTP/2 server refused at the protocol level.
        let builder = || {
            let builder = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(provider.timeout_secs.min(30)))
                .timeout(Duration::from_secs(provider.timeout_secs));
            if direct { builder.no_proxy() } else { builder }
        };
        let client = builder().default_headers(headers).build()?;
        let bare = builder().build()?;
        Ok(Self {
            client,
            bare,
            base_url: provider.base_url.clone(),
            compression: provider.request_compression.map(|compression| {
                Arc::new(Compressor {
                    compression,
                    on: AtomicBool::new(true),
                })
            }),
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

    /// The server's own root: a base that ends in `/v1` drops it, so a
    /// llama.cpp native path (`/completion`) is reached under any prefix.
    pub(super) fn native(&self) -> Self {
        Self {
            client: self.client.clone(),
            bare: self.bare.clone(),
            base_url: self
                .base_url
                .strip_suffix("/v1")
                .unwrap_or(&self.base_url)
                .to_owned(),
            compression: self.compression.clone(),
        }
    }

    fn request(&self, path: &str, headers: &BTreeMap<String, String>) -> reqwest::RequestBuilder {
        let mut request = self.client.post(self.url(path));
        if !headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-type"))
        {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        for (name, value) in headers {
            request = request.header(name, value);
        }
        request
    }

    /// Posts `body` as JSON, compressed when this provider's route takes it
    /// (ARCH-0081 §6). A 400 or 415 to a compressed body is sent once more,
    /// plain; when the plain answer differs, the encoding was the cause and
    /// compression turns off for this process.
    fn post(&self, path: &str, headers: &BTreeMap<String, String>, body: &JsonValue) -> Sending {
        let plain = serde_json::to_vec(body).unwrap_or_default();
        let request = self.request(path, headers);
        let encoded = self.compression.as_ref().and_then(|compressor| {
            Some((Arc::clone(compressor), compressor.encode(path, &plain)?))
        });
        let Some((compressor, encoded)) = encoded else {
            return Box::pin(request.body(plain).send());
        };
        let resend = self.request(path, headers);
        Box::pin(async move {
            let response = request
                .header(reqwest::header::CONTENT_ENCODING, compressor.token())
                .body(encoded)
                .send()
                .await?;
            if !matches!(response.status().as_u16(), 400 | 415) {
                return Ok(response);
            }
            let refused = response.status();
            drop(response);
            let response = resend.body(plain).send().await?;
            if response.status() != refused {
                compressor.on.store(false, Ordering::Relaxed);
                tracing::warn!(
                    status = refused.as_u16(),
                    codec = compressor.token(),
                    "a provider refused a compressed request body; sending plain from now on"
                );
            }
            Ok(response)
        })
    }

    pub(super) async fn post_json(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
    ) -> Result<JsonReply, HttpFailure> {
        self.post_json_within(path, headers, body, MAX_REPLY_BYTES)
            .await
    }

    /// [`Self::post_json`], with a reply bound of the caller's.
    pub(super) async fn post_json_within(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
        max_bytes: usize,
    ) -> Result<JsonReply, HttpFailure> {
        let response = self.post(path, headers, body).await?;
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let bytes = bounded_body(response, max_bytes).await?;
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

    /// One media exchange at `path`, its reply body read whole up to
    /// [`MAX_MEDIA_REPLY_BYTES`]. One request, as every exchange here.
    pub(super) async fn send_media(
        &self,
        path: &str,
        send: MediaSend,
    ) -> Result<BytesReply, HttpFailure> {
        let url = self.url(path);
        let request = match send {
            MediaSend::Get => self.client.get(url),
            MediaSend::Delete => self.client.delete(url),
            MediaSend::Json(body) => self.client.post(url).json(&body),
            MediaSend::Multipart(form) => self.client.post(url).multipart(form),
            MediaSend::Octets(body) => self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(body),
        };
        let response = request.send().await?;
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let body = bounded_body(response, MAX_MEDIA_REPLY_BYTES).await?;
        Ok(BytesReply {
            status,
            headers,
            body,
        })
    }

    /// A file the provider named by its full URI, read whole up to
    /// [`MAX_MEDIA_REPLY_BYTES`]. The key goes only to the provider's own
    /// origin; one redirect from there is followed, without the key or any
    /// provider header when it leaves that origin (a clip served from
    /// storage).
    pub(super) async fn fetch_media(&self, uri: &str) -> Result<BytesReply, HttpFailure> {
        let origin = reqwest::Url::parse(&self.base_url)
            .map_err(|_| HttpFailure::Connection)?
            .origin();
        let target = reqwest::Url::parse(uri).map_err(|_| HttpFailure::Malformed)?;
        if target.origin() != origin {
            return Err(HttpFailure::Malformed);
        }
        let mut response = self.client.get(target.clone()).send().await?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|location| location.to_str().ok())
                .and_then(|location| target.join(location).ok())
                .filter(|location| location.scheme() == "https")
                .ok_or(HttpFailure::Malformed)?;
            let client = if location.origin() == origin {
                &self.client
            } else {
                &self.bare
            };
            response = client.get(location).send().await?;
        }
        let status = response.status().as_u16();
        let headers = reply_headers(&response);
        let body = bounded_body(response, MAX_MEDIA_REPLY_BYTES).await?;
        Ok(BytesReply {
            status,
            headers,
            body,
        })
    }

    /// Starts a streamed exchange. A non-2xx answer arrives as one
    /// [`SseItem::Status`] (or [`HttpFailure::BodyTooLarge`]); a 2xx answer
    /// as its events, in order.
    pub(super) fn post_sse(
        &self,
        path: &str,
        headers: &BTreeMap<String, String>,
        body: &JsonValue,
    ) -> impl Stream<Item = Result<SseItem, HttpFailure>> + Send + 'static {
        let sending = self.post(path, headers, body);
        futures_util::stream::unfold(SseState::Start(sending), next_sse)
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

/// Reads a whole reply body. One whose declared length, or whose bytes so
/// far, pass `max_bytes` is refused there; the rest is never read.
async fn bounded_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, HttpFailure> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(HttpFailure::BodyTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > max_bytes {
            return Err(HttpFailure::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// One unit of a streamed exchange.
pub(super) enum SseItem {
    Status(JsonReply),
    Event(SseEvent),
}

enum SseState {
    Start(Sending),
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
        SseState::Start(sending) => {
            let response = match sending.await {
                Ok(response) => response,
                Err(error) => return Some((Err(error.into()), SseState::Done)),
            };
            if !response.status().is_success() {
                let status = response.status().as_u16();
                let headers = reply_headers(&response);
                let body = match bounded_body(response, MAX_REPLY_BYTES).await {
                    Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(JsonValue::Null),
                    Err(HttpFailure::BodyTooLarge) => {
                        return Some((Err(HttpFailure::BodyTooLarge), SseState::Done));
                    }
                    Err(_) => JsonValue::Null,
                };
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
