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
use oneiron::llm::DispatchRelease;
use oneiron::{BudgetLease, LlmError};
use serde_json::Value as JsonValue;

use super::sse::{EventTooLarge, SseDecoder, SseEvent};
use crate::config::models::{ProviderConfig, RequestCodec, RequestCompression};

mod client;
mod never_sent;
mod reply_line;

pub(super) use reply_line::{ReplyBytes, charge_read, holding_chat_replies, holding_replies};
use reply_line::{read_booked, read_whole};

/// The smallest request body worth compressing (ARCH-0081 §6).
const MIN_COMPRESSED_BYTES: usize = 16 * 1024;

/// Whether this process serves from a cloud node, where gzip costs more on
/// the link than it saves (ARCH-0081 §6): a gzip route then sends plain, and
/// zstd still compresses.
static CLOUD_NODE: AtomicBool = AtomicBool::new(false);

/// Marks this process a cloud node: a managed or host-readable deployment.
pub(crate) fn mark_cloud_node() {
    CLOUD_NODE.store(true, Ordering::Relaxed);
}

/// Whether this process is a cloud node: what the daemon's broker calls
/// carry, so the broker skips gzip there as this leg does (OF-603).
pub(crate) fn is_cloud_node() -> bool {
    CLOUD_NODE.load(Ordering::Relaxed)
}
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
    /// A reply body grew past its caller's own bound before it ended: an
    /// identity or launch-manifest read ([`MAX_REPLY_BYTES`]), or a decision
    /// read's. A JSON reply or an error status's body has none (FIX 9321).
    BodyTooLarge,
    /// The memory a media reply's body needed could not be allocated
    /// (FIX 8615): the machine's own floor, never a size bound.
    OutOfMemory,
}

/// The most a house server's identity or launch-manifest read holds: that
/// protocol's own bound. A JSON reply or an error status's body is read
/// whole, however large (FIX 9321).
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

/// A finished exchange whose body is whatever the protocol sends: JSON, or
/// media bytes. A media reply's body is held on the media-reply line while
/// this lives, unless the media call it was read for holds it
/// ([`holding_replies`]).
pub(super) struct BytesReply {
    pub(super) status: u16,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) body: Vec<u8>,
    pub(super) held: ReplyBytes,
}

/// A media exchange whose answer is taken as it arrives
/// ([`ProviderHttp::send_media_streamed`]).
pub(super) enum StreamedReply {
    /// A 2xx answer, its body still to read.
    Body(MediaStream),
    /// Any other status, its body read whole on the media-reply line, for
    /// the caller to classify.
    Refused(BytesReply),
}

/// A 2xx media reply's body, taken a chunk at a time as it arrives and never
/// held whole here (FIX 6122).
pub(super) struct MediaStream(reqwest::Response);

impl MediaStream {
    /// The body's next bytes as they arrive; `None` at its end.
    pub(super) async fn chunk(&mut self) -> Result<Option<Vec<u8>>, HttpFailure> {
        Ok(self.0.chunk().await?.map(Vec::from))
    }
}

/// What one media exchange sends.
pub(super) enum MediaSend {
    Get,
    Delete,
    Json(JsonValue),
    Multipart(reqwest::multipart::Form),
    /// A framed binary body (`application/octet-stream`) carrying an upload
    /// its admission allowed for one request (FIX 9517): a refused
    /// compressed body's plain resend asks it again and goes only while it
    /// still allows the upload.
    Octets(Vec<u8>, UploadAdmission),
}

/// Asked right before an upload goes again: `false` sends nothing more.
pub(super) type UploadAdmission = Arc<dyn Fn() -> bool + Send + Sync>;

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
    /// The same client keeping no idle connection: what a request that never
    /// reached its upstream goes once more on (FIX 7113).
    fresh: reqwest::Client,
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

/// `plain` in `codec`: `None` when the body is under
/// [`MIN_COMPRESSED_BYTES`], the codec is gzip on a cloud node, or encoding
/// would not make it smaller. The tagger's client shares it.
pub(crate) fn encode_request_body(codec: RequestCodec, plain: &[u8]) -> Option<Vec<u8>> {
    if plain.len() < MIN_COMPRESSED_BYTES
        || (codec == RequestCodec::Gzip && CLOUD_NODE.load(Ordering::Relaxed))
    {
        return None;
    }
    let encoded = match codec {
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

/// The `Content-Encoding` token of `codec`.
pub(crate) const fn codec_token(codec: RequestCodec) -> &'static str {
    match codec {
        RequestCodec::Gzip => "gzip",
        RequestCodec::Zstd => "zstd",
    }
}

impl Compressor {
    /// `plain` in this provider's codec, for a post to `path`: `None` when
    /// it is off, the route is not one it decodes on, or
    /// [`encode_request_body`] leaves it plain.
    fn encode(&self, path: &str, plain: &[u8]) -> Option<Vec<u8>> {
        if !self.on.load(Ordering::Relaxed)
            || self.compression.route.is_some_and(|route| route != path)
        {
            return None;
        }
        encode_request_body(self.compression.codec, plain)
    }

    fn token(&self) -> &'static str {
        codec_token(self.compression.codec)
    }
}

/// One JSON post in flight, owning all it sends.
type Sending = Pin<Box<dyn Future<Output = Result<reqwest::Response, reqwest::Error>> + Send>>;

/// A released JSON send: provider failures use the existing HTTP class;
/// release failures keep their original model error.
#[derive(Debug)]
pub(super) enum HttpReleaseError {
    Transport(HttpFailure),
    Release(LlmError),
}

type ReleaseSending<'a> =
    Pin<Box<dyn Future<Output = Result<reqwest::Response, HttpReleaseError>> + Send + 'a>>;

/// A finished exchange's reply as JSON: an empty body is null, and a body
/// that does not parse is null on an error status and malformed otherwise.
fn json_reply(
    status: u16,
    headers: BTreeMap<String, String>,
    bytes: &[u8],
) -> Result<JsonReply, HttpFailure> {
    let body = if bytes.is_empty() {
        JsonValue::Null
    } else {
        match serde_json::from_slice(bytes) {
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
                let body = match read_whole(response).await {
                    Ok((bytes, _held)) => serde_json::from_slice(&bytes).unwrap_or(JsonValue::Null),
                    Err(HttpFailure::OutOfMemory) => {
                        return Some((Err(HttpFailure::OutOfMemory), SseState::Done));
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
