//! Compressed bodies on the HTTP API (ARCH-0081 §8, OF-604).
//!
//! A request to `/mcp`, `/mcp/tool-first`, `/v1/llm/*` or `/v1/core/*` may
//! arrive zstd- or gzip-encoded. It is decoded here, before any route reads
//! it, so the facade's receipt and invocation readers and the idempotency
//! buffer digest the bytes the client meant, and decoding stops at the
//! route's own body limit. Any other path passes untouched: git smart HTTP
//! forwards its own gzip to `git http-backend`, and LFS, the provider webhooks
//! and the relay locker keep their raw bodies.
//!
//! A JSON reply of 16 KiB or more goes zstd or gzip when the client asks.
//! NDJSON and SSE are not `application/json`, and a streamed body has no exact
//! size, so a stream still flushes each event plain.

use std::io::{Read, Write};

use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;

use crate::error::{ApiError, ApiErrorDetails};

/// The smallest body worth a codec, either way: the /ws codec frame's threshold.
const MIN_ENCODED_BYTES: usize = oneiron::sync::transport::CODEC_MIN_FRAME_BYTES;
/// zstd level for replies, as for every frame we encode ourselves.
const REPLY_ZSTD_LEVEL: i32 = oneiron::sync::transport::CODEC_ZSTD_LEVEL;
/// gzip level for replies to a client that does not take zstd: the fast end.
const REPLY_GZIP_LEVEL: u32 = 1;

/// Axum's extractor ceiling, which a route with no `DefaultBodyLimit` keeps.
const AXUM_DEFAULT_BODY_BYTES: usize = 2 * 1024 * 1024;
/// `api/llm.rs`'s nest ceiling for `/v1/llm/*`.
const LLM_BODY_BYTES: usize = 64 * 1024 * 1024;
/// `api/llm.rs`'s `/v1/llm/decision_read` ceiling.
const LLM_DECISION_READ_BODY_BYTES: usize = 256 * 1024;
/// `api/llm.rs`'s `/v1/llm/defaults` ceiling.
const LLM_DEFAULTS_BODY_BYTES: usize = 16 * 1024;
/// `api/facade.rs`'s `FACADE_MAX_BODY_BYTES`.
const FACADE_BODY_BYTES: usize = MAX_REMOTE_REQUEST_BYTES;
/// `api/blob_artifacts.rs`'s `ARTIFACT_BODY_LIMIT`.
const ARTIFACT_BODY_BYTES: usize = 96 * 1024 * 1024;

/// The decoded-body ceiling for `path`, equal to the limit its route applies,
/// or `None` when the path is outside the decoded set and its body passes
/// untouched.
fn decoded_body_cap(path: &str) -> Option<usize> {
    if matches!(path, "/mcp" | "/mcp/tool-first") {
        return Some(AXUM_DEFAULT_BODY_BYTES);
    }
    if let Some(rest) = path.strip_prefix("/v1/llm/") {
        return Some(match rest {
            "decision_read" => LLM_DECISION_READ_BODY_BYTES,
            "defaults" => LLM_DEFAULTS_BODY_BYTES,
            _ => LLM_BODY_BYTES,
        });
    }
    let rest = path.strip_prefix("/v1/core/")?;
    Some(if rest.starts_with("facade/") {
        FACADE_BODY_BYTES
    } else if rest == "artifacts" || rest.starts_with("artifacts/") {
        ARTIFACT_BODY_BYTES
    } else {
        AXUM_DEFAULT_BODY_BYTES
    })
}

#[derive(Clone, Copy)]
enum Codec {
    Zstd,
    Gzip,
}

impl Codec {
    fn token(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
        }
    }
}

/// The API's body codec, as one layer: decodes the request, runs the route,
/// and encodes a JSON reply the client can take.
pub(crate) async fn body_codec(request: Request, next: Next) -> Response {
    let reply = reply_codec(request.method(), request.headers());
    let request = match decode_request(request).await {
        Ok(request) => request,
        Err(refusal) => return refusal.into_response(),
    };
    let response = next.run(request).await;
    match reply {
        Some(codec) => encode_reply(response, codec).await,
        None => response,
    }
}

async fn decode_request(request: Request) -> Result<Request, ApiError> {
    let Some(cap) = decoded_body_cap(request.uri().path()) else {
        return Ok(request);
    };
    let mut encodings = request
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .into_iter();
    let Some(encoding) = encodings.next() else {
        return Ok(request);
    };
    let named = encoding.to_str().unwrap_or("").trim().to_ascii_lowercase();
    // One coding or none: a stacked list is refused like an unknown coding.
    let codec = match (named.as_str(), encodings.next()) {
        ("identity", None) => return Ok(request),
        ("zstd", None) => Codec::Zstd,
        ("gzip" | "x-gzip", None) => Codec::Gzip,
        _ => {
            return Err(ApiError::new(
                format!("this route does not decode Content-Encoding `{named}`"),
                ApiErrorDetails::UnsupportedFormat {
                    format: Some(named),
                },
                ["Send the body as zstd, gzip or identity."],
            ));
        }
    };
    let (mut parts, body) = request.into_parts();
    let raw = axum::body::to_bytes(body, cap)
        .await
        .map_err(|_| too_large(cap))?;
    let decoded = tokio::task::spawn_blocking(move || decode(codec, &raw, cap))
        .await
        .map_err(|_| ApiError::internal_server_error("the request body decoder stopped"))??;
    parts.headers.remove(header::CONTENT_ENCODING);
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(decoded.len()));
    Ok(Request::from_parts(parts, Body::from(decoded)))
}

/// Decodes `raw` and holds at most `cap + 1` bytes of what it decodes to.
fn decode(codec: Codec, raw: &[u8], cap: usize) -> Result<Vec<u8>, ApiError> {
    let mut decoded = Vec::new();
    if raw.is_empty() {
        return Ok(decoded);
    }
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let read = match codec {
        Codec::Zstd => zstd::stream::read::Decoder::with_buffer(raw)
            .and_then(|decoder| decoder.take(limit).read_to_end(&mut decoded)),
        Codec::Gzip => flate2::read::MultiGzDecoder::new(raw)
            .take(limit)
            .read_to_end(&mut decoded),
    };
    if read.is_err() {
        return Err(ApiError::bad_request(
            format!("the {} request body does not decode", codec.token()),
            None,
        ));
    }
    if decoded.len() > cap {
        return Err(too_large(cap));
    }
    Ok(decoded)
}

fn too_large(cap: usize) -> ApiError {
    ApiError::payload_too_large("request body", cap, cap.saturating_add(1))
}

/// The codec a reply to this request may use: zstd when the client takes it,
/// else gzip, else none. A `q=0` refuses a coding, and `*` takes any coding
/// not named.
fn reply_codec(method: &Method, headers: &HeaderMap) -> Option<Codec> {
    if method == Method::HEAD {
        return None;
    }
    let (mut zstd, mut gzip, mut any) = (None, None, false);
    for value in headers.get_all(header::ACCEPT_ENCODING) {
        for item in value.to_str().unwrap_or("").split(',') {
            let mut params = item.split(';');
            let name = params.next().unwrap_or("").trim().to_ascii_lowercase();
            let taken = !params.any(|param| {
                param
                    .trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            });
            match name.as_str() {
                "zstd" => zstd = Some(taken),
                "gzip" | "x-gzip" => gzip = Some(gzip.unwrap_or(false) || taken),
                "*" => any = taken,
                _ => {}
            }
        }
    }
    if zstd.unwrap_or(any) {
        Some(Codec::Zstd)
    } else if gzip.unwrap_or(any) {
        Some(Codec::Gzip)
    } else {
        None
    }
}

/// Encodes a whole JSON reply of at least [`MIN_ENCODED_BYTES`], and only
/// when the encoding is smaller. A streamed body has no exact size and passes.
async fn encode_reply(response: Response, codec: Codec) -> Response {
    let json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("application/json"));
    let size = response.body().size_hint().exact();
    let Some(size) = size.and_then(|size| usize::try_from(size).ok()) else {
        return response;
    };
    if !json
        || size < MIN_ENCODED_BYTES
        || response.headers().contains_key(header::CONTENT_ENCODING)
        || response.headers().contains_key(header::CONTENT_RANGE)
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(plain) = axum::body::to_bytes(body, size).await else {
        return ApiError::internal_server_error("the reply body could not be read").into_response();
    };
    let source = plain.clone();
    let encoded = tokio::task::spawn_blocking(move || encode(codec, &source))
        .await
        .ok()
        .flatten()
        .filter(|encoded| encoded.len() < plain.len());
    let Some(encoded) = encoded else {
        return Response::from_parts(parts, Body::from(plain));
    };
    parts.headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(codec.token()),
    );
    parts
        .headers
        .append(header::VARY, HeaderValue::from_static("accept-encoding"));
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(encoded))
}

fn encode(codec: Codec, plain: &[u8]) -> Option<Vec<u8>> {
    match codec {
        Codec::Zstd => zstd::stream::encode_all(plain, REPLY_ZSTD_LEVEL).ok(),
        Codec::Gzip => {
            let mut encoder = flate2::write::GzEncoder::new(
                Vec::with_capacity(plain.len() / 2),
                flate2::Compression::new(REPLY_GZIP_LEVEL),
            );
            encoder.write_all(plain).ok()?;
            encoder.finish().ok()
        }
    }
}
