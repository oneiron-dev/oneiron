//! Streaming bridge between axum and the blocking smart-HTTP serve plane.

// ---------------------------------------------------------------------------
// The streaming bridge
// ---------------------------------------------------------------------------

use super::gate::text_response;
use super::status_codec::{concat_chunks, rewrite_receive_pack_status};
use crate::server::SyncServer;
use axum::body::Body;
use axum::body::Bytes;
use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::response::Response;
use futures_util::StreamExt;
use oneiron::origin::smart_http;
use std::io;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// Bounded in-flight chunks in each direction. Backpressure, not buffering:
/// the producer blocks instead of accumulating a body.
const GIT_HTTP_STREAM_CHUNKS: usize = 4;

// Status reports only; fetch packs continue to stream without this bound.
pub(super) const GIT_HTTP_MAX_HELD_BYTES: usize = 8 * 1024 * 1024;

pub(super) const GIT_HTTP_MAX_HELD_CHUNKS: usize = 4096;

/// Runs one serve invocation on a blocking worker and streams both directions
/// through bounded channels.
///
/// The worker owns the subprocess; the async side owns the socket. Neither ever
/// holds a whole body: a chunk moves when the far side has room for it.
pub(super) async fn run_serve(
    server: Arc<SyncServer>,
    repo: String,
    request: smart_http::ServeRequest,
    body: Body,
) -> Response {
    // A push is held until its landing is journaled; everything else streams.
    let held = request.is_receive_pack();
    let (request_tx, request_rx) = mpsc::channel::<Bytes>(GIT_HTTP_STREAM_CHUNKS);
    let (head_tx, head_rx) = oneshot::channel::<ResponseHead>();
    let (response_tx, response_rx) = mpsc::channel::<Bytes>(GIT_HTTP_STREAM_CHUNKS);

    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else {
                break;
            };
            if request_tx.send(chunk).await.is_err() {
                break;
            }
        }
    });

    let worker = tokio::task::spawn_blocking(move || {
        let mut reader = ChannelReader::new(request_rx);
        let mut sink = ChannelSink::new(head_tx, response_tx);
        // CoreAuth's validated principal_ref travels unchanged. The existing
        // serve path persists landed admission and observed outcome evidence;
        // this bridge supplies neither a claim id nor an alternate credential.
        smart_http::serve(
            server.vault(),
            &repo,
            &request,
            smart_http::DoorSeam::Landed,
            &mut reader,
            &mut sink,
        )
    });

    if held {
        return held_response(head_rx, response_rx, worker).await;
    }
    match head_rx.await {
        // The backend answered, and a fetch's answer is the pack itself: it
        // streams out as it is produced and is never held.
        Ok(head) => streaming_response(head, response_rx),
        Err(_) => serve_failure(worker.await),
    }
}

/// Holds a push's response until its landing is journaled.
///
/// A fetch's response is a pack and must never be buffered. A push's response
/// is git's own status report — a handful of pkt-lines, bounded by the number
/// of refs the push named — while the pack it answers has already streamed IN.
/// Holding it costs nothing and buys the one thing a push needs: the client is
/// told the push succeeded only after the publication protocol says it did.
///
/// Streaming the report first and journaling afterwards is what made a refused
/// publication indistinguishable from a landed one. The client saw `ok`, the
/// origin recorded nothing, and the ref the client believed it had pushed was
/// never advertised.
pub(super) async fn held_response(
    head: oneshot::Receiver<ResponseHead>,
    mut chunks: mpsc::Receiver<Bytes>,
    worker: tokio::task::JoinHandle<oneiron::Result<smart_http::ServeReport>>,
) -> Response {
    let head = head.await.ok();
    let mut body = Vec::new();
    let mut bytes = 0usize;
    let mut exceeded = false;
    // Keep draining after overflow: dropping the receiver or waiting first can
    // strand the blocking producer before it journals the effects already made.
    while let Some(chunk) = chunks.recv().await {
        if !exceeded {
            if chunk.len() > GIT_HTTP_MAX_HELD_BYTES.saturating_sub(bytes)
                || body.len() >= GIT_HTTP_MAX_HELD_CHUNKS
            {
                exceeded = true;
                body.clear();
            } else {
                bytes += chunk.len();
                body.push(chunk);
            }
        }
    }
    let joined = worker.await;
    if exceeded {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "git status response exceeded its limit; ref effects may be partial; retry to recover",
        );
    }
    landed_response(head, body, joined)
}

/// The response a held push produces, decided by the landing rather than by the
/// backend.
///
/// `git receive-pack` reports on what IT did — it moved refs and migrated the
/// objects — and it has no opinion about the publication protocol that runs
/// after it. When that protocol refuses (an availability proof that failed, a
/// compare-and-swap another writer won), the push did not land, and the only
/// honest answer is a failure the client surfaces rather than the backend's
/// `ok`.
pub(super) fn landed_response(
    head: Option<ResponseHead>,
    body: Vec<Bytes>,
    joined: Result<oneiron::Result<smart_http::ServeReport>, tokio::task::JoinError>,
) -> Response {
    let report = match joined {
        Ok(Ok(report)) => report,
        refused => return serve_failure(refused),
    };
    let Some((status, mut headers)) = head else {
        return text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git smart-http produced no response",
        );
    };
    let body = concat_chunks(body);
    let body = if report.ref_results.is_empty() {
        body
    } else {
        let Some(rewritten) = rewrite_receive_pack_status(&body, &report.ref_results) else {
            return text_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "git per-ref status is unavailable; ref effects may be partial; retry to recover",
            );
        };
        // The pkt-line lengths changed. A backend Content-Length is no longer valid.
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()));
        Bytes::from(rewritten)
    };
    let mut response = Response::new(Body::from(body));
    apply_response_head(&mut response, status, headers);
    response
}

pub(super) type ResponseHead = (u16, Vec<(String, String)>);

pub(super) fn serve_failure(
    joined: Result<oneiron::Result<smart_http::ServeReport>, tokio::task::JoinError>,
) -> Response {
    if let Ok(Err(error)) = &joined {
        tracing::warn!(error = %error, "git smart-http worker failed");
    }
    let (status, message) = match joined {
        Ok(Ok(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "git smart-http produced no response".to_owned(),
        ),
        Ok(Err(oneiron::Error::Code(oneiron::error::CodeError::ReceivePackLandingRefused {
            ..
        }))) => (
            StatusCode::CONFLICT,
            "git publication refused; ref effects may be partial".to_owned(),
        ),
        Ok(Err(
            oneiron::Error::ConcurrentWrite(_)
            | oneiron::Error::Code(oneiron::error::CodeError::RepoMutationFailed(_)),
        )) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "git publication is pending; ref effects may be partial; retry to recover".to_owned(),
        ),
        Ok(Err(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "git request could not complete; ref effects may be partial".to_owned(),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "git smart-http worker did not complete".to_owned(),
        ),
    };
    let mut response = text_response(status, &message);
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
    }
    response
}

/// Wraps the backend's own status and headers around a body that is still
/// arriving. The body is a stream, so a large pack leaves the process the same
/// way it entered: in chunks, never whole.
fn streaming_response(head: ResponseHead, chunks: mpsc::Receiver<Bytes>) -> Response {
    let (status, headers) = head;
    let stream = futures_util::stream::unfold(chunks, |mut chunks| async move {
        chunks
            .recv()
            .await
            .map(|chunk| (Ok::<Bytes, io::Error>(chunk), chunks))
    });
    let mut response = Response::new(Body::from_stream(stream));
    apply_response_head(&mut response, status, headers);
    response
}

/// Puts the backend's own status and headers on a response, whatever the body
/// turned out to be.
fn apply_response_head(response: &mut Response, status: u16, headers: Vec<(String, String)>) {
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    for (name, value) in headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&value) else {
            continue;
        };
        response.headers_mut().append(name, value);
    }
}

/// The request body, as a blocking reader over the async stream.
struct ChannelReader {
    chunks: mpsc::Receiver<Bytes>,
    carry: Bytes,
}

impl ChannelReader {
    fn new(chunks: mpsc::Receiver<Bytes>) -> Self {
        Self {
            chunks,
            carry: Bytes::new(),
        }
    }
}

impl io::Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.carry.is_empty() {
            match self.chunks.blocking_recv() {
                Some(chunk) => self.carry = chunk,
                None => return Ok(0),
            }
        }
        let take = self.carry.len().min(out.len());
        out[..take].copy_from_slice(&self.carry[..take]);
        self.carry = self.carry.slice(take..);
        Ok(take)
    }
}

/// The response, as a blocking sink onto the async stream.
struct ChannelSink {
    head: Option<oneshot::Sender<ResponseHead>>,
    chunks: mpsc::Sender<Bytes>,
}

impl ChannelSink {
    fn new(head: oneshot::Sender<ResponseHead>, chunks: mpsc::Sender<Bytes>) -> Self {
        Self {
            head: Some(head),
            chunks,
        }
    }
}

impl smart_http::ServeSink for ChannelSink {
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        let Some(head) = self.head.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "git smart-http produced two header blocks",
            ));
        };
        head.send((status, headers.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client went away"))
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.chunks
            .blocking_send(Bytes::copy_from_slice(bytes))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client went away"))
    }
}
