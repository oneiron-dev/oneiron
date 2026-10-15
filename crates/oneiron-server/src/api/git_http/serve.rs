//! Streaming bridge between axum and the blocking smart-HTTP serve plane.

// ---------------------------------------------------------------------------
// The streaming bridge
// ---------------------------------------------------------------------------

use super::gate::text_response;
use super::held::HeldBytes;
use super::status_codec::{StatusFault, rewrite_receive_pack_status};
use crate::api::transfer::{self, BodyPiece, BodyReader};
use crate::server::SyncServer;
use axum::body::Body;
use axum::body::Bytes;
use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::response::Response;
use oneiron::origin::smart_http;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// Bounded in-flight chunks in each direction. Backpressure, not buffering:
/// the producer blocks instead of accumulating a body.
const GIT_HTTP_STREAM_CHUNKS: usize = 4;

/// The largest request-body piece handed to the backend at once.
const GIT_HTTP_BODY_PIECE: usize = 64 * 1024;

/// Runs one serve invocation on a blocking worker and streams both directions
/// through bounded channels.
///
/// The worker owns the subprocess; the async side owns the socket. Neither ever
/// holds a whole body: a chunk moves when the far side has room for it, and
/// neither waits on the other past the transfer idle limit. The exchange's
/// permit is taken before any child exists and is held by the worker, which
/// outlives this handler whenever the response streams.
pub(super) async fn run_serve(
    server: Arc<SyncServer>,
    repo: String,
    request: smart_http::ServeRequest,
    body: Body,
) -> Response {
    let Ok(permit) = server.transfers.admit_git(request.remote_user.as_deref()) else {
        return saturated();
    };
    // A push is held until its landing is journaled; everything else streams.
    let held = request.is_receive_pack().then(|| {
        (
            Arc::clone(server.vault()),
            server.transfers.git_status_memory,
        )
    });
    let idle = server.transfers.idle;
    let (request_tx, request_rx) = mpsc::channel::<BodyPiece>(GIT_HTTP_STREAM_CHUNKS);
    let (head_tx, head_rx) = oneshot::channel::<ResponseHead>();
    let (response_tx, response_rx) = mpsc::channel::<Bytes>(GIT_HTTP_STREAM_CHUNKS);

    tokio::spawn(transfer::feed_body(
        body,
        request_tx,
        idle,
        GIT_HTTP_BODY_PIECE,
    ));

    let runtime = Handle::current();
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut reader = BodyReader::new(request_rx);
        let mut sink = ChannelSink {
            head: Some(head_tx),
            chunks: response_tx,
            runtime,
            idle,
        };
        // CoreAuth's validated principal_ref travels unchanged. The existing
        // serve path persists landed admission and observed outcome evidence;
        // this bridge supplies neither a claim id nor an alternate credential.
        smart_http::serve_bounded(
            server.vault(),
            &repo,
            &request,
            smart_http::DoorSeam::Landed,
            idle,
            &mut reader,
            &mut sink,
        )
    });

    if let Some((vault, status_memory)) = held {
        return held_response(head_rx, response_rx, worker, vault, status_memory).await;
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
/// is git's own status report — a pkt-line per ref the push named — while the
/// pack it answers has already streamed IN. Holding it buys the one thing a
/// push needs: the client is told the push succeeded only after the
/// publication protocol says it did. A push may name any number of refs, so
/// the report is held in memory up to `status_memory` bytes and on disk past
/// them ([`HeldBytes`]), never refused for its size.
///
/// Streaming the report first and journaling afterwards is what made a refused
/// publication indistinguishable from a landed one. The client saw `ok`, the
/// origin recorded nothing, and the ref the client believed it had pushed was
/// never advertised.
pub(super) async fn held_response(
    head: oneshot::Receiver<ResponseHead>,
    mut chunks: mpsc::Receiver<Bytes>,
    worker: tokio::task::JoinHandle<oneiron::Result<smart_http::ServeReport>>,
    vault: Arc<oneiron::Vault>,
    status_memory: usize,
) -> Response {
    let head = head.await.ok();
    // Held on the blocking pool, since a report past memory is written to
    // disk. Keep draining after a failed write: dropping the receiver or
    // waiting first can strand the blocking producer before it journals the
    // effects already made.
    let holding = tokio::task::spawn_blocking(move || {
        let mut held = HeldBytes::new(status_memory, smart_http::origin_door_root(&vault).ok());
        let mut failed = None;
        while let Some(chunk) = chunks.blocking_recv() {
            if failed.is_none() {
                failed = held.write_all(&chunk).err();
            }
        }
        (held, failed)
    });
    let joined = worker.await;
    let held = match holding.await {
        Ok((held, None)) => held,
        Ok((_, Some(error))) => return held_failure(&error),
        Err(_) => return serve_failure(joined),
    };
    match tokio::task::spawn_blocking(move || landed_response(head, held, joined)).await {
        Ok(response) => response,
        Err(_) => text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git status could not be answered; ref effects may be partial; retry to recover",
        ),
    }
}

/// A held report that could not be written or read back.
fn held_failure(error: &io::Error) -> Response {
    tracing::warn!(kind = ?error.kind(), "git status report could not be held");
    let status = if error.kind() == io::ErrorKind::StorageFull {
        StatusCode::INSUFFICIENT_STORAGE
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    text_response(
        status,
        "git status report could not be held; ref effects may be partial; retry to recover",
    )
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
///
/// It reads and writes the held report, so it blocks: call it from the
/// blocking pool.
pub(super) fn landed_response(
    head: Option<ResponseHead>,
    mut body: HeldBytes,
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
    let body = if report.ref_results.is_empty() {
        body
    } else {
        let mut rewritten = body.sibling();
        match rewrite_receive_pack_status(&mut body, &report.ref_results, &mut rewritten)
            .and_then(|()| rewritten.flush().map_err(StatusFault::Held))
        {
            Ok(()) => {}
            Err(StatusFault::Unreadable) => {
                return text_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "git per-ref status is unavailable; ref effects may be partial; retry to recover",
                );
            }
            Err(StatusFault::Held(error)) => return held_failure(&error),
        }
        // The pkt-line lengths changed. A backend Content-Length is no longer valid.
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()));
        rewritten
    };
    let body = match body.into_body() {
        Ok(body) => body,
        Err(error) => return held_failure(&error),
    };
    let mut response = Response::new(body);
    apply_response_head(&mut response, status, headers);
    response
}

pub(super) type ResponseHead = (u16, Vec<(String, String)>);

/// Every git exchange permit is held: refused now, never queued.
fn saturated() -> Response {
    let mut response = text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "git transfers are at their limit; retry later",
    );
    response
        .headers_mut()
        .insert("retry-after", HeaderValue::from_static("1"));
    response
}

pub(super) fn serve_failure(
    joined: Result<oneiron::Result<smart_http::ServeReport>, tokio::task::JoinError>,
) -> Response {
    if let Ok(Err(error)) = &joined {
        tracing::warn!(kind = ?error.kind(), "git smart-http worker failed");
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
        Ok(Err(oneiron::Error::Code(oneiron::error::CodeError::GitHttpExchangeIdle))) => (
            StatusCode::REQUEST_TIMEOUT,
            "git transfer moved no data within its idle limit; ref effects may be partial"
                .to_owned(),
        ),
        Ok(Err(oneiron::Error::Code(oneiron::error::CodeError::GitHttpRepositoryBusy))) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "the repository is busy with another writer; nothing was received; retry later"
                .to_owned(),
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

/// The response, as a blocking sink onto the async stream.
struct ChannelSink {
    head: Option<oneshot::Sender<ResponseHead>>,
    chunks: mpsc::Sender<Bytes>,
    runtime: Handle,
    idle: Duration,
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
        transfer::send_within(
            &self.runtime,
            &self.chunks,
            Bytes::copy_from_slice(bytes),
            self.idle,
        )
    }
}
