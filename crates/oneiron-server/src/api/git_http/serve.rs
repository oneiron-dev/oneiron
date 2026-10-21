//! Streaming bridge between axum and the blocking smart-HTTP serve plane.

// ---------------------------------------------------------------------------
// The streaming bridge
// ---------------------------------------------------------------------------

use super::gate::text_response;
use super::status_codec::{StatusFault, rewrite_receive_pack_status};
use crate::admission::WaitTimedOut;
use crate::api::transfer::{self, BodyPiece, BodyReader};
use crate::server::SyncServer;
use axum::body::Body;
use axum::body::Bytes;
use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::response::Response;
use oneiron::federation::GitPushCaller;
use oneiron::origin::residence::{
    ORIGIN_WRITER_ERASED_REFUSAL, OriginAuthority, OriginHostAuthority, OriginResidence,
};
use oneiron::origin::smart_http;
use oneiron::origin::smart_http::{AtDiskFloor, HeldBytes, SpillFloor};
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// Bounded in-flight chunks in each direction. Backpressure, not buffering:
/// the producer blocks instead of accumulating a body.
const GIT_HTTP_STREAM_CHUNKS: usize = 4;

/// The largest request-body piece handed to the backend at once, and the
/// largest piece of a held report sent at once.
const GIT_HTTP_BODY_PIECE: usize = 64 * 1024;

/// Runs one serve invocation on a blocking worker and streams both directions
/// through bounded channels.
///
/// The worker owns the subprocess; the async side owns the socket. Neither ever
/// holds a whole body: a chunk moves when the far side has room for it, and
/// neither waits on the other past the transfer idle limit. The exchange's
/// permit is taken before any child exists and is held by the worker, which
/// outlives this handler whenever the response streams. Past the bound the
/// exchange waits its turn; a push first waits for its repository's turn,
/// behind the pushes to that repository that came before it, so no worker
/// thread ever sits waiting for a repository. A push is first decided
/// (G1-PUSH) as `caller`, the pusher the gate authenticated, before it
/// queues; the engine decides it again under the coordinator.
pub(super) async fn run_serve(
    server: Arc<SyncServer>,
    repo: String,
    request: smart_http::ServeRequest,
    body: Body,
    caller: Option<GitPushCaller>,
) -> Response {
    // A push runs under the lease this host holds over the repository, read
    // from the vault's own authority row and this install's machine, never
    // from the request. A mirror, or a repository another host writes, is
    // told so before it queues, as is one whose writer was erased: it names
    // the owner's cutover. A repository that does not resolve leaves the
    // answer to the exchange.
    let authority = if request.is_push() {
        let vault = Arc::clone(server.vault());
        let name = repo.clone();
        match tokio::task::spawn_blocking(move || vault.origin_host_authority(&name)).await {
            Ok(Ok(OriginHostAuthority::Held(lease))) => Some(lease),
            Ok(Ok(OriginHostAuthority::Mirror(row))) => return not_the_writer(&row, true),
            Ok(Ok(OriginHostAuthority::Elsewhere(row))) => return not_the_writer(&row, false),
            Ok(Ok(OriginHostAuthority::WriterErased(_))) => {
                return text_response(StatusCode::FORBIDDEN, ORIGIN_WRITER_ERASED_REFUSAL);
            }
            Ok(Ok(OriginHostAuthority::Unconfigured) | Err(_)) | Err(_) => None,
        }
    } else {
        None
    };
    if request.is_push()
        && let Some(refused) =
            super::gate::preflight(&server, &repo, &request, caller.as_ref()).await
    {
        return refused;
    }
    let principal = request.remote_user.as_deref();
    // A repository that does not resolve has no line; the exchange says why.
    let turn = match request
        .is_receive_pack()
        .then(|| smart_http::push_queue_key(server.vault(), &repo).ok())
        .flatten()
    {
        Some(key) => match server.transfers.push_turn(key, principal).await {
            Ok(turn) => Some(turn),
            Err(WaitTimedOut) => return waited_out(),
        },
        None => None,
    };
    let Ok(permit) = server.transfers.admit_git(principal).await else {
        return waited_out();
    };
    // What the exchange holds past memory keeps the vault disk's reserve.
    let floor: Arc<dyn SpillFloor> = Arc::new(server.transfers.disk.clone());
    let bounds = smart_http::ExchangeBounds {
        idle: server.transfers.idle,
        repository_wait: server.transfers.wait,
        scan: server.transfers.scan,
        spill_floor: Some(Arc::clone(&floor)),
    };
    // A push is held until its landing is journaled; everything else streams.
    let held = request
        .is_receive_pack()
        .then_some(server.transfers.git_status_memory);
    let idle = server.transfers.idle;
    let (request_tx, request_rx) = mpsc::channel::<BodyPiece>(GIT_HTTP_STREAM_CHUNKS);
    let (head_tx, head_rx) = oneshot::channel::<Answer>();
    let (response_tx, response_rx) = mpsc::channel::<Bytes>(GIT_HTTP_STREAM_CHUNKS);
    let sent = Arc::new(AtomicBool::new(false));
    let all_sent = Arc::clone(&sent);

    tokio::spawn(transfer::feed_body(
        body,
        request_tx,
        idle,
        GIT_HTTP_BODY_PIECE,
    ));

    let runtime = Handle::current();
    let worker = transfer::spawn_worker(move || {
        let _held = (turn, permit);
        let mut reader = BodyReader::new(request_rx);
        let mut sink = ChannelSink {
            head: Some(head_tx),
            chunks: response_tx,
            runtime,
            idle,
        };
        let vault = server.vault();
        // CoreAuth's validated principal_ref travels unchanged. The existing
        // serve path persists landed admission and observed outcome evidence;
        // this bridge supplies neither a claim id nor an alternate credential.
        let Some(status_memory) = held else {
            return Some(smart_http::serve_bounded_as(
                vault,
                &repo,
                &request,
                smart_http::DoorSeam::Landed,
                bounds,
                authority.as_ref(),
                caller.as_ref(),
                &mut reader,
                &mut sink,
            ));
        };
        let mut holding = HoldingSink {
            head: None,
            held: HeldBytes::new(status_memory, smart_http::origin_door_root(vault).ok())
                .with_floor(Some(floor)),
            failed: None,
        };
        let served = smart_http::serve_bounded_as(
            vault,
            &repo,
            &request,
            smart_http::DoorSeam::Landed,
            bounds,
            authority.as_ref(),
            caller.as_ref(),
            &mut reader,
            &mut holding,
        );
        sink.answer(
            landed(holding.head, holding.held, holding.failed, served),
            &all_sent,
        );
        None
    });

    match head_rx.await {
        // The backend answered, and a fetch's answer is the pack itself: it
        // streams out as it is produced and is never held. A push's answer
        // comes once its landing is journaled.
        Ok(Answer::Head(head)) => {
            streaming_response(head, response_rx, held.is_some().then_some(sent))
        }
        Ok(Answer::Whole(response)) => response,
        Err(_) => match worker.await {
            Ok(Some(served)) => serve_failure(Ok(served)),
            Ok(None) => text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "git smart-http produced no response",
            ),
            Err(panicked) => serve_failure(Err(panicked)),
        },
    }
}

/// What the worker answers the handler with.
enum Answer {
    /// The head of a body that streams through the response channel.
    Head(ResponseHead),
    /// A whole response: a held push's refusal.
    Whole(Response),
}

/// What a held push answers, decided by its landing.
pub(super) enum Landed {
    Answer(Response),
    /// The backend's head over the report, rewritten for what landed.
    Report(ResponseHead, HeldBytes),
}

/// A push's response, held until its landing is journaled.
///
/// A fetch's response is a pack and must never be buffered. A push's response
/// is git's own status report — a pkt-line per ref the push named — while the
/// pack it answers has already streamed IN. Holding it buys the one thing a
/// push needs: the client is told the push succeeded only after the
/// publication protocol says it did. A push may name any number of refs, so
/// the worker holds the report itself, in memory up to the transfer's
/// `git_status_memory` and on disk past it ([`HeldBytes`]), and never refuses
/// it for its size; only the vault disk's reserve, or the disk itself, does.
/// It keeps reading the backend after a failed write.
///
/// Streaming the report first and journaling afterwards is what made a refused
/// publication indistinguishable from a landed one. The client saw `ok`, the
/// origin recorded nothing, and the ref the client believed it had pushed was
/// never advertised.
struct HoldingSink {
    head: Option<ResponseHead>,
    held: HeldBytes,
    failed: Option<io::Error>,
}

impl smart_http::ServeSink for HoldingSink {
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        if self.head.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "git smart-http produced two header blocks",
            ));
        }
        self.head = Some((status, headers.to_vec()));
        Ok(())
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.failed.is_none() {
            self.failed = self.held.write_all(bytes).err();
        }
        Ok(())
    }
}

/// A held report that could not be written or read back.
fn held_failure(error: &io::Error) -> Response {
    tracing::warn!(kind = ?error.kind(), "git status report could not be held");
    if AtDiskFloor::is_in(error) {
        return text_response(
            StatusCode::INSUFFICIENT_STORAGE,
            "the vault's disk is at its free-space reserve (limits.disk_reserve_bytes); git status report could not be held; ref effects may be partial; retry to recover",
        );
    }
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
/// It reads and writes the held report, so it blocks.
pub(super) fn landed(
    head: Option<ResponseHead>,
    mut body: HeldBytes,
    failed: Option<io::Error>,
    served: oneiron::Result<smart_http::ServeReport>,
) -> Landed {
    if let Some(error) = failed {
        return Landed::Answer(held_failure(&error));
    }
    let report = match served {
        Ok(report) => report,
        refused => return Landed::Answer(serve_failure(Ok(refused))),
    };
    let Some((status, mut headers)) = head else {
        return Landed::Answer(text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git smart-http produced no response",
        ));
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
                return Landed::Answer(text_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "git per-ref status is unavailable; ref effects may be partial; retry to recover",
                ));
            }
            Err(StatusFault::Held(error)) => return Landed::Answer(held_failure(&error)),
        }
        rewritten
    };
    // The held length, whatever the backend said: the pkt-line lengths may
    // have changed, and a report cut short must read as cut short however the
    // client frames the response, HTTP/1.0 included.
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()));
    headers.push((CONTENT_LENGTH.as_str().to_owned(), body.len().to_string()));
    Landed::Report((status, headers), body)
}

/// [`landed`] as one whole response, for a report held in memory.
#[cfg(test)]
pub(super) fn landed_response(
    head: Option<ResponseHead>,
    body: HeldBytes,
    joined: Result<oneiron::Result<smart_http::ServeReport>, transfer::WorkerGone>,
) -> Response {
    let served = match joined {
        Ok(served) => served,
        panicked => return serve_failure(panicked),
    };
    match landed(head, body, None, served) {
        Landed::Answer(response) => response,
        Landed::Report((status, headers), mut body) => {
            let mut bytes = Vec::new();
            body.reader()
                .and_then(|mut reader| reader.read_to_end(&mut bytes))
                .expect("a report held in memory");
            let mut response = Response::new(Body::from(bytes));
            apply_response_head(&mut response, status, headers);
            response
        }
    }
}

pub(super) type ResponseHead = (u16, Vec<(String, String)>);

/// A push to a repository this host does not write: a read-only mirror, or
/// one whose current epoch another host holds. Reads still serve here.
fn not_the_writer(row: &OriginAuthority, mirror: bool) -> Response {
    let message = if mirror {
        format!(
            "this origin is a read-only mirror at authority epoch {}; push to the authoritative origin",
            row.epoch
        )
    } else {
        format!(
            "another host writes this repository at authority epoch {} ({}); push to that origin",
            row.epoch,
            match row.residence {
                OriginResidence::LocalVault => "local-vault",
                OriginResidence::CloudVault => "cloud-vault",
            }
        )
    };
    text_response(StatusCode::FORBIDDEN, &message)
}

/// The exchange waited its whole deadline for its turn. Nothing was started.
fn waited_out() -> Response {
    let mut response = text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "git transfer waited past limits.queue_wait_timeout_ms for its turn; nothing was started; retry",
    );
    response
        .headers_mut()
        .insert("retry-after", HeaderValue::from_static("1"));
    response
}

pub(super) fn serve_failure(
    joined: Result<oneiron::Result<smart_http::ServeReport>, transfer::WorkerGone>,
) -> Response {
    if let Ok(Err(error)) = &joined {
        tracing::warn!(kind = ?error.kind(), "git smart-http worker failed");
    }
    if let Ok(Err(oneiron::Error::Code(oneiron::error::CodeError::GitPushCapabilityRequired {
        repo,
        reason,
    }))) = &joined
    {
        return super::gate::capability_refused(repo, reason);
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
            "another writer held the repository past limits.queue_wait_timeout_ms; nothing was received; retry"
                .to_owned(),
        ),
        Ok(Err(oneiron::Error::Code(oneiron::error::CodeError::LfsReadRoomWaitedOut))) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "no room to check the LFS objects came within limits.queue_wait_timeout_ms; ref effects may be partial; retry to recover"
                .to_owned(),
        ),
        Ok(Err(
            oneiron::Error::ConcurrentWrite(_)
            | oneiron::Error::Code(oneiron::error::CodeError::RepoMutationFailed(_)),
        )) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "git publication is pending; ref effects may be partial; retry to recover".to_owned(),
        ),
        // The disk floor: what the exchange holds past memory (its command
        // section) would take the vault's disk below its reserve.
        Ok(Err(oneiron::Error::Io(error))) if AtDiskFloor::is_in(&error) => (
            StatusCode::INSUFFICIENT_STORAGE,
            "the vault's disk is at its free-space reserve (limits.disk_reserve_bytes); ref effects may be partial; retry later"
                .to_owned(),
        ),
        // The same hold, on a disk that is full.
        Ok(Err(oneiron::Error::Io(error))) if error.kind() == io::ErrorKind::StorageFull => (
            StatusCode::INSUFFICIENT_STORAGE,
            "the origin's disk is full; ref effects may be partial; retry later".to_owned(),
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
///
/// A held report comes with `sent`, which its worker sets once the last piece
/// is queued. A report whose pieces stop before that (the client stopped
/// reading past the idle limit, the file could not be read back, the worker
/// unwound) ends as a body error, never as a complete report.
fn streaming_response(
    head: ResponseHead,
    chunks: mpsc::Receiver<Bytes>,
    sent: Option<Arc<AtomicBool>>,
) -> Response {
    let (status, headers) = head;
    let stream = futures_util::stream::unfold((chunks, sent), |(mut chunks, sent)| async move {
        match chunks.recv().await {
            Some(chunk) => Some((Ok(chunk), (chunks, sent))),
            None => match sent {
                Some(sent) if !sent.load(Ordering::Acquire) => Some((
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "git status report ended before it was sent",
                    )),
                    (chunks, None),
                )),
                _ => None,
            },
        }
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
    head: Option<oneshot::Sender<Answer>>,
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
        head.send(Answer::Head((status, headers.to_vec())))
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

impl ChannelSink {
    /// Sends a held push's answer: a whole response, or the backend's head
    /// and then the report a piece at a time. Each piece waits at most the
    /// idle limit for the client to take it, so a client that stops reading
    /// ends the exchange, and the report, its file and the permit go with it.
    /// `sent` is set once the whole report is queued, before the channel
    /// closes.
    fn answer(mut self, landed: Landed, sent: &AtomicBool) {
        let (head, mut body) = match landed {
            Landed::Answer(response) => {
                if let Some(head) = self.head.take() {
                    let _ = head.send(Answer::Whole(response));
                }
                return;
            }
            Landed::Report(head, body) => (head, body),
        };
        let mut reader = match body.reader() {
            Ok(reader) => reader,
            Err(error) => {
                if let Some(head) = self.head.take() {
                    let _ = head.send(Answer::Whole(held_failure(&error)));
                }
                return;
            }
        };
        let Some(sender) = self.head.take() else {
            return;
        };
        if sender.send(Answer::Head(head)).is_err() {
            return;
        }
        let mut piece = vec![0; GIT_HTTP_BODY_PIECE];
        loop {
            match reader.read(&mut piece) {
                Ok(0) => {
                    sent.store(true, Ordering::Release);
                    return;
                }
                Ok(read) => {
                    if smart_http::ServeSink::write_chunk(&mut self, &piece[..read]).is_err() {
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "git status report could not be read back");
                    return;
                }
            }
        }
    }
}
