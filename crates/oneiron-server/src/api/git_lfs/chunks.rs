//! Grant-scoped binary have/want endpoint over the standing bearer identity.
//!
//! Each way the exchange is a chunk-sync stream of frames and an end frame
//! (FIX 145, [`oneiron::sync::chunks::stream`]): its request is decoded as
//! its frames arrive, and its reply written a frame at a time as its client
//! takes it. Neither is held whole, and no length refuses either.

use super::gate::{LfsAccess, authorize_request};
use super::support::{
    ChargedBody, LFS_PIECES_IN_FLIGHT, LfsMarkedRead, declared_size, lfs_piece_hold, lfs_waited_out,
};
use crate::api::Transfers;
use crate::api::transfer::ReadHold;
use crate::byte_line::{ByteLine, HeldBytes};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;
use crate::wire_telemetry::LimitQuestions;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use oneiron::authority::PeerMachine;
use oneiron::origin::lfs::LfsOid;
use oneiron::sync::chunks::{ChunkSyncRequest, ChunkSyncResponse};
use oneiron::{FederationGrantScope, Vault};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

/// Why an exchange went unanswered.
enum Unanswered {
    /// Its body failed or went quiet before its stream ended.
    Body,
    /// Its request was no chunk request, or was refused; which, it does not
    /// say.
    Refused,
}

pub(super) async fn exchange(
    State(server): State<Arc<SyncServer>>,
    Path(_repo): Path<String>,
    parts: Parts,
    body: Body,
) -> Result<Response, EnvelopedApiError> {
    let auth = authorize_request(&parts, &server, LfsAccess::Read).await?;
    // The machine the request's connection proved: the selector, the
    // manifest and every piece are judged for it (FIX 4937).
    let peer = auth.peer();
    let principal = auth.require_registered_principal()?;
    let principal = oneiron::EntityId::from_hex(principal)
        .map_err(|_| ApiError::forbidden_scope("registered chunk principal"))?;
    // It decodes its request as its frames arrive and writes its reply as its
    // client takes it (FIX 145), so it takes room in the LFS memory row first
    // for its request decoded, by all the length its request declares (a
    // frame's when it declares none, each byte it reads past that charged as
    // it arrives), and for the rest of the exchange; then it is an LFS
    // transfer like any other. Its worker holds both until the request is
    // answered, whether or not its caller is still there, and hands them on
    // to the reply. It waits on its headers and reads its body at its turn,
    // so a request in line holds none of it.
    let declared = declared_size(&parts.headers);
    let room_taken = Transfers::exchange_room(declared);
    let Some(room) = server.transfers.lfs_read_room(room_taken).await else {
        return Ok(lfs_waited_out());
    };
    let Ok(permit) = server.transfers.admit_lfs(auth.principal_ref()).await else {
        return Ok(lfs_waited_out());
    };
    let mut request = ChargedBody::feed(
        body,
        &server.transfers,
        (room, room_taken),
        Transfers::exchange_request_bytes(declared),
    );
    let vault = Arc::clone(&server.vault);
    let scope = crate::handler::selector_grant_scope();
    let caller = auth.clone();
    let line = server.transfers.lfs_reads_line();
    let questions = Arc::clone(&server.transfers.questions);
    let (served, permit) = crate::api::transfer::spawn_worker(move || {
        let decoded = oneiron::sync::chunks::read_chunk_request_stream(&mut request);
        let failed = request.failed();
        let (mut room, room_taken) = request.into_room();
        let served = match decoded {
            Ok(decoded) => answer(
                &vault,
                decoded,
                (&caller, principal, scope, peer),
                (&line, &questions, &mut room, room_taken),
            )
            .map_err(|_| Unanswered::Refused),
            Err(_) if failed => Err(Unanswered::Body),
            Err(_) => Err(Unanswered::Refused),
        };
        (served, (room, permit))
    })
    .await
    .map_err(|_| ApiError::internal_server_error("lfs chunk worker failed"))?;
    let (object, response, read) = served.map_err(|unanswered| match unanswered {
        Unanswered::Body => {
            ApiError::bad_request("the request body ended before it was whole", None)
        }
        // Do not reveal absent object vs denied selector vs hash membership.
        Unanswered::Refused => ApiError::forbidden_scope("lfs chunk selector"),
    })?;
    #[cfg(test)]
    release_hook::run(&server);
    // A device-only flag may land while the worker builds the reply, or a
    // marked object's read stop standing: the object is judged again as its
    // bytes are released.
    let reads_marked = read
        .as_ref()
        .is_some_and(|read| read.stands(&server.vault, object));
    if oneiron::sync::chunks::lfs_object_withheld_as(&server.vault, object, peer, reads_marked)
        .unwrap_or(true)
    {
        return Err(ApiError::forbidden_scope("lfs chunk selector").into());
    }
    // No length is declared: the stream's end frame makes a reply cut short
    // at the idle limit a broken transfer to the client, never a shorter one
    // (FIX 145).
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/vnd.oneiron.chunks")],
        reply(
            Arc::clone(&server.vault),
            (object, peer, read),
            response,
            permit,
            server.transfers.idle,
        ),
    )
        .into_response())
}

/// The page `request` asks for, judged for `peer`, the machine the request
/// proved (FIX 4937), under `principal`'s grant in `scope`. The object is
/// named only now: the copies of a manifest row past the frame its room
/// counted are charged on the exchange's room before the serve reads it
/// whole (FIX 9032). A lift-marked object's real bytes go to the owner and to
/// an agent whose read is granted, each as `caller` authenticated it (FIX
/// 2897); the read rides with the reply.
fn answer(
    vault: &Vault,
    request: ChunkSyncRequest,
    (caller, principal, scope, peer): (
        &crate::auth::CoreAuth,
        oneiron::EntityId,
        FederationGrantScope,
        PeerMachine,
    ),
    (line, questions, room, room_taken): (&ByteLine, &LimitQuestions, &mut HeldBytes, u64),
) -> oneiron::Result<(LfsOid, ChunkSyncResponse, Option<LfsMarkedRead>)> {
    let object = LfsOid::from_bytes(request.oid);
    if let Some(row) = vault.lfs_manifest_row_bytes(object)? {
        Transfers::charge_exchange_manifest(line, questions, room, room_taken, row);
    }
    let mut read = None;
    let response = oneiron::sync::chunks::answer_chunk_request(
        vault,
        principal,
        scope,
        request,
        peer,
        &mut |oid, asked| {
            read = LfsMarkedRead::of(vault, caller, oid, asked);
            Ok(read.as_ref().map(LfsMarkedRead::authority))
        },
    )?;
    Ok((object, response, read))
}

/// The reply, written as its stream's frames by a worker that holds the
/// memory room and the transfer permit until its end frame is handed on, or
/// until the client has taken none for `idle` (FIX 145): its encoding is
/// never held whole, only the frames in flight. Only the frames already
/// handed out outlive it. Each piece is judged for `peer`, the machine the
/// request proved, and a marked object's for its read.
fn reply(
    vault: Arc<Vault>,
    (object, peer, read): (LfsOid, PeerMachine, Option<LfsMarkedRead>),
    response: ChunkSyncResponse,
    permit: ReadHold,
    idle: Duration,
) -> Body {
    let (pieces, receiver) = mpsc::channel::<Bytes>(LFS_PIECES_IN_FLIGHT);
    let runtime = Handle::current();
    // A worker that never starts drops the room and the permit; the reply
    // ends before its end frame, a broken transfer to the client.
    let _ = crate::api::transfer::spawn_worker(move || {
        let _permit = permit;
        let mut frames = ReplyFrames {
            pieces,
            runtime,
            idle,
        };
        let _ = oneiron::sync::chunks::write_chunk_response_stream(&response, &mut frames);
    });
    // Each piece is released only while no world withheld from the peer
    // keeps the object; a flag set mid-reply ends the body with an error that
    // says why (FIX 4939).
    Body::from_stream(stream::unfold(receiver, move |mut receiver| {
        let vault = Arc::clone(&vault);
        let read = read.clone();
        async move {
            let piece = receiver.recv().await?;
            if let Some(kept) = lfs_piece_hold(&vault, object, peer, read.as_ref()) {
                receiver.close();
                return Some((Err(kept), receiver));
            }
            Some((Ok(piece), receiver))
        }
    }))
}

/// The reply's frames on their way to the client: each write the stream makes,
/// one whole frame, is handed on as one piece, waiting at most `idle` for the
/// client to make room. A client that stopped reading ends the reply with
/// `TimedOut`, and one that went away with `BrokenPipe`.
struct ReplyFrames {
    pieces: mpsc::Sender<Bytes>,
    runtime: Handle,
    idle: Duration,
}

impl io::Write for ReplyFrames {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        crate::api::transfer::send_within(
            &self.runtime,
            &self.pieces,
            Bytes::copy_from_slice(bytes),
            self.idle,
        )?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A device-only flag committed after the worker built its reply and before
/// the handler releases it.
#[cfg(test)]
pub(super) mod release_hook {
    use std::cell::Cell;

    thread_local! {
        // Per thread: the handler resumes on the test's own current-thread
        // runtime.
        static FLAG: Cell<Option<oneiron::EntityId>> = const { Cell::new(None) };
    }

    pub(in crate::api::git_lfs) fn arm(world: oneiron::EntityId) {
        FLAG.set(Some(world));
    }

    pub(super) fn run(server: &crate::server::SyncServer) {
        if let Some(world) = FLAG.take() {
            server
                .vault
                .keep_world_on_this_machine_under_for_test(
                    &crate::test_credentials::host_issuer(server),
                    world,
                    true,
                )
                .expect("device-only flag");
        }
    }
}
