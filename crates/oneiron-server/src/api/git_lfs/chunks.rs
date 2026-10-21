//! Grant-scoped binary have/want endpoint over the standing bearer identity.

use super::gate::{LfsAccess, authorize_request};
use super::support::{LfsMarkedRead, declared_size, lfs_piece_hold, lfs_waited_out, read_whole};
use crate::api::Transfers;
use crate::api::transfer::ReadHold;
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use oneiron::Vault;
use oneiron::authority::PeerMachine;
use oneiron::origin::lfs::{LFS_CHUNK_MAX, LfsOid};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub(super) async fn exchange(
    State(server): State<Arc<SyncServer>>,
    Path(_repo): Path<String>,
    parts: Parts,
    body: Body,
) -> Result<Response, EnvelopedApiError> {
    let auth = authorize_request(&parts, &server, LfsAccess::Read)?;
    // The machine the request's connection proved: the selector, the
    // manifest and every piece are judged for it (FIX 4937).
    let peer = auth.peer();
    let principal = auth.require_registered_principal()?;
    let principal = oneiron::EntityId::from_hex(principal)
        .map_err(|_| ApiError::forbidden_scope("registered chunk principal"))?;
    // It reads its request, decodes its selector into a tree of values and
    // builds its reply whole, so it takes room for all of it in the LFS
    // memory row first, by the length its request declares; then it is an
    // LFS transfer like any other. Its worker holds both until the reply is
    // built, whether or not its caller is still there, and hands them on to
    // the reply. It waits on its headers and reads its body at its turn, so
    // a request in line holds none of it.
    let declared = declared_size(&parts.headers);
    let Some(room) = server
        .transfers
        .lfs_read_room(Transfers::exchange_room(declared))
        .await
    else {
        return Ok(lfs_waited_out());
    };
    let Ok(permit) = server.transfers.admit_lfs(auth.principal_ref()).await else {
        return Ok(lfs_waited_out());
    };
    let permit = (room, permit);
    let frame = oneiron::sync::chunks::MAX_CHUNK_SYNC_FRAME;
    let limit = declared.map_or(frame, |declared| {
        usize::try_from(declared).unwrap_or(frame).min(frame)
    });
    let body = read_whole(body, limit).await?;
    let vault = Arc::clone(&server.vault);
    let scope = crate::handler::selector_grant_scope();
    let caller = auth.clone();
    let (object, bytes, read, permit) = crate::api::transfer::spawn_worker(move || {
        let object = oneiron::sync::chunks::chunk_request_object(&body)?;
        // A lift-marked object's real bytes go to the owner and to an agent
        // whose read is granted, each as this request authenticated it (FIX
        // 2897); the read rides with the reply.
        let mut read = None;
        let bytes = oneiron::sync::chunks::serve_chunk_request_reading(
            &vault,
            principal,
            scope,
            &body,
            peer,
            &mut |oid, asked| {
                read = LfsMarkedRead::of(&vault, &caller, oid, asked);
                Ok(read.as_ref().map(LfsMarkedRead::authority))
            },
        )?;
        Ok::<_, oneiron::Error>((object, bytes, read, permit))
    })
    .await
    .map_err(|_| ApiError::internal_server_error("lfs chunk worker failed"))?
    // Do not reveal absent object vs denied selector vs hash membership.
    .map_err(|_| ApiError::forbidden_scope("lfs chunk selector"))?;
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
    // The declared length makes a reply cut short at the idle limit a broken
    // transfer to the client, never a shorter one.
    let length = bytes.len().to_string();
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/vnd.oneiron.chunks"),
            (header::CONTENT_LENGTH, length.as_str()),
        ],
        reply(
            Arc::clone(&server.vault),
            (object, peer, read),
            bytes,
            permit,
            server.transfers.idle,
        ),
    )
        .into_response())
}

/// The reply, handed out a piece at a time by a task that holds the memory
/// room and the transfer permit until the last piece is taken, or until the
/// client has taken none for `idle`. Only the pieces already handed out
/// outlive it. Each piece is judged for `peer`, the machine the request
/// proved, and a marked object's for its read.
fn reply(
    vault: Arc<Vault>,
    (object, peer, read): (LfsOid, PeerMachine, Option<LfsMarkedRead>),
    bytes: Vec<u8>,
    permit: ReadHold,
    idle: Duration,
) -> Body {
    let (pieces, receiver) = mpsc::channel::<Bytes>(2);
    tokio::spawn(async move {
        let _permit = permit;
        for piece in bytes.chunks(LFS_CHUNK_MAX) {
            let piece = Bytes::copy_from_slice(piece);
            if pieces.send_timeout(piece, idle).await.is_err() {
                return;
            }
        }
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
