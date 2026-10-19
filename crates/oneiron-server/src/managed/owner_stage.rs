//! Managed ingress's byte-exact staging of an owner-attested request whose
//! body streams (FIX 5255, part 2 of 3): git smart HTTP and LFS, and the
//! uploads that take up to 96 MiB ([`super::attested_routes`]'s staged
//! routes).
//!
//! The supervisor's `ManagedOwnerAction` covers the request's exact body,
//! its length first, so the body has to be held whole before the action can
//! be checked. These routes take more than the buffered verification holds,
//! or have no ceiling at all, so their body is spooled instead: to an
//! anonymous file on the vault's own disk, under the free-space floor every
//! transfer keeps, counted as it lands. The spool is then hashed into the
//! same v2 transcript, the counted length first, and the action verified
//! before any handler runs; only then is the spool replayed, byte for byte,
//! as the request's body. Nothing is held in memory but the piece in hand,
//! and a compressed body is verified as sent, before any route decodes it.
//!
//! Every other attested route's body is held in memory up to the buffered
//! verification's 64 MiB, as it always was, and spills to the same stage
//! past it (FIX 5619, Rule 5): its size never refuses it, only the disk's
//! floor ([`verify_held`]).

use std::io::{ErrorKind, Read, Seek, SeekFrom};

use axum::body::{Body, BodyDataStream, Bytes};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use oneiron_vault_contract::{
    MANAGED_OWNER_BOUND_HEADERS, ManagedOwnerAction, ManagedOwnerHead, ManagedOwnerRequest,
    ManagedOwnerTranscript,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::ledger::WakeLedger;
use super::state_serve::{ManagedOwnerHolder, owner_attestation_refused};
use crate::server::SyncServer;

/// The most of a staged body read at once, as it is hashed and as it is
/// replayed: a buffer's size, not a bound on the body.
const STAGE_PIECE: usize = 64 * 1024;

/// The most of a buffered route's body ingress holds in memory to verify it
/// (`MAX_REMOTE_REQUEST_BYTES`, 64 MiB): what those routes held whole before
/// FIX 5619. A body within it needs no disk; one past it is staged.
const HELD_BODY_BYTES: usize = oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;

/// Verifies `assertion` over `request` with its body staged, and hands the
/// request back with that body replayed and the owner it names marked. Or
/// answers why not, with nothing served: a body past the route's own
/// `ceiling` (413), one that would take the vault's disk below its reserve
/// (507), one that stalled past the transfer idle limit (408) or failed
/// (400), and an assertion that does not verify over the request it came
/// with (401, never the host's root).
pub(super) async fn verify_staged(
    server: &SyncServer,
    ledger: &WakeLedger,
    assertion: &ManagedOwnerAction,
    request: Request,
    ceiling: Option<u64>,
) -> Result<Request, Response> {
    let Ok(holder) = oneiron::EntityId::from_hex(&assertion.holder_ref) else {
        return Err(owner_attestation_refused(request.uri().path()));
    };
    let (parts, body) = request.into_parts();
    let declared = declared_length(&parts);
    if ceiling
        .zip(declared)
        .is_some_and(|(ceiling, declared)| declared > ceiling)
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let pieces = body.into_data_stream();
    let (spool, length) = spool_body(server, Bytes::new(), pieces, declared, ceiling).await?;
    verify_spooled(ledger, assertion, holder, parts, spool, length).await
}

/// Verifies `assertion` over a request on a route the buffered verification
/// held (FIX 5619, Rule 5), so that its size never refuses it. A body within
/// [`HELD_BODY_BYTES`] is held and verified in memory, as it always was, and
/// a vault at its disk reserve still serves it. One past it, or declared
/// past it, is staged as [`verify_staged`] stages a streaming route's, with
/// no ceiling of its own: only the disk's floor ends it, and the route's own
/// body limit still holds once it is replayed. The answers are
/// [`verify_staged`]'s, and a body that failed is 400.
pub(super) async fn verify_held(
    server: &SyncServer,
    ledger: &WakeLedger,
    assertion: &ManagedOwnerAction,
    request: Request,
) -> Result<Request, Response> {
    let Ok(holder) = oneiron::EntityId::from_hex(&assertion.holder_ref) else {
        return Err(owner_attestation_refused(request.uri().path()));
    };
    let (parts, body) = request.into_parts();
    let declared = declared_length(&parts);
    let mut pieces = body.into_data_stream();
    let mut held = Vec::new();
    let fits = declared.is_none_or(|declared| {
        usize::try_from(declared).is_ok_and(|declared| declared <= HELD_BODY_BYTES)
    });
    if fits {
        loop {
            match pieces.next().await {
                None => return verify_in_memory(ledger, assertion, holder, parts, held),
                Some(Ok(piece)) => {
                    held.extend_from_slice(&piece);
                    if held.len() > HELD_BODY_BYTES {
                        break;
                    }
                }
                Some(Err(_)) => return Err(body_failed()),
            }
        }
    }
    let (spool, length) = spool_body(server, Bytes::from(held), pieces, declared, None).await?;
    verify_spooled(ledger, assertion, holder, parts, spool, length).await
}

/// The length a request declares, when it declares one.
fn declared_length(parts: &Parts) -> Option<u64> {
    parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

/// Verifies `assertion` over the request `parts` head with its whole `body`
/// held, and hands the request back with that body and `holder` marked.
fn verify_in_memory(
    ledger: &WakeLedger,
    assertion: &ManagedOwnerAction,
    holder: oneiron::EntityId,
    parts: Parts,
    body: Vec<u8>,
) -> Result<Request, Response> {
    let header = |name: &'static str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    };
    let verified = ledger.verify_owner_action(
        assertion,
        &ManagedOwnerRequest {
            method: parts.method.as_str(),
            path: parts.uri.path(),
            query: parts.uri.query().unwrap_or(""),
            headers: MANAGED_OWNER_BOUND_HEADERS.map(header),
            body: &body,
        },
    );
    if !verified {
        return Err(owner_attestation_refused(parts.uri.path()));
    }
    let mut request = Request::from_parts(parts, Body::from(body));
    request.extensions_mut().insert(ManagedOwnerHolder(holder));
    Ok(request)
}

/// Verifies `assertion` over the request `parts` head with its body of
/// `length` bytes staged in `spool`, and hands the request back with the
/// spool replayed as its body and `holder` marked.
async fn verify_spooled(
    ledger: &WakeLedger,
    assertion: &ManagedOwnerAction,
    holder: oneiron::EntityId,
    parts: Parts,
    spool: std::fs::File,
    length: u64,
) -> Result<Request, Response> {
    let header = |name: &'static str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    };
    let head = ManagedOwnerHead {
        method: parts.method.as_str(),
        path: parts.uri.path(),
        query: parts.uri.query().unwrap_or(""),
        headers: MANAGED_OWNER_BOUND_HEADERS.map(header),
    };
    let transcript = ledger.owner_transcript(&assertion.holder_ref, &head, length);
    // The spool is read back on a blocking thread: a local file at the
    // disk's pace, never at a client's.
    let hashed = tokio::task::spawn_blocking(move || hash_spool(spool, transcript)).await;
    let Ok(Ok((spool, transcript))) = hashed else {
        return Err(stage_failed());
    };
    if !assertion.verify_transcript(transcript) {
        return Err(owner_attestation_refused(parts.uri.path()));
    }
    let mut request = Request::from_parts(parts, replay(spool));
    request.extensions_mut().insert(ManagedOwnerHolder(holder));
    Ok(request)
}

/// Spools a body, `prefix` (what was already read of it) and then the rest of
/// `pieces`, to an anonymous file on the vault's disk and counts it.
/// Each piece first claims the room it has still to write on the disk's
/// floor (the rest the request declared, or the piece itself), so no
/// upload counts that room as free meanwhile; a piece that would take the
/// disk below its reserve ends the stage, and the spool goes with it.
async fn spool_body(
    server: &SyncServer,
    prefix: Bytes,
    pieces: BodyDataStream,
    declared: Option<u64>,
    ceiling: Option<u64>,
) -> Result<(std::fs::File, u64), Response> {
    let vault = std::sync::Arc::clone(server.vault());
    let opened = tokio::task::spawn_blocking(move || vault.archive_spool_file()).await;
    let Ok(Ok(spool)) = opened else {
        return Err(stage_failed());
    };
    let mut spool = tokio::fs::File::from_std(spool);
    let floor = server.transfers.disk.clone();
    let claim = floor.claim();
    let mut pieces =
        futures_util::stream::iter((!prefix.is_empty()).then_some(Ok::<_, axum::Error>(prefix)))
            .chain(pieces);
    let mut length: u64 = 0;
    loop {
        let piece = match tokio::time::timeout(server.transfers.idle, pieces.next()).await {
            Ok(Some(Ok(piece))) => piece,
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(body_failed()),
            Err(_) => {
                return Err((
                    StatusCode::REQUEST_TIMEOUT,
                    "the request body stalled past the transfer idle limit",
                )
                    .into_response());
            }
        };
        let size = u64::try_from(piece.len()).unwrap_or(u64::MAX);
        let landed = length.saturating_add(size);
        if ceiling.is_some_and(|ceiling| landed > ceiling) {
            return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
        }
        let still = declared.map_or(size, |declared| declared.saturating_sub(length).max(size));
        if !floor.hold(&claim, still) {
            return Err(disk_floor());
        }
        if let Err(error) = spool.write_all(&piece).await {
            return Err(if error.kind() == ErrorKind::StorageFull {
                disk_floor()
            } else {
                stage_failed()
            });
        }
        length = landed;
    }
    if spool.flush().await.is_err() {
        return Err(stage_failed());
    }
    Ok((spool.into_std().await, length))
}

/// Feeds the whole spool to `transcript`, and rewinds it for the replay.
fn hash_spool(
    mut spool: std::fs::File,
    mut transcript: ManagedOwnerTranscript,
) -> std::io::Result<(std::fs::File, ManagedOwnerTranscript)> {
    spool.seek(SeekFrom::Start(0))?;
    let mut piece = vec![0; STAGE_PIECE];
    loop {
        match spool.read(&mut piece) {
            Ok(0) => break,
            Ok(read) => transcript.update(&piece[..read]),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    spool.seek(SeekFrom::Start(0))?;
    Ok((spool, transcript))
}

/// The staged body as the request's own: the spool's bytes, in order, read
/// as the handler asks for them. The spool goes once the body does, read
/// to its end or dropped unread.
fn replay(spool: std::fs::File) -> Body {
    let spool = tokio::fs::File::from_std(spool);
    // A read that fails ends the body with its error, and nothing after it.
    let pieces = futures_util::stream::try_unfold(spool, |mut spool| async move {
        let mut piece = vec![0; STAGE_PIECE];
        let read = spool.read(&mut piece).await;
        read.map(|read| {
            (read > 0).then(|| {
                piece.truncate(read);
                (Bytes::from(piece), spool)
            })
        })
    });
    Body::from_stream(pieces)
}

/// The answer to a request body that failed on its way in.
fn body_failed() -> Response {
    (StatusCode::BAD_REQUEST, "the request body failed").into_response()
}

/// The refusal of a stage the vault's disk had no room for.
fn disk_floor() -> Response {
    (
        StatusCode::INSUFFICIENT_STORAGE,
        "the vault's disk is at its free-space reserve (limits.disk_reserve_bytes): the owner's \
         request body could not be staged for verification, and nothing was served",
    )
        .into_response()
}

/// The refusal of a stage the vault's disk could not write or read back.
fn stage_failed() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "the owner's request body could not be staged for verification; nothing was served",
    )
        .into_response()
}
