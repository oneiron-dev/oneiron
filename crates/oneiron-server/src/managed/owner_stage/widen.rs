//! Byte-exact verification of the supervisor's widen action, without a body ceiling.

use std::io::{ErrorKind, Read, Seek, SeekFrom};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use futures_util::{StreamExt, stream};
use oneiron_vault_contract::{ManagedWidenAction, ManagedWidenTranscript};

use super::{STAGE_PIECE, body_failed, declared_length, replay, spool_body, stage_failed};
use crate::managed::ledger::WakeLedger;
use crate::managed::state_serve::ManagedWidenHolder;
use crate::server::SyncServer;

/// The former refusal boundary, used only to choose memory or disk.
const HELD_WIDEN_BYTES: usize = 2 * 1024 * 1024;

pub(in crate::managed) async fn verify_widen(
    server: &SyncServer,
    ledger: &WakeLedger,
    assertion: &ManagedWidenAction,
    request: Request,
) -> Result<Request, Response> {
    let (parts, body) = request.into_parts();
    let declared = declared_length(&parts);
    let mut pieces = body.into_data_stream();
    let mut held = Vec::new();
    if declared.is_none_or(|size| size <= HELD_WIDEN_BYTES as u64) {
        loop {
            let piece = match tokio::time::timeout(server.transfers.idle, pieces.next()).await {
                Ok(None) => {
                    let verified = ledger.verify_widen_action(assertion, &held);
                    let request = Request::from_parts(parts, Body::from(held));
                    return Ok(mark_holder(request, assertion, verified));
                }
                Ok(Some(Ok(piece))) => piece,
                Ok(Some(Err(_))) => return Err(body_failed()),
                Err(_) => {
                    return Err((
                        axum::http::StatusCode::REQUEST_TIMEOUT,
                        "the request body stalled past the transfer idle limit",
                    )
                        .into_response());
                }
            };
            if piece.len() > HELD_WIDEN_BYTES - held.len() {
                pieces = Body::from_stream(
                    stream::once(async move { Ok::<_, axum::Error>(piece) }).chain(pieces),
                )
                .into_data_stream();
                break;
            }
            held.extend_from_slice(&piece);
        }
    }
    let (spool, length) = spool_body(server, Bytes::from(held), pieces, declared, None).await?;
    let transcript = ledger.widen_transcript(&assertion.holder_ref, length);
    let hashed = tokio::task::spawn_blocking(move || hash_spool(spool, transcript)).await;
    let Ok(Ok((spool, transcript))) = hashed else {
        return Err(stage_failed());
    };
    let verified = assertion.verify_transcript(transcript);
    let request = Request::from_parts(parts, replay(spool));
    Ok(mark_holder(request, assertion, verified))
}

/// An invalid assertion still goes through without adding an identity.
fn mark_holder(mut request: Request, assertion: &ManagedWidenAction, verified: bool) -> Request {
    if verified && let Ok(holder) = oneiron::EntityId::from_hex(&assertion.holder_ref) {
        request.extensions_mut().insert(ManagedWidenHolder(holder));
    }
    request
}

fn hash_spool(
    mut spool: std::fs::File,
    mut transcript: ManagedWidenTranscript,
) -> std::io::Result<(std::fs::File, ManagedWidenTranscript)> {
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
