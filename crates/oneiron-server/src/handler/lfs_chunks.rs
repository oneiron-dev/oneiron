//! Versioned owner-authenticated chunk requests, disjoint from selector window mode.

use std::ops::ControlFlow;

use super::conn_state::{ConnState, WindowSyncMode};
use crate::protocol::{self, ProtocolError};
use crate::server::SyncServer;

/// `Break` when `session_gone` finds the socket's caller gone once the request
/// was served (FIX 6313): no reply is queued, and the connection ends as the
/// gate before dispatch ends it.
pub(super) async fn handle(
    server: &SyncServer,
    payload: Vec<u8>,
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    state: &mut ConnState,
    session_gone: &(dyn Fn() -> bool + Sync),
) -> Result<ControlFlow<()>, ProtocolError> {
    if (!protocol::is_owner_window_version(state.protocol_version)
        && !protocol::is_residence_version(state.protocol_version))
        || state.window_sync_mode == WindowSyncMode::Selector
    {
        return Err(ProtocolError::InvalidPayload(
            "chunk lane needs a chunk-capable owner connection",
        ));
    }
    if payload.len() > oneiron::sync::chunks::MAX_CHUNK_SYNC_FRAME {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: oneiron::sync::chunks::MAX_CHUNK_SYNC_FRAME,
        });
    }
    state.lfs_owner_mode = true;
    // The outer socket already applies its message rate budget and revocation
    // consults. One direct response per request, with no unsolicited broadcast.
    let vault = std::sync::Arc::clone(server.vault());
    // The manifest and every WANT are judged for the machine this socket
    // proved (mesh PR2b); an unproved one is an unknown destination.
    let peer = state.peer_machine(server.vault());
    let (object, read, response) = tokio::task::spawn_blocking(move || {
        let object = oneiron::sync::chunks::chunk_request_object(&payload)?;
        // A lift-marked object's real bytes go to a machine the owner trusts
        // as his own, which this socket proved (FIX 2897); the authority
        // rides with the queued reply.
        let mut read = None;
        let response = oneiron::sync::chunks::serve_owner_chunk_request_reading(
            &vault,
            &payload,
            peer,
            &mut |_, _| {
                read = vault.lfs_owner_machine_read(peer);
                Ok(read)
            },
        )?;
        Ok::<_, oneiron::Error>((object, read, response))
    })
    .await
    .map_err(|e| ProtocolError::Persistence(e.to_string()))?
    .map_err(|_| ProtocolError::InvalidPayload("chunk request refused"))?;
    // FIX 6313: the blocking service may wait, and the session the gate
    // before dispatch found live may have gone meanwhile.
    if session_gone() {
        tracing::warn!("credential revoked — refusing sync message and closing");
        return Ok(ControlFlow::Break(()));
    }
    let frame = oneiron::sync::transport::encode_lfs_chunk_sync(&response)
        .into_result()
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
    state.queued_chunk_objects.push_back((object, read));
    direct_tx
        .send(frame)
        .map_err(|_| ProtocolError::InvalidPayload("chunk reply channel closed"))?;
    Ok(ControlFlow::Continue(()))
}

/// Whether a queued chunk reply leaves now: its object, recorded when the
/// reply was queued, is checked against the device-only flag as it stands,
/// for the machine this socket proved, its proof revalidated now (mesh PR2b).
/// A lift-marked object's reply leaves only while the machine it was read
/// for still stands as the owner's own (FIX 2897).
pub(super) fn chunk_reply_withheld(server: &SyncServer, state: &mut ConnState) -> bool {
    let peer = state.peer_machine(server.vault());
    state
        .queued_chunk_objects
        .pop_front()
        .is_none_or(|(object, read)| {
            let reads_marked =
                read.is_some_and(|read| server.vault().lfs_owner_machine_read(peer) == Some(read));
            oneiron::sync::chunks::lfs_object_withheld_as(
                server.vault(),
                object,
                peer,
                reads_marked,
            )
            .unwrap_or(true)
        })
}
