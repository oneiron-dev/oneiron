//! Versioned owner-authenticated chunk requests, disjoint from selector window mode.

use super::conn_state::{ConnState, WindowSyncMode};
use crate::protocol::{self, ProtocolError};
use crate::server::SyncServer;

pub(super) async fn handle(
    server: &SyncServer,
    payload: Vec<u8>,
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    state: &mut ConnState,
) -> Result<(), ProtocolError> {
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
    let (object, response) = tokio::task::spawn_blocking(move || {
        let object = oneiron::sync::chunks::chunk_request_object(&payload)?;
        oneiron::sync::chunks::serve_owner_chunk_request_for(&vault, &payload, peer)
            .map(|response| (object, response))
    })
    .await
    .map_err(|e| ProtocolError::Persistence(e.to_string()))?
    .map_err(|_| ProtocolError::InvalidPayload("chunk request refused"))?;
    let frame = oneiron::sync::transport::encode_lfs_chunk_sync(&response)
        .into_result()
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
    state.queued_chunk_objects.push_back(object);
    direct_tx
        .send(frame)
        .map_err(|_| ProtocolError::InvalidPayload("chunk reply channel closed"))
}

/// Whether a queued chunk reply leaves now: its object, recorded when the
/// reply was queued, is checked against the device-only flag as it stands,
/// for the machine this socket proved, its proof revalidated now (mesh PR2b).
pub(super) fn chunk_reply_withheld(server: &SyncServer, state: &mut ConnState) -> bool {
    let peer = state.peer_machine(server.vault());
    state.queued_chunk_objects.pop_front().is_none_or(|object| {
        oneiron::sync::chunks::lfs_object_withheld_for(server.vault(), object, peer).unwrap_or(true)
    })
}
