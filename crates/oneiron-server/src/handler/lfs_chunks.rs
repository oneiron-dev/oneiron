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
    if state.protocol_version != protocol::CHUNK_FULL_WINDOW_PROTOCOL_VERSION
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
    let response = tokio::task::spawn_blocking(move || {
        oneiron::sync::chunks::serve_owner_chunk_request(&vault, &payload)
    })
    .await
    .map_err(|e| ProtocolError::Persistence(e.to_string()))?
    .map_err(|_| ProtocolError::InvalidPayload("chunk request refused"))?;
    let frame = oneiron::sync::transport::encode_lfs_chunk_sync(&response)
        .into_result()
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
    direct_tx
        .send(frame)
        .map_err(|_| ProtocolError::InvalidPayload("chunk reply channel closed"))
}
