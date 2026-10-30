//! A socket's by-reference ASSET body transfers on the home (FIX 5489): the
//! engine's session over the windows this socket moves bodies for. An owner
//! lane moves them for each window it is pushed, a residence lane for each
//! window it promoted, and no other lane for any: a body frame on one is
//! answered with incomplete Ends, and it is asked for none.

use std::time::{Duration, Instant};

use oneiron::sync::{
    ASSET_BODY_FRAMES_PER_POLL, AssetBodyPeer, AssetBodySession, TransportError, WindowKey,
};

use super::conn_state::{ConnState, WindowSyncMode};
use crate::protocol::{self, ProtocolError};
use crate::server::SyncServer;

/// How often a socket's body transfers send and ask while its direct queue
/// is empty (a call, FIX 5489): a send's pace, never a body bound.
pub(super) const ASSET_BODY_POLL: Duration = Duration::from_millis(50);

/// One body frame from the device, `tag` and the bytes after it: answered on
/// `direct_tx`, the session's next frames with it.
///
/// # Errors
///
/// [`ProtocolError::UnknownTag`] while the file plane is off, as before it;
/// a frame that does not decode.
pub(super) fn handle(
    server: &SyncServer,
    state: &mut ConnState,
    tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    let frames = with_peer(server, state, |peer, bodies| {
        let mut out = bodies.handle_frame(peer, tag, payload)?;
        out.extend(bodies.poll(
            peer,
            Instant::now(),
            ASSET_BODY_FRAMES_PER_POLL,
            server.config.max_frame_size,
        )?);
        Ok(out)
    })
    .map_err(|error| match error {
        TransportError::UnknownTag(tag) => ProtocolError::UnknownTag(tag),
        error => ProtocolError::InvalidPayload(protocol::transport_err_msg(error)),
    })?;
    queue(direct_tx, frames)
}

/// The socket's body upkeep: what its transfers owe now, queued on
/// `direct_tx`. A failed scan is logged and the socket stays up.
pub(super) fn poll(
    server: &SyncServer,
    state: &mut ConnState,
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) {
    let polled = with_peer(server, state, |peer, bodies| {
        bodies.poll(
            peer,
            Instant::now(),
            ASSET_BODY_FRAMES_PER_POLL,
            server.config.max_frame_size,
        )
    });
    match polled {
        Ok(frames) => {
            let _ = queue(direct_tx, frames);
        }
        Err(error) => tracing::warn!(%error, "asset body poll failed"),
    }
}

/// Runs `f` over this socket's session and the peer it reads through: the
/// home's live documents of the windows the socket moves bodies for.
fn with_peer<T>(
    server: &SyncServer,
    state: &mut ConnState,
    f: impl FnOnce(&AssetBodyPeer<'_>, &mut AssetBodySession) -> T,
) -> T {
    let followed = followed_windows(server, state);
    let manager = &server.reassert_manager;
    let window = |key: &WindowKey| {
        followed
            .contains(key)
            .then(|| manager.window(key))
            .flatten()
            .map(|loaded| loaded.doc.clone())
    };
    let windows = || followed.clone();
    let peer = AssetBodyPeer {
        vault: server.vault(),
        lease_vault_id: manager.materializer().lease_vault_id(),
        window: &window,
        windows: &windows,
    };
    f(&peer, &mut state.asset_bodies)
}

/// The windows this socket moves bodies for now.
fn followed_windows(server: &SyncServer, state: &ConnState) -> Vec<WindowKey> {
    match state.window_sync_mode {
        WindowSyncMode::FullWindow => server
            .reassert_manager
            .loaded_keys()
            .into_iter()
            .filter(|key| state.receives_window(key))
            .collect(),
        WindowSyncMode::Residence => state.promoted_windows.keys().cloned().collect(),
        WindowSyncMode::Selector | WindowSyncMode::Unbound => Vec::new(),
    }
}

/// Queues `frames` on this socket's direct lane, whose sends take the guarded
/// door every reply takes.
fn queue(
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    frames: Vec<Vec<u8>>,
) -> Result<(), ProtocolError> {
    for frame in frames {
        direct_tx
            .send(frame)
            .map_err(|_| ProtocolError::InvalidPayload("asset body reply channel closed"))?;
    }
    Ok(())
}
