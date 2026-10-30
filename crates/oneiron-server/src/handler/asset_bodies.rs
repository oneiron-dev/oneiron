//! A socket's by-reference ASSET body transfers on the home (FIX 5489): the
//! engine's session over the windows this socket moves bodies for. An owner
//! lane moves them for each window it is pushed, a residence lane for each
//! window it promoted, and no other lane for any: a body frame on one is
//! answered with incomplete Ends, and it is asked for none. A body frame's
//! landing runs on a blocking thread, off the socket's loop, which waits for
//! it before it reads the socket's next frame: one landing at a time per
//! socket, in frame order (FIX 12119).

use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use oneiron::sync::{
    ASSET_BODY_FRAMES_PER_POLL, AssetBodyPeer, TransportError, WindowKey, WindowManager,
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
pub(super) async fn handle(
    server: &SyncServer,
    state: &mut ConnState,
    tag: u8,
    payload: Vec<u8>,
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    let followed = followed_windows(server, state);
    // The session goes to the blocking thread and comes back with its frames.
    // A landing that panicked leaves the socket a fresh session: its transfers
    // start again from their first byte, as on a new connection.
    let mut bodies = std::mem::take(
        state
            .asset_bodies
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner),
    );
    let vault = Arc::clone(server.vault());
    let manager = Arc::clone(&server.reassert_manager);
    let socket_max = server.config.max_frame_size;
    let (bodies, frames) = tokio::task::spawn_blocking(move || {
        let frames = with_peer(&vault, &manager, &followed, |peer| {
            let mut out = bodies.handle_frame(peer, tag, &payload)?;
            out.extend(bodies.poll(
                peer,
                Instant::now(),
                ASSET_BODY_FRAMES_PER_POLL,
                socket_max,
            )?);
            Ok::<_, TransportError>(out)
        });
        (bodies, frames)
    })
    .await
    .map_err(|error| ProtocolError::Persistence(format!("asset body landing stopped: {error}")))?;
    *state
        .asset_bodies
        .get_mut()
        .unwrap_or_else(PoisonError::into_inner) = bodies;
    let frames = frames.map_err(|error| match error {
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
    let followed = followed_windows(server, state);
    let bodies = state
        .asset_bodies
        .get_mut()
        .unwrap_or_else(PoisonError::into_inner);
    let polled = with_peer(server.vault(), &server.reassert_manager, &followed, |peer| {
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

/// Runs `f` over the peer this socket's session reads through: the home's
/// live documents, under `manager`, of the windows `followed` the socket
/// moves bodies for.
fn with_peer<T>(
    vault: &oneiron::Vault,
    manager: &WindowManager,
    followed: &[WindowKey],
    f: impl FnOnce(&AssetBodyPeer<'_>) -> T,
) -> T {
    let window = |key: &WindowKey| {
        followed
            .contains(key)
            .then(|| manager.window(key))
            .flatten()
            .map(|loaded| loaded.doc.clone())
    };
    let windows = || followed.to_vec();
    f(&AssetBodyPeer {
        vault,
        materializer: manager.materializer(),
        window: &window,
        windows: &windows,
    })
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
