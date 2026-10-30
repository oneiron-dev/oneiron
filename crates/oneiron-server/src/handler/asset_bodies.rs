//! A socket's by-reference ASSET body transfers on the home (FIX 5489): the
//! engine's session over the windows this socket moves bodies for. An owner
//! lane moves them for each window it is pushed, a residence lane for each
//! window it promoted, and a federation lane serves, and never asks for, the
//! bodies of the rows its selector admitted, from the copy it was sent, while
//! its credential and that selector stand (FIX 12118). An unbound lane moves
//! none: a body frame on one is answered with incomplete Ends, and it is
//! asked for none. A body frame's
//! landing runs on a blocking thread, off the socket's loop, which waits for
//! it before it reads the socket's next frame: one landing at a time per
//! socket, in frame order (FIX 12119).

use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use oneiron::sync::{
    ASSET_BODY_FRAMES_PER_POLL, AssetBodyLane, AssetBodyPeer, TransportError, WindowKey,
    WindowManager, authorize_sync_selector,
};

use super::app_tier::require_bound_app_auth;
use super::conn_state::{ConnState, WindowSyncMode};
use super::window_sync::selector_grant_scope;
use crate::protocol::{self, ProtocolError};
use crate::server::SyncServer;

/// How often a socket's body transfers send and ask while its direct queue
/// is empty (a call, FIX 5489): a send's pace, never a body bound.
pub(super) const ASSET_BODY_POLL: Duration = Duration::from_millis(50);

/// One body frame from the socket's peer, `tag` and the bytes after it:
/// answered on `direct_tx`, the session's next frames with it.
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

/// The windows a socket moves bodies for now, and where their documents
/// come from.
enum Followed {
    /// The home's live windows, under its manager: an own lane's.
    Live(Vec<WindowKey>),
    /// The copies a federation socket's selector admitted, as it was sent
    /// them (FIX 12118).
    Admitted(Vec<(WindowKey, loro::LoroDoc)>),
}

/// Runs `f` over the peer this socket's session reads through: the
/// documents, the home's live ones under `manager` or a federation socket's
/// admitted copies, of the windows `followed` the socket moves bodies for.
fn with_peer<T>(
    vault: &oneiron::Vault,
    manager: &WindowManager,
    followed: &Followed,
    f: impl FnOnce(&AssetBodyPeer<'_>) -> T,
) -> T {
    let (lane, keys) = match followed {
        Followed::Live(keys) => (AssetBodyLane::OwnDevice, keys.clone()),
        Followed::Admitted(copies) => (
            AssetBodyLane::FederationGrant,
            copies.iter().map(|(key, _)| key.clone()).collect(),
        ),
    };
    let window = |key: &WindowKey| match followed {
        Followed::Live(keys) => keys
            .contains(key)
            .then(|| manager.window(key))
            .flatten()
            .map(|loaded| loaded.doc.clone()),
        Followed::Admitted(copies) => copies
            .iter()
            .find(|(admitted, _)| admitted == key)
            .map(|(_, doc)| doc.clone()),
    };
    let windows = || keys.clone();
    f(&AssetBodyPeer {
        lane,
        vault,
        materializer: manager.materializer(),
        window: &window,
        windows: &windows,
    })
}

/// The windows this socket moves bodies for now.
fn followed_windows(server: &SyncServer, state: &ConnState) -> Followed {
    match state.window_sync_mode {
        WindowSyncMode::FullWindow => Followed::Live(
            server
                .reassert_manager
                .loaded_keys()
                .into_iter()
                .filter(|key| state.receives_window(key))
                .collect(),
        ),
        WindowSyncMode::Residence => {
            Followed::Live(state.promoted_windows.keys().cloned().collect())
        }
        // A federation socket's copies, each while its selector still
        // authorizes, and only while the socket's credential is live.
        WindowSyncMode::Selector if require_bound_app_auth(server, state).is_ok() => {
            Followed::Admitted(
                state
                    .admitted_windows
                    .iter()
                    .filter(|(_, (selector, _))| {
                        authorize_sync_selector(
                            server.vault.as_ref(),
                            selector_grant_scope(),
                            selector,
                        )
                        .is_ok()
                    })
                    .map(|(key, (_, doc))| (key.clone(), doc.clone()))
                    .collect(),
            )
        }
        WindowSyncMode::Selector | WindowSyncMode::Unbound => Followed::Live(Vec::new()),
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
