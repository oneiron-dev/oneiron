//! The served host's side of ready windows (fix list row 19634): a window a
//! policy wake persisted again here is asked of each socket's peer once per
//! ready generation, a few windows each tick, in turn
//! ([`oneiron::sync::manager::ReadyProgress`]), through the same last door as
//! every other frame the socket sends.
//!
//! Only a socket the window already reaches takes its notice, and only while
//! the machine it proved stands and may read the window's world, since a
//! vector names the window and its causal history too:
//! - an owner-lane socket the window is pushed to: the home's own
//!   `VV_REQUEST`, which the peer answers with its `UPDATE` and
//!   `VV_RESPONSE`, and the home answers that with what the peer lacks, as
//!   after a lag;
//! - an owner-lane socket that forgot the window's subscription past its row
//!   and follows `WINDOW_INVALIDATE`: that notice, which the peer answers
//!   with its `VV_REQUEST`;
//! - a residence socket that promoted the window: `PROMOTED_INVALIDATE`, under
//!   the same authorization as a live change's.
//!
//! No ready row subscribes a window, and no selector or federation socket is
//! asked. A notice is stamped once it is on the socket, or once a door keeps
//! it off on purpose; one that cannot be made now stays owed for the next
//! tick.

use loro::VersionVector;
use oneiron::authority::PeerMachine;
use oneiron::sync::WindowKey;
use oneiron::sync::manager::{READY_WINDOWS_PER_PASS, ReadyProgress};
use oneiron::sync::window::Withhold;

use super::app_tier::require_bound_app_auth;
use super::conn_state::{ConnState, WindowSyncMode};
use super::socket_stop::StoppingTransport;
use super::window_pads::{Released, send_released_outcome};
use crate::protocol::{self, window_sub_tags};
use crate::server::SyncServer;

/// What one ready window's notice is on this socket now.
enum ReadyNotice {
    /// The frame, with the credential it goes under when it is an app frame.
    Send(Vec<u8>, Option<String>),
    /// Kept off this socket on purpose: asked again at the window's next
    /// generation.
    Withheld,
    /// Not made now: owed again on the next tick.
    Retry,
}

/// Sends this socket's owed ready-window notices, up to
/// [`READY_WINDOWS_PER_PASS`] a tick; false once a send fails, as for every
/// other send of the socket.
pub(super) async fn send_ready_window_requests(
    server: &SyncServer,
    conn_state: &ConnState,
    progress: &mut ReadyProgress,
    transport: &mut StoppingTransport,
) -> bool {
    let due = match progress.due(&server.reassert_manager, READY_WINDOWS_PER_PASS, |key| {
        ready_window_allowed(conn_state, key)
    }) {
        Ok(due) => due,
        Err(error) => {
            tracing::warn!(%error, "ready windows not read");
            return true;
        }
    };
    for (key, generation) in due {
        let (frame, jti) = match ready_window_notice(server, conn_state, &key) {
            ReadyNotice::Send(frame, jti) => (frame, jti),
            ReadyNotice::Withheld => {
                progress.stamp(key, generation);
                continue;
            }
            ReadyNotice::Retry => continue,
        };
        transport.app_jti = jti;
        let released = send_released_outcome(server, conn_state, transport, frame).await;
        transport.app_jti = None;
        match released {
            Released::Sent | Released::Withheld => progress.stamp(key, generation),
            Released::Retry(_) => {}
            Released::Failed => return false,
        }
    }
    true
}

/// The last door's verdict on `frame` for the machine `peer` when it is a
/// window `UPDATE` or `REPLACEMENT`, with its window: read once, so the
/// socket withholds the frame and re-arms the window's ready request from
/// the same reading (FIX 19634). Anything but `Portable` is withheld; an
/// `Uninspectable` one is a passing failure, so its ready exchange is owed
/// again. `None` for any other frame.
pub(super) fn window_update_verdict(
    server: &SyncServer,
    peer: PeerMachine,
    frame: &[u8],
) -> Option<(Option<WindowKey>, oneiron::sync::window::UpdateVerdict)> {
    if frame.first() != Some(&protocol::TAG_WINDOW_SYNC) {
        return None;
    }
    let (key, sub_tag, update) = protocol::decode_window_sync(frame.get(1..)?).ok()?;
    if !matches!(
        sub_tag,
        window_sub_tags::UPDATE | window_sub_tags::REPLACEMENT
    ) {
        return None;
    }
    let verdict =
        oneiron::sync::window::raw_update_verdict_for(&server.reassert_manager, key, update, peer);
    Some((WindowKey::try_new(key), verdict))
}

/// Whether window `key`'s ready notice may go to this socket at all: an
/// owner-lane socket the window is pushed to, or one that follows
/// `WINDOW_INVALIDATE` and forgot the window's subscription; a residence
/// socket that promoted the window. Read from the socket's state alone.
fn ready_window_allowed(state: &ConnState, key: &WindowKey) -> bool {
    match state.window_sync_mode {
        WindowSyncMode::Residence => state.promoted_windows.contains_key(key),
        WindowSyncMode::Selector => false,
        WindowSyncMode::FullWindow | WindowSyncMode::Unbound => {
            protocol::is_owner_window_version(state.protocol_version)
                && (state.receives_window(key)
                    || (protocol::takes_window_invalidations(state.protocol_version)
                        && state.invalidates_window(key)))
        }
    }
}

/// Window `key`'s ready notice for this socket, judged now: the machine the
/// socket proved still stands, this home still stores the window, the
/// machine may read its world, and on a residence socket the promotion's
/// grant still covers it.
fn ready_window_notice(server: &SyncServer, state: &ConnState, key: &WindowKey) -> ReadyNotice {
    let peer = state.peer_machine(server.vault());
    if !matches!(peer, PeerMachine::Proven { .. }) {
        return ReadyNotice::Withheld;
    }
    match server.reassert_manager.window_stored(key) {
        Ok(true) => {}
        Ok(false) => return ReadyNotice::Withheld,
        Err(error) => {
            tracing::warn!(window = %key, %error, "ready window storage not read");
            return ReadyNotice::Retry;
        }
    }
    let worlds = match oneiron::sync::residence::withheld_from_peer(server.vault.as_ref(), peer) {
        Ok(Some(worlds)) => worlds,
        Ok(None) => return ReadyNotice::Withheld,
        Err(error) => {
            tracing::warn!(window = %key, %error, "ready window readers not read");
            return ReadyNotice::Retry;
        }
    };
    if key.world().is_some_and(|world| worlds.contains(&world)) {
        return ReadyNotice::Withheld;
    }
    let mut jti = None;
    let frame = match state.window_sync_mode {
        WindowSyncMode::Residence => {
            let Some(selector) = state.promoted_windows.get(key) else {
                return ReadyNotice::Withheld;
            };
            let Ok(auth) = require_bound_app_auth(server, state) else {
                return ReadyNotice::Withheld;
            };
            let window = match server.reassert_manager.open_window(key) {
                Ok(window) => window,
                Err(error) => {
                    tracing::warn!(window = %key, %error, "ready window not opened");
                    return ReadyNotice::Retry;
                }
            };
            match super::window_sync::authorize_promoted_window(
                server,
                auth,
                peer,
                key,
                selector,
                &window.doc,
            ) {
                Ok(()) => {}
                // A store that could not be read now denies nothing: the
                // notice is owed again on the next tick.
                Err(protocol::ProtocolError::Persistence(error)) => {
                    tracing::warn!(window = %key, %error, "ready window grant not read");
                    return ReadyNotice::Retry;
                }
                Err(_) => return ReadyNotice::Withheld,
            }
            jti = auth.jti().map(str::to_owned);
            protocol::encode_window_sync(key.as_str(), window_sub_tags::PROMOTED_INVALIDATE, &[])
        }
        _ if state.receives_window(key) => {
            let window = match server.reassert_manager.open_window(key) {
                Ok(window) => window,
                Err(error) => {
                    tracing::warn!(window = %key, %error, "ready window not opened");
                    return ReadyNotice::Retry;
                }
            };
            // A window whose whole send this machine may not take names
            // nothing of its history to it either.
            match oneiron::sync::window::export_withheld_for(
                server.vault.as_ref(),
                key,
                &window.doc,
                &VersionVector::new(),
                Withhold::Worlds(&worlds),
            ) {
                Ok(false) => {}
                Ok(true) => return ReadyNotice::Withheld,
                Err(error) => {
                    tracing::warn!(window = %key, %error, "ready window withholding not read");
                    return ReadyNotice::Retry;
                }
            }
            protocol::encode_window_sync(
                key.as_str(),
                window_sub_tags::VV_REQUEST,
                &window.doc.oplog_vv().encode(),
            )
        }
        _ => protocol::encode_window_sync(key.as_str(), window_sub_tags::WINDOW_INVALIDATE, &[]),
    };
    match frame.into_result() {
        Ok(frame) => ReadyNotice::Send(frame, jti),
        Err(error) => {
            tracing::warn!(
                window = %key,
                error = protocol::transport_err_msg(error),
                "ready window notice not encoded"
            );
            ReadyNotice::Retry
        }
    }
}
