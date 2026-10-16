//! A socket that fell behind the shared fan-out is told again what it may
//! have missed; it is never closed for lag (rule 5).
//!
//! The fan-out is lossy: past its capacity a slow socket's receiver skips
//! frames. Each subscription kind the socket holds then gets one content-free
//! notice through the socket's direct queue, where every last door still
//! judges it:
//! - a window an owner-lane socket is pushed: on v13 `WINDOW_INVALIDATE`,
//!   which the peer answers with its `VV_REQUEST`; on v11 the home's own
//!   `VV_REQUEST`, which the peer answers with its `UPDATE` and
//!   `VV_RESPONSE`, and the home answers that with what the peer lacks;
//! - a window a v13 socket forgot past its row: `WINDOW_INVALIDATE`, as any
//!   change of it would have sent;
//! - a promoted residence window: `PROMOTED_INVALIDATE`, under the same
//!   authorization as a live change's;
//! - a selector document or an owner NOTE: an empty `UPDATE` notice, which
//!   the direct door turns into this socket's export from its last
//!   acknowledged version;
//! - the root: its whole export, which a peer merges.
//!
//! App-tier subscriptions replay on their own (`replay_after_lag`). The
//! socket's select drains its direct queue before it takes another
//! broadcast, so one lag's notices are all sent before the next lag can
//! queue more: no more than one per window or document ever waits.

use loro::VersionVector;
use oneiron::sync::schema::read_window_list;
use oneiron::sync::transport::{self, document_sub_tags};

use super::app_tier::require_bound_app_auth;
use super::conn_state::{ConnState, WindowSyncMode};
use crate::protocol::{self, window_sub_tags};
use crate::server::SyncServer;

/// The notices that resync every subscription `state` holds after a lag.
pub(super) fn lag_resync_frames(server: &SyncServer, state: &ConnState) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    if let Ok(root) = server.export_root_updates(&VersionVector::new()) {
        frames.push(protocol::encode_root_update(&root));
    }
    if protocol::is_owner_window_version(state.protocol_version) {
        let notices = protocol::takes_window_invalidations(state.protocol_version);
        for key in read_window_list(&server.root_doc) {
            let pushed = state.receives_window(&key);
            let frame = if notices && (pushed || state.invalidates_window(&key)) {
                protocol::encode_window_sync(key.as_str(), window_sub_tags::WINDOW_INVALIDATE, &[])
            } else if pushed {
                let Ok(window) = server.reassert_manager.open_window(&key) else {
                    continue;
                };
                protocol::encode_window_sync(
                    key.as_str(),
                    window_sub_tags::VV_REQUEST,
                    &window.doc.oplog_vv().encode(),
                )
            } else {
                continue;
            };
            frames.extend(frame.into_result().ok());
        }
    }
    if state.window_sync_mode == WindowSyncMode::Residence
        && let Ok(auth) = require_bound_app_auth(server, state)
    {
        for (key, selector) in &state.promoted_windows {
            let authorized = server
                .reassert_manager
                .open_window(key)
                .is_ok_and(|window| {
                    super::window_sync::authorize_promoted_window(
                        server,
                        auth,
                        state.peer_machine(server.vault()),
                        key,
                        selector,
                        &window.doc,
                    )
                    .is_ok()
                });
            if authorized {
                frames.extend(
                    protocol::encode_window_sync(
                        key.as_str(),
                        window_sub_tags::PROMOTED_INVALIDATE,
                        &[],
                    )
                    .into_result()
                    .ok(),
                );
            }
        }
    }
    for entity in state.documents.keys().chain(state.owner_documents.keys()) {
        frames.extend(
            transport::encode_document(*entity, document_sub_tags::UPDATE, &[])
                .into_result()
                .ok(),
        );
    }
    frames
}
