//! One app-tier socket's loop, chosen at its upgrade and fixed for the
//! socket's life: full replication for the owner-grade caller its upgrade
//! admitted ([`replication`]), or a stale owner sign-in's booking calls and
//! nothing more ([`booking`], FIX 11712). No frame moves a socket from one
//! loop to the other.

use std::sync::Arc;

use axum::extract::ws::WebSocket;

use crate::auth::CoreAuth;
use crate::server::SyncServer;

// A stale owner sign-in's loop, which serves no sync state.
mod booking;
// The full-replication loop, as it was before the booking loop came beside it.
mod replication;

pub(super) use self::booking::BookingCaller;

/// What one app-tier socket serves, fixed at its upgrade.
pub(super) enum SocketMode {
    /// Full replication, for the owner-grade caller its upgrade admitted:
    /// that credential's revocable token id, a managed vault's attested
    /// owner, whom no token id names, and the actor its sync frames count
    /// under.
    Replication {
        session_jti: Option<String>,
        owner: Option<CoreAuth>,
        telemetry_actor: String,
    },
    /// A stale owner sign-in's socket: the five booking verbs and nothing
    /// more (FIX 11712).
    Booking(BookingCaller),
}

/// Main connection lifecycle: the loop `mode` names, over `socket` and the
/// engine's stop it lives under (OF-237), for a caller at `locality` whose
/// upgrade proved `machine` and was observed as `signing_request_transport`.
pub(super) async fn handle_connection(
    socket: (WebSocket, crate::embedded::UpgradeStop),
    server: Arc<SyncServer>,
    conn_id: u32,
    mode: SocketMode,
    locality: oneiron::claim::CallerLocality,
    machine: oneiron::authority::PeerMachine,
    signing_request_transport: Option<oneiron::memory::SigningRequestTransport>,
) {
    match mode {
        SocketMode::Replication {
            session_jti,
            owner,
            telemetry_actor,
        } => {
            replication::handle_connection(
                socket,
                server,
                conn_id,
                (session_jti, owner),
                telemetry_actor,
                locality,
                machine,
                signing_request_transport,
            )
            .await;
        }
        SocketMode::Booking(caller) => {
            booking::serve(
                socket,
                server,
                conn_id,
                caller,
                locality,
                machine,
                signing_request_transport,
            )
            .await;
        }
    }
}
