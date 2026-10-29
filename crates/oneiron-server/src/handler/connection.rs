//! Upgrade route, hello bootstrap, and the single-owner connection event loop.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message as WsMessage, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::transport::{WS_MAX_WRITE_BUFFER_SIZE, WS_WRITE_BUFFER_SIZE};

use crate::auth::{CoreAuth, RevokedTokenJtis, is_revoked_or_unreadable, require_owner_auth};
use crate::protocol::{self, ProtocolError, SyncMessage};
use crate::server::SyncServer;

// The connection loop itself, apart so each file stays under the size bar.
mod run;

/// Builds the WebSocket routes for the sync server.
pub(crate) fn ws_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route("/ws", get(ws_upgrade_handler))
        .with_state(server.clone())
        .layer(axum::middleware::from_fn_with_state(
            server.clone(),
            crate::auth::admit_http_binding,
        ))
        // FIX 811: a refused upgrade is its connection's receipt.
        .layer(axum::middleware::from_fn_with_state(
            server,
            crate::api::call_receipt::connection_receipt,
        ))
}

/// Handles WebSocket upgrade requests.
///
/// Auth: the upgrade request must present an owner-grade credential in the
/// `Authorization: Bearer` header — a logged, holder-bound top-scope slip.
/// Neither the issuer secret nor a device lease grants socket access.
/// An unauthenticated upgrade is rejected with 401 BEFORE the socket upgrade
/// (fail-closed) — without this gate any network peer could pull the full
/// root snapshot and window exports. When no secret is configured, upgrades
/// are rejected unless the explicit insecure dev escape hatch is enabled,
/// matching `auth::require_owner_auth` on the HTTP side. An upgrade naming
/// the MCP subprotocol is the one exception: it opens the MCP carrier
/// ([`super::mcp_socket`]), which serves none of that state.
///
/// The credential's revocable identity is carried into the connection rather
/// than discarded with the rest of the `CoreAuth`: the handshake proves the
/// token was live at upgrade time, and the socket outlives that instant.
///
/// On a managed vault, an upgrade its supervisor attested as the owner's own
/// (managed ingress verified that over the `GET`, its path, raw query,
/// placing headers and empty body, never the frames) is the owner himself,
/// while the vault records him as its live owner (FIX 5255). No token id
/// names him, so the socket asks the vault that again before every read,
/// release and inbound effect, and its app tier is bound to him without a
/// slip. A machine stands for the socket only where one was proved.
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    crate::auth::Locality(locality): crate::auth::Locality,
    machine: Option<axum::Extension<oneiron::authority::PeerMachine>>,
    extensions: axum::http::Extensions,
    State(server): State<Arc<SyncServer>>,
) -> Result<Response, Response> {
    // The MCP carrier serves no sync state, so it admits any holder-bound
    // slip rather than only an owner-grade one, and on a managed vault the
    // owner his supervisor attested. There each call it carries is admitted
    // under the reap freeze as one `POST /mcp` is (FIX 5128).
    if super::mcp_socket::requested(&ws) {
        return super::mcp_socket::upgrade(ws, &headers, &extensions, server);
    }
    let auth = match CoreAuth::for_attested_request(&headers, &extensions, "/ws", &server) {
        Some(Ok(auth)) if auth.is_owner_grade() => auth,
        Some(Ok(_)) => {
            return Err(crate::auth::caller_slip_too_narrow("full replication").into_response());
        }
        Some(Err(refused)) => return Err(refused.into_response()),
        None => require_owner_auth(&headers, &server.config, server.vault().as_ref())
            .map_err(|_| sync_upgrade_refused(&headers, &server))?,
    };
    // Full replication reads the whole vault, an owner act: a hosted
    // operator's root is refused before the upgrade (FIX 2222), with its
    // typed body (FIX 6032). Every refusal stays this door's 403.
    crate::api::host_action::require_host_owner_act(&server, &auth).map_err(|refused| {
        if refused.status() == StatusCode::FORBIDDEN {
            refused.into_response()
        } else {
            StatusCode::FORBIDDEN.into_response()
        }
    })?;
    let session_jti = auth.jti().map(str::to_owned);
    let owner = auth.managed_owner().is_some().then(|| auth.clone());
    // The socket's sync frames count under the actor its upgrade admitted,
    // as an HTTP request counts under its own (OF-520, FIX 1086).
    let telemetry_actor = auth.principal_ref().unwrap_or(auth.principal()).to_owned();
    // The binding door proved the machine with the upgrade's own slip proof.
    let machine = machine.map_or(oneiron::authority::PeerMachine::Unknown, |m| m.0);
    // The home answers with its own machine over that same proof, so the
    // device judges its sends for this machine (OF-534 G6/G7).
    let home_proof = home_proof_header(&headers, server.vault().as_ref());

    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new WebSocket connection");

    // `write_buffer_size` is a security setting here, not a tuning knob: it is
    // what keeps `start_send` from writing to the socket on its own. See
    // [`WS_WRITE_BUFFER_SIZE`]. Note that `max_frame_size` below does NOT pin
    // that — it bounds inbound reads only — so the outbound side is held by
    // [`GuardedTransport::fits_below_write_through`], which refuses per frame
    // in release builds.
    // FIX 811: the socket's unattributed replies name the connection its
    // upgrade arrived on.
    let connection = crate::api::call_receipt::connection_id();
    // OF-237: over an embedded engine's channel or mesh the whole socket,
    // hello included, lives under the engine's stop, which it answers itself,
    // and the stop waits for it and every call it admitted from before the
    // upgrade registers.
    let hold = crate::embedded::UpgradeHold::take(&extensions);
    let mut response = ws
        .max_frame_size(server.config.max_frame_size)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
        .on_upgrade(move |socket| {
            crate::embedded::UpgradeHold::run(hold, move |stop| {
                crate::api::call_receipt::on_connection(
                    connection,
                    run::handle_connection(
                        (socket, stop),
                        server,
                        conn_id,
                        (session_jti, owner),
                        telemetry_actor,
                        locality,
                        machine,
                    ),
                )
            })
        })
        .into_response();
    if let Some(value) = home_proof {
        response
            .headers_mut()
            .insert(oneiron::sync::home_proof::HOME_PROOF_HEADER, value);
    }
    Ok(response)
}

/// The refusal of a sync upgrade whose credential is not owner-grade. On a
/// managed vault a caller's own forwarded slip that verified, but is
/// narrower than full replication, is told so and never served as the host
/// (WILL-PLAN L14 row 01); every other refusal is the bare 401 it was.
fn sync_upgrade_refused(headers: &HeaderMap, server: &SyncServer) -> Response {
    if server.managed_issuer.is_some()
        && CoreAuth::from_headers(headers, &server.config, server.vault().as_ref()).is_ok()
    {
        return crate::auth::caller_slip_too_narrow("full replication").into_response();
    }
    StatusCode::UNAUTHORIZED.into_response()
}

/// This install's machine proof answering the upgrade whose slip proof
/// `headers` carry, or `None`: no slip proof, or no machine of this vault
/// here yet. A proof that cannot be made leaves the device judging this home
/// as an unknown destination, as before.
fn home_proof_header(
    headers: &HeaderMap,
    vault: &oneiron::Vault,
) -> Option<axum::http::HeaderValue> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .trim();
    let proof = crate::auth::BindingProof::from_headers(headers).ok()?;
    let value = vault
        .home_connection_proof(token, proof.timestamp, &proof.nonce)
        .ok()??;
    axum::http::HeaderValue::from_str(&value).ok()
}

/// Whether this socket's credential has since been revoked.
///
/// The upgrade handshake proves the credential was live THEN; the socket
/// lives arbitrarily long after it. Revocation is an explicit operator act
/// against one named token, so it must reach sessions that were ALREADY open
/// — otherwise `token revoke` only closes the front door while the peer
/// already inside keeps full vault service. Fail-closed on an unreadable
/// registry, matching the handshake: "we could not check" is not "still live".
///
/// `None` is possible only in explicit unauthenticated development mode.
pub(super) fn session_credential_revoked(
    revoked: &dyn RevokedTokenJtis,
    session_jti: Option<&str>,
) -> bool {
    session_jti.is_some_and(|jti| is_revoked_or_unreadable(jti, revoked))
}

/// Whether this socket's caller no longer stands: its credential revoked
/// ([`session_credential_revoked`]), or, for a managed vault's attested
/// owner, whom no token id names, the vault no longer recording him as its
/// live owner (FIX 5255).
fn session_gone(
    vault: &oneiron::Vault,
    session_jti: Option<&str>,
    owner: Option<&CoreAuth>,
) -> bool {
    session_credential_revoked(vault, session_jti)
        || owner.is_some_and(|owner| !owner.credential_is_live(vault))
}

/// What woke the connection loop.
///
/// The select produces this and nothing borrowed, so every future it raced —
/// including the read — is dropped before the handler touches the transport
/// again. That is what lets one task own both halves.
enum ConnEvent {
    Inbound(Option<Result<WsMessage, axum::Error>>),
    Broadcast(Result<Option<Vec<u8>>, crate::broadcast::BroadcastError>),
    Direct(Option<Vec<u8>>),
    AppDelivery,
    /// A verb RPC run off the loop ended; its answer is already queued.
    Answered(Result<Result<(), ProtocolError>, tokio::task::JoinError>),
}

/// How many verb RPCs one socket runs at once, off its loop. The loop reads
/// no further frame from the socket while this many are in flight.
const MAX_VERB_CALLS_IN_FLIGHT: usize = 8;

/// Whether this message class moves server state, and therefore requires a
/// live credential.
///
/// Everything that reads the vault out (root VV deltas, window VV exchange,
/// selector fetches), writes into it (window updates), registers device
/// identity (lease), or publishes to live peers (ephemeral presence/cursor
/// state) is privileged. Exactly one class is not:
///
/// - `RootUpdate` — the root doc is server-authoritative; the handler
///   discards client updates without touching any state, so a revoked peer
///   sending one already achieves nothing. Exempting it keeps an idle
///   keepalive-shaped connection off the registry.
///
/// `Ephemeral` is deliberately NOT exempt, though it carries no vault
/// content. The read-side argument for exempting it — the outbound guard
/// stops the revoked peer from receiving the fan-out — says nothing about
/// the write side: the handler applies the payload to the hub store and
/// broadcasts it, so a revoked bearer would keep PUBLISHING presence and
/// cursor state to every live peer after losing all read access. Revocation
/// means no further service in either direction.
///
/// The exemption is the reason this is an explicit allow-list rather than a
/// blanket check: a new privileged message variant must be classified here,
/// and the compiler forces that decision by exhaustive match.
fn privileged_sync_message(msg: &SyncMessage) -> bool {
    match msg {
        SyncMessage::RootUpdate(_) => false,
        SyncMessage::Ephemeral(_)
        | SyncMessage::LfsChunks(_)
        | SyncMessage::RootVersionVector(_)
        | SyncMessage::LeaseRequest { .. }
        | SyncMessage::Doc { .. }
        | SyncMessage::Batch(_)
        | SyncMessage::WindowSync { .. }
        | SyncMessage::Rpc(_)
        | SyncMessage::Sub(_) => true,
    }
}

fn window_broadcast_allowed(
    protocol_version: u8,
    state: &super::conn_state::ConnState,
    frame: &[u8],
) -> bool {
    let key = frame
        .get(1..)
        .and_then(|payload| oneiron::sync::transport::decode_window_sync(payload).ok())
        .and_then(|(key, _, _)| oneiron::sync::WindowKey::try_new(key));
    match protocol_version {
        version if protocol::is_owner_window_version(version) => {
            key.is_some_and(|key| state.receives_window(&key))
        }
        _ => false,
    }
}

/// What a broadcast window frame becomes on this socket: itself where the
/// socket is pushed the window, a `WINDOW_INVALIDATE` where it forgot the
/// window's subscription past `max_windows_per_connection`, or nothing. A
/// frame this server withholds as device-only is neither.
fn window_delivery(
    server: &SyncServer,
    protocol_version: u8,
    state: &super::conn_state::ConnState,
    frame: Vec<u8>,
) -> Option<Vec<u8>> {
    if window_broadcast_allowed(protocol_version, state, &frame) {
        let peer = state.peer_machine(server.vault());
        return (!window_update_withheld(server, peer, &frame)).then_some(frame);
    }
    if !protocol::takes_window_invalidations(protocol_version) {
        return None;
    }
    let (key, _, _) = frame
        .get(1..)
        .and_then(|payload| protocol::decode_window_sync(payload).ok())?;
    let window = oneiron::sync::WindowKey::try_new(key)?;
    if !state.invalidates_window(&window)
        || window_update_withheld(server, state.peer_machine(server.vault()), &frame)
    {
        return None;
    }
    protocol::encode_window_sync(key, protocol::window_sub_tags::WINDOW_INVALIDATE, &[])
        .into_result()
        .ok()
}

/// Whether `frame` is a window UPDATE or REPLACEMENT this server now
/// withholds from the machine `peer` proved on this socket, by that
/// machine's own world read settings (OF-534 G6). Read at the socket, since
/// the flag may turn after the frame was queued for this connection.
fn window_update_withheld(
    server: &SyncServer,
    peer: oneiron::authority::PeerMachine,
    frame: &[u8],
) -> bool {
    if frame.first() != Some(&protocol::TAG_WINDOW_SYNC) {
        return false;
    }
    frame
        .get(1..)
        .and_then(|payload| protocol::decode_window_sync(payload).ok())
        .is_some_and(|(key, sub_tag, update)| {
            matches!(
                sub_tag,
                protocol::window_sub_tags::UPDATE | protocol::window_sub_tags::REPLACEMENT
            ) && oneiron::sync::window::raw_update_verdict_for(
                &server.reassert_manager,
                key,
                update,
                peer,
            ) != oneiron::sync::window::UpdateVerdict::Portable
        })
}

pub(super) fn should_forward_broadcast(protocol_version: u8, data: &[u8]) -> bool {
    if matches!(
        data.first(),
        Some(&oneiron::sync::transport::TAG_DOCUMENT) | Some(&oneiron::sync::transport::TAG_BATCH)
    ) {
        return false; // Only document_delivery may construct a recipient's export.
    }
    (protocol_version == protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION
        || protocol::is_owner_window_version(protocol_version))
        || data.first().copied() != Some(protocol::TAG_WINDOW_SYNC)
}
