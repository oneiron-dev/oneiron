//! A managed vault member's held MCP socket (FIX 1302 stage 2).
//!
//! A member with no slip of his own, whose supervisor signed the socket's
//! upgrade for him (`ManagedPersonAction`, verified at managed ingress over
//! the `GET`, its path, raw query, placing headers and empty body), holds the
//! MCP carrier, which serves no root snapshot, presence or sync frame. Its
//! serve gate carries the MCP handshake and a `tools/call` of a member door
//! alone (`api::person_socket_admits`). Each call runs through `/mcp` as his
//! own signed call does there, named by the socket it came on
//! (`ManagedPersonSession`), never by the signature of the upgrade, and the
//! door's person check and the engine's roster, role and Grant checks judge
//! him again. His socket closes on the vault's deletion as every socket
//! does.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::extract::ws::WebSocketUpgrade;
use axum::http::{Extensions, HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::{
    CARRIED_FORWARDING_HEADERS, CARRIED_HEADERS, Caller, Credential, MCP_CREDENTIAL_HEADER,
    MCP_SUBPROTOCOL, OWNER_PLACING_HEADERS, WS_MAX_WRITE_BUFFER_SIZE, WS_WRITE_BUFFER_SIZE, serve,
};
use crate::managed::{ManagedCarrierContext, ManagedPersonHolder, ManagedPersonSession};
use crate::server::SyncServer;

/// The member a supervisor signed this upgrade for, with no credential of
/// anyone's and no owner attestation beside him, on a managed vault. `None`
/// for any other upgrade, which keeps the path it had.
pub(in crate::handler) fn signed_person_holder(
    headers: &HeaderMap,
    extensions: &Extensions,
    server: &SyncServer,
) -> Option<oneiron::EntityId> {
    if server.managed_issuer.is_none()
        || crate::auth::carries_caller_slip(headers)
        || headers.contains_key(MCP_CREDENTIAL_HEADER)
        || headers.contains_key(header::AUTHORIZATION)
        || crate::auth::attested_owner(extensions, server).is_some()
    {
        return None;
    }
    extensions
        .get::<ManagedPersonHolder>()
        .map(|holder| holder.0)
}

/// Opens `holder`'s held MCP socket: each call it carries reaches the member
/// doors alone, admitted under the reap freeze as the `POST /mcp` it
/// becomes. An upgrade managed ingress handed no admission is refused,
/// never served bare.
pub(in crate::handler) fn person_upgrade(
    ws: WebSocketUpgrade,
    headers: &HeaderMap,
    extensions: &Extensions,
    server: Arc<SyncServer>,
    holder: oneiron::EntityId,
) -> Result<Response, Response> {
    let managed = extensions
        .get::<ManagedCarrierContext>()
        .cloned()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    let mut carried = HeaderMap::new();
    for name in CARRIED_HEADERS {
        if let Some(value) = headers.get(&name) {
            carried.insert(name, value.clone());
        }
    }
    for name in CARRIED_FORWARDING_HEADERS
        .into_iter()
        .chain(OWNER_PLACING_HEADERS)
    {
        if let Some(value) = headers.get(name) {
            carried.insert(name, value.clone());
        }
    }
    let caller = Caller {
        credential: Credential::Person(ManagedPersonSession(holder)),
        headers: carried,
        tcp_peer: extensions.get::<ConnectInfo<SocketAddr>>().copied(),
        local_peer: extensions
            .get::<ConnectInfo<crate::managed::UnixPeer>>()
            .cloned(),
        managed: Some(managed),
    };
    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new MCP member socket");
    // FIX 811: the socket's unattributed replies name the connection its
    // upgrade arrived on.
    let connection = crate::api::call_receipt::connection_id();
    // OF-237: the carrier lives under an embedded engine's stop.
    let hold = crate::embedded::UpgradeHold::take(extensions);
    Ok(ws
        .protocols([MCP_SUBPROTOCOL])
        .max_frame_size(server.config.max_frame_size)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
        .on_upgrade(move |socket| {
            crate::embedded::UpgradeHold::run(hold, move |stop| {
                crate::api::call_receipt::on_connection(
                    connection,
                    serve(socket, stop, server, conn_id, (None, None), caller),
                )
            })
        })
        .into_response())
}
