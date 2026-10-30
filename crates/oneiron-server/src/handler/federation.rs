//! Authenticated selector fetches with durable defer and current-grant replay.

use std::ops::ControlFlow;

use super::app_tier::require_bound_app_auth;
use super::conn_state::{ConnState, WindowSyncMode};
use super::window_sync::{
    decode_and_authorize_selector_request, map_selector_filter_err, selector_grant_scope,
};
use crate::auth::CoreScope;
use crate::protocol::{self, ProtocolError, window_sub_tags};
use crate::server::SyncServer;
use loro::ExportMode;
use oneiron::sync::federation_burst::{
    FederationBurstDecision, prepare_selector_fetch, replay_selector_fetch,
};
use oneiron::sync::{WindowKey, filtered_window_doc_for_peer};

/// `Break` when `session_gone` finds the socket's caller gone once the window
/// has loaded (FIX 6313): nothing is sent or completed for it, and the
/// connection ends as the gate before dispatch ends it.
pub(super) async fn handle_selector_fetch(
    server: &SyncServer,
    key: &WindowKey,
    sub_tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    state: &mut ConnState,
    session_gone: &(dyn Fn() -> bool + Sync),
) -> Result<ControlFlow<()>, ProtocolError> {
    state.bind_window_sync_mode(WindowSyncMode::Selector)?;
    // Owner/shared-secret upgrade is NOT a stable peer identity. The MACed,
    // live app-tier credential must name the actual granted principal.
    let auth = require_bound_app_auth(server, state)?;
    // The window is the selector grant's, not the credential's lane, so a
    // credential limited to facets is refused (owner ruling FACET-READ).
    auth.require(CoreScope::Read)
        .and_then(|()| auth.require_unnarrowed_facets())
        .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    let principal = oneiron::EntityId::from_hex(
        auth.require_registered_principal()
            .map_err(|_| ProtocolError::RpcNoPrincipal)?,
    )
    .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    let (retry, request) = if sub_tag == window_sub_tags::SELECTOR_RETRY {
        let id: [u8; 32] = payload
            .get(..32)
            .ok_or(ProtocolError::InvalidPayload("short selector retry"))?
            .try_into()
            .map_err(|_| ProtocolError::InvalidPayload("short selector retry"))?;
        (Some(id), &payload[32..])
    } else {
        (None, payload)
    };
    if request.len() > server.config.max_update_payload {
        return Err(ProtocolError::FrameTooLarge {
            size: request.len(),
            max: server.config.max_update_payload,
        });
    }
    // No queue row, observation, or doc exists before both decoding and
    // authorization.
    let decoded = decode_and_authorize_selector_request(server, request)?;
    if decoded.selector.member_ref != principal {
        return Err(ProtocolError::InvalidPayload("selector principal mismatch"));
    }
    let prepared = match retry {
        Some(id) => replay_selector_fetch(
            server.vault.as_ref(),
            principal,
            selector_grant_scope(),
            key,
            &id,
            request,
        ),
        None => prepare_selector_fetch(
            server.vault.as_ref(),
            principal,
            selector_grant_scope(),
            key,
            request,
        ),
    }
    .map_err(map_selector_filter_err)?;
    if let FederationBurstDecision::Defer { request_id, .. } = prepared.decision {
        // The response carries the original request so restart/reconnect does
        // not depend on connection-local correlation state. It is NOT a row
        // rematerialization marker and cannot be redeemed by another principal.
        let mut retry = request_id.to_vec();
        retry.extend_from_slice(request);
        send(direct_tx, key, window_sub_tags::SELECTOR_DEFERRED, &retry)?;
        return Ok(ControlFlow::Continue(()));
    }
    let window = server
        .serve_window(key)
        .await
        .map_err(|e| ProtocolError::Persistence(format!("window load failed: {e}")))?;
    // FIX 6313: the load may wait, and the session the gate before dispatch
    // found live may have gone meanwhile. The work prepared above stays as it
    // is; nothing of it is exported or completed for a gone session.
    if session_gone() {
        tracing::warn!("credential revoked — refusing sync message and closing");
        return Ok(ControlFlow::Break(()));
    }
    let doc = window.doc.clone();
    let filtered = filtered_window_doc_for_peer(
        server.vault.as_ref(),
        &doc,
        key,
        selector_grant_scope(),
        &prepared.selector,
        state.peer_machine(server.vault()),
    )
    .map_err(map_selector_filter_err)?;
    let delta = filtered
        .export(ExportMode::all_updates())
        .map_err(|e| ProtocolError::ExportFailed(e.to_string()))?;
    send(direct_tx, key, window_sub_tags::UPDATE, &delta)?;
    // The rows it admitted are the ones whose by-reference bodies this socket
    // is served, while its selector stands (FIX 12118).
    state
        .admitted_windows
        .insert(key.clone(), (prepared.selector.clone(), filtered));
    prepared
        .complete(server.vault.as_ref())
        .map_err(map_selector_filter_err)?;
    Ok(ControlFlow::Continue(()))
}

fn send(
    tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    key: &WindowKey,
    tag: u8,
    payload: &[u8],
) -> Result<(), ProtocolError> {
    let frame = protocol::encode_window_sync(key.as_str(), tag, payload)
        .into_result()
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
    tx.send(frame)
        .map_err(|_| ProtocolError::Persistence("selector response channel closed".into()))
}

/// Selector bytes are a standalone closed subgraph. Recheck only that
/// subgraph against the destination now, not an unrelated canonical row.
pub(super) fn selector_update_withheld(
    server: &SyncServer,
    frame: &[u8],
    peer: oneiron::authority::PeerMachine,
) -> bool {
    if frame.first() != Some(&protocol::TAG_WINDOW_SYNC) {
        return false;
    }
    let Some((key, sub_tag, update)) = frame
        .get(1..)
        .and_then(|payload| protocol::decode_window_sync(payload).ok())
    else {
        return true;
    };
    matches!(
        sub_tag,
        protocol::window_sub_tags::UPDATE | protocol::window_sub_tags::REPLACEMENT
    ) && oneiron::sync::window::selector_update_verdict_for_peer(server.vault(), key, update, peer)
        != oneiron::sync::window::UpdateVerdict::Portable
}
