//! Authenticated selector fetches with durable defer and current-grant replay.

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
use oneiron::sync::{WindowKey, filtered_window_doc};

pub(super) async fn handle_selector_fetch(
    server: &SyncServer,
    key: &WindowKey,
    sub_tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    state: &mut ConnState,
) -> Result<(), ProtocolError> {
    state.bind_window_sync_mode(WindowSyncMode::Selector)?;
    // Owner/shared-secret upgrade is NOT a stable peer identity. The MACed,
    // live app-tier credential must name the actual granted principal.
    let auth = require_bound_app_auth(server, state)?;
    auth.require(CoreScope::Read)
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
    // authorization. Keep the independent fabricated-window DoS bound too.
    let decoded = decode_and_authorize_selector_request(server, request)?;
    if decoded.selector.member_ref != principal {
        return Err(ProtocolError::InvalidPayload("selector principal mismatch"));
    }
    state.touch_window(key.clone(), server.config.max_windows_per_connection)?;
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
        return Ok(());
    }
    let doc = server
        .get_or_create_window(key)
        .await
        .map_err(|e| ProtocolError::Persistence(format!("window load failed: {e}")))?;
    let filtered = filtered_window_doc(
        server.vault.as_ref(),
        &doc,
        key,
        selector_grant_scope(),
        &prepared.selector,
    )
    .map_err(map_selector_filter_err)?;
    let delta = filtered
        .export(ExportMode::all_updates())
        .map_err(|e| ProtocolError::LoroImport(e.to_string()))?;
    send(direct_tx, key, window_sub_tags::UPDATE, &delta)?;
    prepared
        .complete(server.vault.as_ref())
        .map_err(map_selector_filter_err)
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
