//! WindowSync sub-tag dispatcher with selector and VV paths.

use loro::{ExportMode, VersionVector};

use oneiron::sync::{
    AllowBlock, SelectorVvRequest, WindowKey, authorize_sync_selector, decode_selector_vv_request,
    filtered_window_doc,
};

use super::conn_state::{ConnState, WindowSyncMode};
use crate::protocol::{self, ProtocolError, window_sub_tags};
use crate::server::SyncServer;

/// Numeric grant-scope ABI for this single-vault selector server path.
/// Distinct from the lease ABI's internal vault id: federation grants reject
/// zero as a shared-vault scope, and FED-001 fixtures pin the nonzero scope.
const SERVER_SELECTOR_VAULT_ID: u64 = 7;

/// Handles a WindowSync message: routes to the correct window LoroDoc.
pub(super) async fn handle_window_sync(
    server: &SyncServer,
    conn_id: u32,
    window_key: &str,
    sub_tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    conn_state: &mut ConnState,
) -> Result<(), ProtocolError> {
    // Window-key chokepoint. `decode_window_sync` already validated the key
    // at the parse boundary; re-validate here so this write path stays
    // fail-closed even if a future caller bypasses the wire decoder.
    let key = WindowKey::try_new(window_key)
        .ok_or(ProtocolError::InvalidPayload("invalid window key"))?;

    // Enforce max_update_payload BEFORE the window doc is fetched/created:
    // an oversized update must not mutate any server state.
    if matches!(
        sub_tag,
        window_sub_tags::UPDATE | window_sub_tags::SELECTOR_VV_REQUEST
    ) && payload.len() > server.config.max_update_payload
    {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_update_payload,
        });
    }

    match sub_tag {
        window_sub_tags::SELECTOR_VV_REQUEST => {
            conn_state.bind_window_sync_mode(WindowSyncMode::Selector)?;
            match conn_state.allow_federation_window(&key) {
                AllowBlock::Allow => {}
                AllowBlock::Pause(reason) => {
                    let state = conn_state.federation_quota_snapshot();
                    tracing::warn!(
                        conn_id,
                        window_key,
                        ?reason,
                        ?state,
                        "federation selector connection paused"
                    );
                    return Ok(());
                }
                AllowBlock::Block(reason) => {
                    tracing::warn!(
                        conn_id,
                        window_key,
                        ?reason,
                        "federation selector connection blocked"
                    );
                    return Err(ProtocolError::InvalidPayload(
                        "federation selector quota blocked",
                    ));
                }
            }
        }
        window_sub_tags::VV_REQUEST | window_sub_tags::VV_RESPONSE | window_sub_tags::UPDATE => {
            conn_state.bind_window_sync_mode(WindowSyncMode::FullWindow)?;
        }
        _ => {}
    }

    let selector_request = if sub_tag == window_sub_tags::SELECTOR_VV_REQUEST {
        Some(decode_and_authorize_selector_request(server, payload)?)
    } else {
        None
    };

    // Count distinct, valid window keys per connection before any load/create.
    // The default cap is generous so legitimate historical-window tombstone
    // sync can touch all real windows; it only stops fabricated-key floods.
    let key = conn_state.touch_window(key, server.config.max_windows_per_connection)?;

    // Loads persisted window state (d:w: + pending u:w:) on first touch.
    // Corrupt persisted state closes the connection rather than serving a
    // fresh empty window (fail-closed — see SyncServer::get_or_create_window).
    let doc = server
        .get_or_create_window(&key)
        .await
        .map_err(|e| ProtocolError::Persistence(format!("window load failed: {e}")))?;

    match sub_tag {
        window_sub_tags::VV_REQUEST => {
            // Client sent its binary VV (SyncStep1) — export ONLY the delta it
            // is missing (ExportMode::updates via the single delta-export entry
            // point). Malformed VV → typed error, fail-closed: never fall back
            // to a full export.
            let delta = oneiron::sync::window::export_window_updates_since(
                server.vault.as_ref(),
                &key,
                &doc,
                payload,
            )
            .map_err(map_delta_export_err)?;
            let response =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            // Send directly to the requesting client's WebSocket sink, NOT via
            // broadcast. Broadcasting with the requester's conn_id would cause
            // echo suppression to drop the response for the requester.
            let _ = direct_tx.send(response);
            // Reverse SyncStep1: send our VV so the client pushes its local
            // diff back — this is what makes the exchange bidirectional.
            let vv_response = protocol::encode_window_sync(
                window_key,
                window_sub_tags::VV_RESPONSE,
                &doc.oplog_vv().encode(),
            )
            .into_result()
            .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = direct_tx.send(vv_response);
        }
        window_sub_tags::SELECTOR_VV_REQUEST => {
            // Grant-backed closed-subgraph fetch. The full-window VV path
            // above stays byte-for-byte compatible; selected sync exports
            // from a synthetic doc so unauthorized entries are never present
            // in the outbound Loro update bytes.
            let request = selector_request.ok_or(ProtocolError::InvalidPayload(
                "missing sync selector request",
            ))?;
            let filtered = filtered_window_doc(
                server.vault.as_ref(),
                &doc,
                &key,
                selector_grant_scope(),
                &request.selector,
            )
            .map_err(map_selector_filter_err)?;
            let delta = filtered
                .export(ExportMode::all_updates())
                .map_err(|e| ProtocolError::LoroImport(e.to_string()))?;
            let response =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = direct_tx.send(response);
        }
        window_sub_tags::UPDATE => {
            // Client sending Loro update bytes — import with origin for echo suppression
            let origin = format!("conn:{conn_id}");
            doc.import_with(payload, &origin)
                .map_err(|e| ProtocolError::LoroImport(format!("{e}")))?;
            // Durability BEFORE fan-out (ARCH-0023b Observer A duty: "MUST
            // persist synchronously"). `subscribe_local_update` does not fire
            // for imports, so the imported update bytes are appended to
            // sync_state (u:w:*) explicitly. A persistence failure closes the
            // connection without broadcasting: the server must never relay an
            // update — tombstones included — that it cannot replay after a
            // restart.
            let persist_result = server.persist_imported_update(&key, payload);
            if let Err(e) = persist_result {
                // The cached doc already imported this update (import runs
                // before the durable append), so it now holds state a restart
                // would lose. Left cached, a later VV_REQUEST would serve the
                // unpersisted update, the origin client would VV-confirm and
                // clear its local queue, and the next server restart would
                // drop the update — tombstones included — fleet-wide. Evict
                // the window so the next access reloads from durable
                // d:w:/u:w: state. Known residual: connections already
                // holding a reference-clone of the evicted doc can still
                // export it until their next fetch (generation/poison flag =
                // follow-up).
                server.evict_window(&key).await;
                return Err(ProtocolError::Persistence(format!(
                    "update persist failed: {e}"
                )));
            }

            let broadcast_msg =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, payload)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, broadcast_msg);
        }
        window_sub_tags::VV_RESPONSE => {
            // Client's VV answering our VV_REQUEST — export and send only our
            // local diff. Same fail-closed VV decoding as VV_REQUEST.
            let delta = oneiron::sync::window::export_window_updates_since(
                server.vault.as_ref(),
                &key,
                &doc,
                payload,
            )
            .map_err(map_delta_export_err)?;
            let response =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = direct_tx.send(response);
        }
        _ => {
            tracing::warn!(window_key, sub_tag, "unknown WindowSync sub-tag");
        }
    }

    Ok(())
}

fn decode_and_authorize_selector_request(
    server: &SyncServer,
    payload: &[u8],
) -> Result<SelectorVvRequest, ProtocolError> {
    let request = decode_selector_vv_request(payload)
        .map_err(|_| ProtocolError::InvalidPayload("invalid sync selector request"))?;
    let remote_vv = VersionVector::decode(&request.remote_vv)
        .map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
    if !remote_vv.is_empty() {
        return Err(ProtocolError::InvalidPayload(
            "selector sync requires empty version vector resync",
        ));
    }
    authorize_sync_selector(
        server.vault.as_ref(),
        selector_grant_scope(),
        &request.selector,
    )
    .map_err(map_selector_filter_err)?;
    Ok(request)
}

/// Maps a delta-export error onto the protocol taxonomy.
///
/// Malformed inbound VV bytes (`CrdtDecodeError`) get the dedicated
/// fail-closed `VvDecode` variant (the connection loop closes on it);
/// anything else is an export-side failure.
fn map_delta_export_err(e: oneiron::Error) -> ProtocolError {
    if matches!(
        e,
        oneiron::Error::Sync(oneiron::error::SyncError::CrdtDecodeError { .. })
    ) {
        ProtocolError::VvDecode(e.to_string())
    } else {
        ProtocolError::LoroImport(e.to_string())
    }
}

fn map_selector_filter_err(e: oneiron::Error) -> ProtocolError {
    if matches!(
        e,
        oneiron::Error::Sync(oneiron::error::SyncError::SyncProtocolError { .. })
            | oneiron::Error::InvalidFederationGrantBody(_)
    ) {
        ProtocolError::InvalidPayload("sync selector rejected")
    } else {
        ProtocolError::Persistence(format!("selector filter failed: {e}"))
    }
}

pub(super) fn selector_grant_scope() -> oneiron::FederationGrantScope {
    oneiron::FederationGrantScope::vault(SERVER_SELECTOR_VAULT_ID)
}
