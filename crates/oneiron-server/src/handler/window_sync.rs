//! WindowSync sub-tag dispatcher with selector and VV paths.

use loro::VersionVector;

use oneiron::claim::ScopedReadActorKey;
use oneiron::sync::residence::{admit_promoted_window_update, promotion_covers_full_window};
use oneiron::sync::schema::read_window_list;
use oneiron::sync::{
    SelectorVvRequest, SyncSelector, WindowKey, authorize_sync_selector,
    decode_selector_vv_request, decode_sync_selector,
};

use super::app_tier::require_bound_app_auth;
use super::conn_state::{ConnState, WindowSyncMode};
use crate::auth::CoreAuth;
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
        window_sub_tags::UPDATE
            | window_sub_tags::RESIDENCE_UPDATE
            | window_sub_tags::SELECTOR_VV_REQUEST
    ) && payload.len() > server.config.max_update_payload
    {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_update_payload,
        });
    }

    if sub_tag == window_sub_tags::PROMOTION_REQUEST {
        if conn_state.protocol_version != protocol::RESIDENCE_PROTOCOL_VERSION
            || payload.len() > 4096
            || !read_window_list(&server.root_doc).contains(&key)
        {
            return Err(ProtocolError::InvalidPayload(
                "invalid window promotion request",
            ));
        }
        conn_state.bind_window_sync_mode(WindowSyncMode::Residence)?;
        let selector = decode_sync_selector(payload)
            .map_err(|_| ProtocolError::InvalidPayload("invalid promotion selector"))?;
        let doc = server
            .get_or_create_window(&key)
            .await
            .map_err(|e| ProtocolError::Persistence(e.to_string()))?;
        authorize_promoted_window(
            server,
            require_bound_app_auth(server, conn_state)?,
            &key,
            &selector,
            &doc,
        )?;
        conn_state.touch_window(key.clone(), server.config.max_windows_per_connection)?;
        conn_state.promoted_windows.insert(key, selector);
        let granted =
            protocol::encode_window_sync(window_key, window_sub_tags::PROMOTION_GRANTED, &[])
                .into_result()
                .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
        direct_tx
            .send(granted)
            .map_err(|_| ProtocolError::Persistence("promotion reply channel closed".into()))?;
        return Ok(());
    }
    if matches!(
        sub_tag,
        window_sub_tags::SELECTOR_VV_REQUEST | window_sub_tags::SELECTOR_RETRY
    ) {
        return super::federation::handle_selector_fetch(
            server, &key, sub_tag, payload, direct_tx, conn_state,
        )
        .await;
    }
    if sub_tag == window_sub_tags::RESIDENCE_UPDATE {
        conn_state.bind_window_sync_mode(WindowSyncMode::Residence)?;
    } else if matches!(
        sub_tag,
        window_sub_tags::VV_REQUEST | window_sub_tags::VV_RESPONSE | window_sub_tags::UPDATE
    ) {
        if conn_state.protocol_version == protocol::RESIDENCE_PROTOCOL_VERSION {
            if !conn_state.promoted_windows.contains_key(&key) {
                return Err(ProtocolError::InvalidPayload(
                    "full-window exchange requires grant-checked promotion",
                ));
            }
            conn_state.bind_window_sync_mode(WindowSyncMode::Residence)?;
        } else {
            conn_state.bind_window_sync_mode(WindowSyncMode::FullWindow)?;
        }
    }

    if matches!(
        sub_tag,
        window_sub_tags::RESIDENCE_ACK
            | window_sub_tags::PROMOTION_GRANTED
            | window_sub_tags::PROMOTED_INVALIDATE
    ) {
        return Err(ProtocolError::InvalidPayload(
            "client cannot send server-only residence control",
        ));
    }

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
    if conn_state.protocol_version == protocol::RESIDENCE_PROTOCOL_VERSION
        && matches!(
            sub_tag,
            window_sub_tags::VV_REQUEST | window_sub_tags::VV_RESPONSE | window_sub_tags::UPDATE
        )
    {
        let selector = conn_state
            .promoted_windows
            .get(&key)
            .ok_or(ProtocolError::InvalidPayload("window not promoted"))?;
        authorize_promoted_window(
            server,
            require_bound_app_auth(server, conn_state)?,
            &key,
            selector,
            &doc,
        )?;
    }

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
            // Subscribe only after a valid VV and a complete direct catch-up.
            conn_state.subscribe_window(&key);
        }
        window_sub_tags::UPDATE | window_sub_tags::RESIDENCE_UPDATE => {
            let (residence_seq, update) = if sub_tag == window_sub_tags::RESIDENCE_UPDATE {
                let (seq, update) = payload
                    .split_at_checked(8)
                    .ok_or(ProtocolError::InvalidPayload("short residence update"))?;
                let seq = u64::from_be_bytes(seq.try_into().expect("length checked"));
                if seq == 0 || update.is_empty() {
                    return Err(ProtocolError::InvalidPayload("invalid residence update"));
                }
                (Some(seq), update)
            } else {
                (None, payload)
            };
            // Admission runs on an isolated document before Observer B or
            // persistence can see the input. Rejected diagnostics must never
            // be relayed as raw history, even if a later export would scrub.
            oneiron::sync::window::validate_window_update_residence_with_vault(
                server.vault.as_ref(),
                &doc,
                update,
                &key,
            )
            .map_err(map_delta_export_err)?;
            if conn_state.protocol_version == protocol::RESIDENCE_PROTOCOL_VERSION {
                let selector = conn_state
                    .promoted_windows
                    .get(&key)
                    .ok_or(ProtocolError::InvalidPayload("window not promoted"))?;
                let auth = require_bound_app_auth(server, conn_state)?;
                auth.require(crate::auth::CoreScope::Write)
                    .map_err(|_| ProtocolError::RpcNoPrincipal)?;
                let proof = auth.verified_slip().ok_or(ProtocolError::RpcNoPrincipal)?;
                admit_promoted_window_update(
                    &server.vault,
                    &doc,
                    selector_grant_scope(),
                    selector,
                    proof,
                    update,
                )
                .map_err(map_selector_filter_err)?;
            }
            // Client sending Loro update bytes — import with origin for echo suppression
            let origin = format!("conn:{conn_id}");
            doc.import_with(update, &origin)
                .map_err(|e| ProtocolError::LoroImport(format!("{e}")))?;
            // Durability BEFORE fan-out (ARCH-0023b Observer A duty: "MUST
            // persist synchronously"). `subscribe_local_update` does not fire
            // for imports, so the imported update bytes are appended to
            // sync_state (u:w:*) explicitly. A persistence failure closes the
            // connection without broadcasting: the server must never relay an
            // update — tombstones included — that it cannot replay after a
            // restart.
            let persist_result = server.persist_imported_update(&key, update);
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
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, update)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, broadcast_msg);
            if let Some(seq) = residence_seq {
                let mut ack = seq.to_be_bytes().to_vec();
                ack.extend_from_slice(blake3::hash(update).as_bytes());
                let frame =
                    protocol::encode_window_sync(window_key, window_sub_tags::RESIDENCE_ACK, &ack)
                        .into_result()
                        .map_err(|e| {
                            ProtocolError::InvalidPayload(protocol::transport_err_msg(e))
                        })?;
                direct_tx.send(frame).map_err(|_| {
                    ProtocolError::Persistence("residence acknowledgment channel closed".into())
                })?;
            }
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

/// A cached promotion is not permanent authority. Recheck the bound actor,
/// grant and every currently present row before any full delta leaves.
pub(super) fn authorize_promoted_window(
    server: &SyncServer,
    auth: &CoreAuth,
    key: &WindowKey,
    selector: &SyncSelector,
    source: &loro::LoroDoc,
) -> Result<(), ProtocolError> {
    let principal = oneiron::EntityId::from_hex(
        auth.require_registered_principal()
            .map_err(|_| ProtocolError::RpcNoPrincipal)?,
    )
    .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    if selector.member_ref != principal {
        return Err(ProtocolError::InvalidPayload(
            "promotion principal mismatch",
        ));
    }
    let proof = auth.verified_slip().ok_or(ProtocolError::RpcNoPrincipal)?;
    let actor =
        ScopedReadActorKey::from_verified_slip(proof).ok_or(ProtocolError::RpcNoPrincipal)?;
    let scoped = server.vault.scoped_read(actor);
    match promotion_covers_full_window(
        &server.vault,
        source,
        key,
        selector_grant_scope(),
        selector,
        |id| scoped.is_entity_readable(&id),
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ProtocolError::InvalidPayload(
            "promoted window no longer fully granted",
        )),
        Err(error) => Err(map_selector_filter_err(error)),
    }
}

pub(super) fn decode_and_authorize_selector_request(
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

pub(super) fn map_selector_filter_err(e: oneiron::Error) -> ProtocolError {
    if matches!(
        e,
        oneiron::Error::Sync(oneiron::error::SyncError::SyncProtocolError { .. })
            | oneiron::Error::InvalidClaimBody(_)
            | oneiron::Error::Record(oneiron::error::RecordError::InvalidFederationGrantBody(_))
    ) {
        ProtocolError::InvalidPayload("sync selector rejected")
    } else {
        ProtocolError::Persistence(format!("selector filter failed: {e}"))
    }
}

pub(crate) fn selector_grant_scope() -> oneiron::FederationGrantScope {
    oneiron::FederationGrantScope::vault(SERVER_SELECTOR_VAULT_ID)
}
