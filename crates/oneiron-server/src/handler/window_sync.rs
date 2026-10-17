//! WindowSync sub-tag dispatcher with selector and VV paths.

use loro::VersionVector;

use oneiron::sync::residence::{admit_promoted_window_update, promotion_covers_full_window_for};
use oneiron::sync::schema::read_window_list;
use oneiron::sync::window::WindowExport;
use oneiron::sync::{
    SelectorVvRequest, SyncSelector, WindowKey, authorize_sync_selector,
    decode_selector_vv_request, decode_sync_selector,
};

use super::app_tier::require_bound_app_auth;
use super::conn_state::{ConnState, WindowSyncMode};
use crate::auth::CoreAuth;
use crate::protocol::{self, ProtocolError, window_sub_tags};
use crate::server::SyncServer;

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
            | window_sub_tags::SEALED_UPDATE
            | window_sub_tags::SEALED_REQUEST
    ) && payload.len() > server.config.max_update_payload
    {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_update_payload,
        });
    }

    // Sealed relay (OF-292): a private world's ciphertext resting on and
    // moving through this node unread. It never loads or creates the window
    // doc: the host holds no world key and materializes nothing from it.
    if matches!(
        sub_tag,
        window_sub_tags::SEALED_UPDATE | window_sub_tags::SEALED_REQUEST
    ) {
        return handle_sealed_relay(
            server, conn_id, &key, window_key, sub_tag, payload, direct_tx, conn_state,
        );
    }

    if sub_tag == window_sub_tags::PROMOTION_REQUEST {
        // Every opened-item machine of this vault asks for the embedding setup window (OF-370),
        // whatever it opened. A home that holds no such window, or does not grant it to this
        // machine, answers nothing, and the machine asks again on its next connection.
        let setup = key == WindowKey::from_timestamp(oneiron::embed::EMBEDDING_SETUP_LEARNED_AT);
        if setup
            && protocol::is_residence_version(conn_state.protocol_version)
            && !read_window_list(&server.root_doc).contains(&key)
        {
            return Ok(());
        }
        if !protocol::is_residence_version(conn_state.protocol_version)
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
        let window = server
            .serve_window(&key)
            .await
            .map_err(|e| ProtocolError::Persistence(e.to_string()))?;
        let doc = window.doc.clone();
        let authorized = require_bound_app_auth(server, conn_state).and_then(|auth| {
            authorize_promoted_window(
                server,
                auth,
                conn_state.peer_machine(server.vault()),
                &key,
                &selector,
                &doc,
            )
        });
        if setup && authorized.is_err() {
            return Ok(());
        }
        authorized?;
        // The baseline is the root of the snapshot the home would serve this promotion, never a
        // version the device states. A second promotion can only raise it.
        let floor =
            oneiron::sync::window::promotion_baseline(&doc).map_err(map_delta_export_err)?;
        conn_state
            .promotion_baselines
            .entry(key.clone())
            .or_default()
            .merge(&floor);
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
        window_sub_tags::VV_REQUEST
            | window_sub_tags::VV_RESPONSE
            | window_sub_tags::UPDATE
            | window_sub_tags::REPLACEMENT_REQUEST
    ) {
        if protocol::is_residence_version(conn_state.protocol_version) {
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
            | window_sub_tags::WINDOW_INVALIDATE
    ) {
        return Err(ProtocolError::InvalidPayload(
            "client cannot send server-only residence control",
        ));
    }
    // The home never installs a device's window. A device that would have to send one asks for
    // the home's instead and re-authors its own writes on top.
    if sub_tag == window_sub_tags::REPLACEMENT
        || (sub_tag == window_sub_tags::REPLACEMENT_REQUEST
            && (!protocol::installs_window_replacements(conn_state.protocol_version)
                || !payload.is_empty()))
    {
        return Err(ProtocolError::InvalidPayload(
            "invalid window replacement frame",
        ));
    }

    // A frame that names no exchange, and a residence update for a window this socket never
    // promoted, are answered before the window is loaded: neither creates one.
    if !matches!(
        sub_tag,
        window_sub_tags::VV_REQUEST
            | window_sub_tags::VV_RESPONSE
            | window_sub_tags::UPDATE
            | window_sub_tags::RESIDENCE_UPDATE
            | window_sub_tags::REPLACEMENT_REQUEST
    ) {
        tracing::warn!(window_key, sub_tag, "unknown WindowSync sub-tag");
        return Ok(());
    }
    if sub_tag == window_sub_tags::RESIDENCE_UPDATE
        && !conn_state.promoted_windows.contains_key(&key)
    {
        return Err(ProtocolError::InvalidPayload("window not promoted"));
    }
    // A vector that does not decode is refused before the window is loaded, so the refused frame
    // creates nothing.
    if matches!(
        sub_tag,
        window_sub_tags::VV_REQUEST | window_sub_tags::VV_RESPONSE
    ) {
        VersionVector::decode(payload).map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
    }

    // Loads persisted window state (d:w: + pending u:w:) on first touch.
    // Corrupt persisted state closes the connection rather than serving a
    // fresh empty window (fail-closed — see SyncServer::serve_window).
    // The handle is held to the end of the frame, so the window cannot be
    // unloaded under the import below.
    let window = server
        .serve_window(&key)
        .await
        .map_err(|e| ProtocolError::Persistence(format!("window load failed: {e}")))?;
    let doc = window.doc.clone();
    if protocol::is_residence_version(conn_state.protocol_version)
        && matches!(
            sub_tag,
            window_sub_tags::VV_REQUEST
                | window_sub_tags::VV_RESPONSE
                | window_sub_tags::UPDATE
                | window_sub_tags::REPLACEMENT_REQUEST
        )
    {
        let selector = conn_state
            .promoted_windows
            .get(&key)
            .ok_or(ProtocolError::InvalidPayload("window not promoted"))?;
        authorize_promoted_window(
            server,
            require_bound_app_auth(server, conn_state)?,
            conn_state.peer_machine(server.vault()),
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
            let response = export_frame(server, conn_state, &key, &doc, payload)?;
            // Send directly to the requesting client's WebSocket sink, NOT via
            // broadcast. Broadcasting with the requester's conn_id would cause
            // echo suppression to drop the response for the requester.
            let _ = direct_tx.send(response);
            // Reverse SyncStep1: send our VV so the client pushes its local
            // diff back — this is what makes the exchange bidirectional. A
            // window withheld as device-only names only what both sides hold,
            // so a client that sent all it has still sees convergence.
            let remote = VersionVector::decode(payload)
                .map_err(|_| ProtocolError::InvalidPayload("invalid version vector"))?;
            let mut vv = doc.oplog_vv();
            let withheld = peer_withheld(server, conn_state)?;
            if oneiron::sync::window::export_withheld_for(
                server.vault.as_ref(),
                &key,
                &doc,
                &remote,
                withhold(withheld.as_ref()),
            )
            .map_err(map_delta_export_err)?
            {
                vv = vv.intersection(&remote);
            }
            let vv_response = protocol::encode_window_sync(
                window_key,
                window_sub_tags::VV_RESPONSE,
                &vv.encode(),
            )
            .into_result()
            .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = direct_tx.send(vv_response);
            // Subscribe only after a valid VV and a complete direct catch-up.
            let bound = server.config.max_windows_per_connection;
            if let Some(held) = conn_state.subscribe_window(&key, bound) {
                ask_window_row(server, bound, held);
            }
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
            if let Err(error) = oneiron::sync::window::validate_window_update_residence_with_vault(
                server.vault.as_ref(),
                &doc,
                update,
                &key,
            ) {
                // The home's own shallow root cut away what the device's update builds on. The
                // home never installs a device's window: the device takes the home's and writes
                // its own state on top, and an old device that cannot is refused.
                if oneiron::sync::window::update_reaches_below_root(&doc, update) {
                    // The window goes out whole only as a version request's answer would.
                    if protocol::is_residence_version(conn_state.protocol_version) {
                        let selector = conn_state
                            .promoted_windows
                            .get(&key)
                            .ok_or(ProtocolError::InvalidPayload("window not promoted"))?;
                        authorize_promoted_window(
                            server,
                            require_bound_app_auth(server, conn_state)?,
                            conn_state.peer_machine(server.vault()),
                            &key,
                            selector,
                            &doc,
                        )?;
                    }
                    if let Some(frame) = replacement_frame(server, conn_state, &key, &doc)? {
                        let _ = direct_tx.send(frame);
                    }
                    return Ok(());
                }
                return Err(map_delta_export_err(error));
            }
            if protocol::is_residence_version(conn_state.protocol_version) {
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
            let before = doc.oplog_vv();
            let imported = doc
                .import_with(update, &origin)
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

            // Each socket's delivery judges the update for the machine it
            // serves, so a private world's window reaches only the machines
            // that may read it (`window_delivery`). An update that adds no operation, such as a
            // catch-up reply to a vector this home already covers, has nothing to relay: relayed,
            // it would wake every socket that is not pushed the window, and their catch-ups would
            // wake each other in turn. It is still appended above, since another handler may hold
            // the same operations in memory before its own append lands, and the acknowledgment
            // below must name durable bytes.
            if imported.pending.is_some() || doc.oplog_vv() != before {
                let broadcast_msg =
                    protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, update)
                        .into_result()
                        .map_err(|e| {
                            ProtocolError::InvalidPayload(protocol::transport_err_msg(e))
                        })?;
                let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, broadcast_msg);
            }
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
            let response = export_frame(server, conn_state, &key, &doc, payload)?;
            let _ = direct_tx.send(response);
        }
        window_sub_tags::REPLACEMENT_REQUEST => {
            // A device that cannot take this window's history asks for the whole of it.
            if let Some(frame) = replacement_frame(server, conn_state, &key, &doc)? {
                let _ = direct_tx.send(frame);
            }
        }
        _ => {}
    }

    Ok(())
}

/// The sealed relay door (OF-292): this node shelves a private world's
/// sealed packets and forwards them between the owner's machines, judged
/// against the destination each socket proved. The hosted root is never a
/// world key recipient, so nothing here opens a packet: a take on a node
/// that may not read the world shelves it, and an answer goes only where
/// the world may be read or a sealed copy may rest.
fn handle_sealed_relay(
    server: &SyncServer,
    conn_id: u32,
    key: &WindowKey,
    window_key: &str,
    sub_tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    conn_state: &ConnState,
) -> Result<(), ProtocolError> {
    if conn_state.window_sync_mode == WindowSyncMode::Selector {
        return Err(ProtocolError::InvalidPayload(
            "sealed relay on selector lane",
        ));
    }
    let Some(world) = key.world() else {
        return Err(ProtocolError::InvalidPayload(
            "sealed packet for a base window",
        ));
    };
    let vault = server.vault();
    if sub_tag == window_sub_tags::SEALED_UPDATE {
        let packet = oneiron::world_keys::SealedResidenceContent::from_bytes(payload)
            .map_err(|_| ProtocolError::InvalidPayload("malformed sealed packet"))?;
        server
            .reassert_manager
            .take_sealed_residence_content(world, key, &packet)
            .map_err(|_| ProtocolError::InvalidPayload("sealed packet refused"))?;
        // Forward unread to the other sockets; each socket's delivery door
        // re-judges the frame against its own destination.
        let frame =
            protocol::encode_window_sync(window_key, window_sub_tags::SEALED_UPDATE, payload)
                .into_result()
                .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
        let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, frame);
        return Ok(());
    }
    // SEALED_REQUEST: seal fresh where this node may read the world (a
    // self-hosted home), else forward what the shelf holds for the window.
    let destination = conn_state.destination(vault);
    let mut packets = Vec::new();
    match server.reassert_manager.sealed_residence_content_for(
        world,
        key,
        (!payload.is_empty()).then_some(payload),
        destination,
    ) {
        Ok(Some(packet)) => packets.push(packet),
        Ok(None) => {
            let may_rest = vault
                .sealed_copy_may_rest_on(world, destination)
                .unwrap_or(false);
            let may_read = vault
                .authority_fold()
                .map(|fold| fold.world_readable_on(world, destination))
                .unwrap_or(false);
            if may_rest || may_read {
                packets = vault
                    .sealed_window_packets(window_key)
                    .map_err(|e| ProtocolError::Persistence(e.to_string()))?;
            }
        }
        Err(error) => return Err(ProtocolError::Persistence(error.to_string())),
    }
    for packet in packets {
        let frame = protocol::encode_window_sync(
            window_key,
            window_sub_tags::SEALED_UPDATE,
            packet.as_bytes(),
        )
        .into_result()
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
        let _ = direct_tx.send(frame);
    }
    Ok(())
}

/// Asks `max_windows_per_connection`'s question (OF-520): one socket holds `held` windows or
/// documents past `bound`. Nothing waits on the answer, and nothing is refused.
pub(super) fn ask_window_row(server: &SyncServer, bound: usize, held: usize) {
    server.wire_telemetry.limit_questions().ask(
        crate::wire_telemetry::LimitRow::WindowsPerConnection,
        u64::try_from(bound).unwrap_or(u64::MAX),
        u64::try_from(held).unwrap_or(u64::MAX),
    );
}

/// The worlds kept off the machine this socket proved, read now, or `None`
/// for an unknown destination (OF-534 G6). A full-window export judges the
/// machine at the other end, not every machine at once.
fn peer_withheld(
    server: &SyncServer,
    conn_state: &ConnState,
) -> Result<Option<std::collections::BTreeSet<oneiron::EntityId>>, ProtocolError> {
    oneiron::sync::residence::withheld_from_peer(
        server.vault.as_ref(),
        conn_state.peer_machine(server.vault()),
    )
    .map_err(map_delta_export_err)
}

/// The export door's withholding for `withheld`: a proved machine's own
/// worlds, or the device's unknown-destination set.
fn withhold(
    withheld: Option<&std::collections::BTreeSet<oneiron::EntityId>>,
) -> oneiron::sync::window::Withhold<'_> {
    withheld.map_or(
        oneiron::sync::window::Withhold::Unknown,
        oneiron::sync::window::Withhold::Worlds,
    )
}

/// Frames this window's answer to the version vector `remote_vv` for this socket. A promoted
/// residence window answers from its baseline. A peer that holds nothing of the window imports
/// a replacement as its first update, as before replacements existed; one that holds part of it
/// installs the replacement, or is refused when its version cannot, since no answer it can apply
/// exists.
fn export_frame(
    server: &SyncServer,
    conn_state: &ConnState,
    key: &WindowKey,
    doc: &loro::LoroDoc,
    remote_vv: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let withheld = peer_withheld(server, conn_state)?;
    let export = oneiron::sync::window::export_window_since_for(
        server.vault.as_ref(),
        key,
        doc,
        remote_vv,
        conn_state.promotion_baselines.get(key),
        withhold(withheld.as_ref()),
    )
    .map_err(map_delta_export_err)?;
    let (sub_tag, bytes) = match export {
        WindowExport::Update(bytes) => (window_sub_tags::UPDATE, bytes),
        WindowExport::Replacement(bytes)
            if VersionVector::decode(remote_vv).is_ok_and(|remote| remote.is_empty()) =>
        {
            (window_sub_tags::UPDATE, bytes)
        }
        WindowExport::Replacement(bytes)
            if protocol::installs_window_replacements(conn_state.protocol_version) =>
        {
            (window_sub_tags::REPLACEMENT, bytes)
        }
        WindowExport::Replacement(_) => return Err(ProtocolError::ReplacementUnsupported),
    };
    protocol::encode_window_sync(key.as_str(), sub_tag, &bytes)
        .into_result()
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))
}

/// The `REPLACEMENT` frame for a peer that must install this window whole: the history-free
/// snapshot rooted at or after the socket's promotion baseline. A peer that cannot install one is
/// refused. Nothing goes out for a window withheld as device-only.
fn replacement_frame(
    server: &SyncServer,
    conn_state: &ConnState,
    key: &WindowKey,
    doc: &loro::LoroDoc,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    if !protocol::installs_window_replacements(conn_state.protocol_version) {
        return Err(ProtocolError::ReplacementUnsupported);
    }
    let withheld = peer_withheld(server, conn_state)?;
    oneiron::sync::window::export_window_replacement_for(
        server.vault.as_ref(),
        key,
        doc,
        conn_state.promotion_baselines.get(key),
        withhold(withheld.as_ref()),
    )
    .map_err(map_delta_export_err)?
    .map(|snapshot| {
        protocol::encode_window_sync(key.as_str(), window_sub_tags::REPLACEMENT, &snapshot)
            .into_result()
            .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))
    })
    .transpose()
}

/// A cached promotion is not permanent authority. Recheck the bound actor,
/// grant and every currently present row before any full delta leaves.
pub(super) fn authorize_promoted_window(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: oneiron::authority::PeerMachine,
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
    // One admission for the machine this socket proved: the credential, the
    // grant and every carried row's world for that machine (OF-534 G6).
    let admission = oneiron::sync::residence::ResidenceAdmission::load(
        &server.vault,
        proof,
        peer,
        selector_grant_scope(),
        selector,
    )
    .map_err(map_selector_filter_err)?;
    match promotion_covers_full_window_for(
        &server.vault,
        source,
        key,
        selector_grant_scope(),
        selector,
        admission.withhold(),
        |id| admission.allows_item(id),
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

/// The grant scope this single-vault selector server path checks: the one an
/// owner's own-device grant is minted under (FIX 3134). Distinct from the
/// lease ABI's internal vault id.
pub(crate) fn selector_grant_scope() -> oneiron::FederationGrantScope {
    oneiron::federation::own_device_residence_scope()
}
