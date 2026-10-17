//! Sync dispatch plus app-tier Rpc/Sub admission and bound-auth checks.

use loro::VersionVector;

use super::conn_state::ConnState;
use super::connection::session_credential_revoked;
use super::ephemeral::{
    canonical_ephemeral_frames, ephemeral_hub_candidate, validate_ephemeral_payload,
};
use super::window_sync::handle_window_sync;
use crate::auth::CoreAuth;
use crate::protocol::{self, ProtocolError, SyncMessage};
use crate::server::SyncServer;

/// Dispatches a parsed SyncMessage to the appropriate handler.
pub(super) async fn handle_sync_message(
    server: &SyncServer,
    conn_id: u32,
    msg: SyncMessage,
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    conn_state: &mut ConnState,
) -> Result<(), ProtocolError> {
    match msg {
        SyncMessage::LfsChunks(payload) => {
            super::lfs_chunks::handle(server, payload, direct_tx, conn_state).await
        }
        SyncMessage::Doc {
            entity,
            kind,
            payload,
        } => super::documents::handle_document(
            server, conn_id, entity, kind, &payload, direct_tx, conn_state,
        ),
        SyncMessage::Batch(members) => {
            for member in members {
                match member {
                    SyncMessage::Doc {
                        entity,
                        kind,
                        payload,
                    } => {
                        super::documents::handle_document(
                            server, conn_id, entity, kind, &payload, direct_tx, conn_state,
                        )?;
                    }
                    SyncMessage::WindowSync {
                        window_key,
                        sub_tag,
                        payload,
                    } => {
                        handle_window_sync(
                            server,
                            conn_id,
                            &window_key,
                            sub_tag,
                            &payload,
                            direct_tx,
                            conn_state,
                        )
                        .await?;
                    }
                    _ => return Err(ProtocolError::InvalidPayload("invalid node batch member")),
                }
            }
            Ok(())
        }
        SyncMessage::Rpc(payload) => {
            handle_app_message(server, conn_state, protocol::TAG_RPC, &payload, direct_tx)
        }
        SyncMessage::Sub(payload) => {
            handle_app_message(server, conn_state, protocol::TAG_SUB, &payload, direct_tx)
        }
        SyncMessage::RootUpdate(_update_bytes) => {
            // Root doc is server-authoritative — reject client updates silently
            tracing::debug!(
                conn_id,
                "rejected client root update (server-authoritative)"
            );
            Ok(())
        }
        SyncMessage::Ephemeral(payload) => {
            // One change to the hub at a time: read, checked, charged to the
            // retained-memory line and applied under the presence guard
            // (rule 5, row 19).
            let mut presence = server.presence.lock();
            presence.expire(&server.ephemeral_store);
            let states = validate_ephemeral_payload(server, &payload)?;
            if !presence.fit(ephemeral_hub_candidate(server, &payload, &states)?) {
                tracing::warn!(
                    conn_id,
                    kind = "memory_floor",
                    "presence frame not kept: retained memory is full"
                );
                return Ok(());
            }
            server
                .ephemeral_store
                .apply(&payload)
                .map_err(|_| ProtocolError::InvalidPayload("invalid ephemeral payload"))?;
            drop(presence);
            for encoded in canonical_ephemeral_frames(server, &states)? {
                let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, encoded);
            }
            Ok(())
        }
        SyncMessage::LeaseRequest {
            client_id,
            pubkey,
            pop_sig,
        } => {
            // ONE-1140 (OD-3): registrar under the server lease lock. A
            // storage/persist failure is fail-closed (Persistence closes
            // the connection); a REJECTED binding is a normal ack — sync
            // proceeds, peers' replay doors quarantine the device's NEW
            // receipts.
            let decision = server
                .register_lease(client_id, &pubkey, &pop_sig)
                .await
                .map_err(|e| ProtocolError::Persistence(format!("lease registrar: {e}")))?;
            let status = if decision.granted {
                protocol::LEASE_STATUS_GRANTED
            } else {
                protocol::LEASE_STATUS_REJECTED
            };
            let expires_at = if decision.granted {
                decision.expires_at
            } else {
                0
            };
            tracing::info!(
                conn_id,
                client_id = format!("{client_id:016x}"),
                granted = decision.granted,
                "lease request processed"
            );
            // Direct ack to the requester (echo suppression would drop a
            // broadcast for the sender).
            let _ = direct_tx.send(protocol::encode_lease_granted(
                status, client_id, expires_at,
            ));
            // Registry change rides the root-update broadcast to ALL
            // connections — conn_id 0 (the bridge/local sentinel) skips
            // echo suppression because the REQUESTER also needs its own
            // record mirrored into ls: for door-side verification.
            if let Some(update) = decision.root_update {
                let msg = protocol::encode_root_update(&update);
                let _ = crate::broadcast::broadcast(&server.broadcast_tx, 0, msg);
            }
            Ok(())
        }
        SyncMessage::RootVersionVector(vv_bytes) => {
            // Client is requesting root doc updates since their VV (Loro
            // binary encoding). Malformed VV → typed error, fail-closed —
            // NEVER answered with a full export as if the VV were empty.
            let client_vv = VersionVector::decode(&vv_bytes)
                .map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
            tracing::debug!(conn_id, "client sent root VV — sending root delta");
            match server.export_root_updates(&client_vv) {
                Ok(delta) => {
                    let msg = protocol::encode_root_update(&delta);
                    let _ = direct_tx.send(msg);
                }
                Err(_) => {
                    tracing::error!(
                        conn_id,
                        reason = "root_delta_export_failed",
                        "failed to export root delta for VV response"
                    );
                }
            }
            Ok(())
        }
        SyncMessage::WindowSync {
            window_key,
            sub_tag,
            payload,
        } => {
            handle_window_sync(
                server,
                conn_id,
                &window_key,
                sub_tag,
                &payload,
                direct_tx,
                conn_state,
            )
            .await
        }
    }
}

/// App-tier admission is disjoint from sync-mode binding. In particular, a
/// sync-only connection can remain unbound for its entire lifetime.
///
/// The synchronous door: a verb runs here, through the blocking bridge
/// ([`crate::livequery::bound_rpc_reply`]), not off a socket's loop.
#[cfg(test)]
pub(super) fn handle_app_message(
    server: &SyncServer,
    state: &mut ConnState,
    tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    let Some(call) =
        handle_app_message_with_connection(server, state, tag, payload, direct_tx, None)?
    else {
        return Ok(());
    };
    let reply = crate::livequery::bound_rpc_reply(server, &call.auth, call.request)?;
    for frame in reply.queued(call.conn) {
        direct_tx
            .send(frame)
            .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
    }
    Ok(())
}

/// A verb RPC the owner loop answers off the loop: the bound credential it
/// runs under, the request, and the socket its answer is queued for.
pub(super) struct VerbCall {
    auth: CoreAuth,
    request: crate::livequery::RpcRequest,
    conn: u32,
}

impl VerbCall {
    /// Runs the verb to its answer and queues the answer on `direct_tx`,
    /// whose send door judges each frame again (DEC-0005).
    pub(super) async fn answer(
        self,
        server: std::sync::Arc<SyncServer>,
        direct_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<(), ProtocolError> {
        let reply = crate::livequery::rpc_reply(&server, &self.auth, self.request).await?;
        for frame in reply.queued(self.conn) {
            direct_tx
                .send(frame)
                .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
        }
        Ok(())
    }
}

/// Answers an app-tier frame here, except a verb RPC, which it hands back to
/// run off the caller's loop.
pub(super) fn handle_app_message_with_connection(
    server: &SyncServer,
    state: &mut ConnState,
    tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    connection: Option<&mut crate::livequery::connection::Connection>,
) -> Result<Option<VerbCall>, ProtocolError> {
    if state.protocol_version < protocol::APP_TIER_PROTOCOL_VERSION_VERSION {
        return Err(ProtocolError::RpcVersionMismatch);
    }
    if tag == protocol::TAG_RPC {
        let request = crate::livequery::decode_rpc(payload).map_err(|_| {
            if state.bound_auth.is_none() {
                ProtocolError::RpcNoPrincipal
            } else {
                ProtocolError::InvalidPayload("invalid RPC request")
            }
        })?;
        if request.method == "auth.bind" {
            let binding = (|| {
                if state.bound_auth.is_some() {
                    return Err(ProtocolError::RpcNoPrincipal);
                }
                let token = crate::livequery::bind_token(&request.params)
                    .map_err(|_| ProtocolError::RpcNoPrincipal)?;
                let proof: crate::auth::BindingProof = serde_json::from_value(
                    request
                        .params
                        .get("binding")
                        .cloned()
                        .ok_or(ProtocolError::RpcNoPrincipal)?,
                )
                .map_err(|_| ProtocolError::RpcNoPrincipal)?;
                let auth = CoreAuth::bind_transport_once(&token, &proof, server.vault().as_ref())
                    .map_err(|_| ProtocolError::RpcNoPrincipal)?;
                auth.require_registered_principal()
                    .map_err(|_| ProtocolError::RpcNoPrincipal)?;
                Ok(auth)
            })();
            let actor = binding.as_ref().map_or("unauthenticated", |auth| {
                auth.principal_ref().unwrap_or(auth.principal())
            });
            let _ =
                server
                    .wire_telemetry
                    .record("auth.bind", actor, oneiron_vault_contract::now_ts());
            state.bound_auth = Some(binding?.at(state.locality));
            for frame in crate::livequery::rpc_result(request.request_id, serde_json::Value::Null)?
            {
                direct_tx
                    .send(frame)
                    .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
            }
            return Ok(None);
        }
        let auth = require_bound_app_auth(server, state)?;
        let _ = server.wire_telemetry.record(
            &request.method,
            auth.principal_ref().unwrap_or(auth.principal()),
            oneiron_vault_contract::now_ts(),
        );
        // A result is queued with the rows it carries, for the socket's
        // send door to judge again (DEC-0005).
        let conn = connection
            .as_deref()
            .map_or(0, crate::livequery::connection::Connection::conn_id);
        let frames = if request.method == "ping" {
            vec![crate::livequery::ping_result(
                request.request_id,
                request.params,
            )?]
        } else if request.method.starts_with("residence.") {
            let bound = auth.clone();
            // The machine this socket proved, judged again now: residence
            // reads serve it by its own world read settings (OF-534 G6).
            let peer = state.peer_machine(&server.vault);
            crate::livequery::residence_rpc(
                server,
                &bound,
                peer,
                request,
                &mut state.residence_index,
            )?
            .queued(conn)
        } else {
            return Ok(Some(VerbCall {
                auth: auth.clone(),
                request,
                conn,
            }));
        };
        for frame in frames {
            direct_tx
                .send(frame)
                .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
        }
    } else {
        let auth = require_bound_app_auth(server, state)?;
        let request = crate::livequery::decode_sub(payload)?;
        let _ = server.wire_telemetry.record(
            "subscribe",
            auth.principal_ref().unwrap_or(auth.principal()),
            oneiron_vault_contract::now_ts(),
        );
        let connection =
            connection.ok_or(ProtocolError::InvalidPayload("subscription owner missing"))?;
        for frame in connection.control(auth, request)? {
            direct_tx
                .send(frame)
                .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
        }
    }
    Ok(None)
}

pub(super) fn require_bound_app_auth<'a>(
    server: &SyncServer,
    state: &'a ConnState,
) -> Result<&'a CoreAuth, ProtocolError> {
    let auth = state
        .bound_auth
        .as_ref()
        .ok_or(ProtocolError::RpcNoPrincipal)?;
    if !auth.credential_is_live(server.vault().as_ref())
        || session_credential_revoked(server.vault().as_ref(), auth.jti())
    {
        return Err(ProtocolError::RpcNoPrincipal);
    }
    Ok(auth)
}
