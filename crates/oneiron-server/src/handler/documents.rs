//! Per-entity selector admission and scope-filtered document delivery on the sync socket.
use super::{
    app_tier::require_bound_app_auth, conn_state::ConnState, window_sync::selector_grant_scope,
};
use crate::auth::CoreScope;
use crate::{protocol::ProtocolError, server::SyncServer};
use oneiron::EntityId;
use oneiron::sync::{
    decode_selector_vv_request,
    transport::{self, document_sub_tags},
};

pub(super) fn handle_document(
    server: &SyncServer,
    conn_id: u32,
    entity: EntityId,
    kind: u8,
    payload: &[u8],
    direct: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    state: &mut ConnState,
) -> Result<(), ProtocolError> {
    if state.protocol_version != transport::PROTOCOL_VERSION
        && state.protocol_version != transport::CHUNK_FULL_WINDOW_PROTOCOL_VERSION
    {
        return Err(ProtocolError::InvalidPayload(
            "document sync requires a document-capable protocol",
        ));
    }
    if payload.len() > server.config.max_update_payload {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_update_payload,
        });
    }
    let principal = document_principal(server, state)?;
    if kind == document_sub_tags::UPDATE {
        require_bound_app_auth(server, state)?
            .require(CoreScope::Write)
            .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    }
    if let Some(request) = state.documents.get(&entity)
        && request.selector.member_ref != principal
    {
        return Err(ProtocolError::InvalidPayload("selector principal mismatch"));
    }
    match kind {
        document_sub_tags::REQUEST => {
            if !state.documents.contains_key(&entity)
                && state.documents.len() >= server.config.max_windows_per_connection
            {
                return Err(ProtocolError::InvalidPayload(
                    "document subscription limit exceeded",
                ));
            }
            let request = decode_selector_vv_request(payload).map_err(storage_error)?;
            if request.selector.member_ref != principal {
                return Err(ProtocolError::InvalidPayload("selector principal mismatch"));
            }
            if is_note(server, entity)? {
                require_note_auth(server, state, &request.selector, false)?;
            }
            let frame = server
                .reassert_manager
                .export_document(
                    entity,
                    selector_grant_scope(),
                    &request.selector,
                    &request.remote_vv,
                )
                .map_err(storage_error)?;
            state.documents.insert(entity, request);
            let _ = direct.send(frame);
            Ok(())
        }
        document_sub_tags::ACK => {
            loro::VersionVector::decode(payload)
                .map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
            let request = state
                .documents
                .get_mut(&entity)
                .ok_or(ProtocolError::InvalidPayload("document not admitted"))?;
            request.remote_vv = payload.to_vec();
            Ok(())
        }
        document_sub_tags::NOTE_OPS => {
            let request = state
                .documents
                .get(&entity)
                .ok_or(ProtocolError::InvalidPayload("document not admitted"))?;
            let auth = require_note_auth(server, state, &request.selector, true)?;
            let actor = EntityId::from_hex(
                auth.require_registered_principal()
                    .map_err(|_| ProtocolError::RpcNoPrincipal)?,
            )
            .map_err(|_| ProtocolError::RpcNoPrincipal)?;
            let class = match auth.actor_class() {
                Some("human") => oneiron::EdgeActorClass::Human,
                Some("agent") => oneiron::EdgeActorClass::Agent,
                Some("system") => oneiron::EdgeActorClass::System,
                _ => return Err(ProtocolError::RpcNoPrincipal),
            };
            let operation = oneiron::note::NoteOperation::decode(payload).map_err(storage_error)?;
            let receipt = server
                .vault
                .memory(actor, class)
                .admit_note_operation(
                    entity,
                    selector_grant_scope(),
                    &request.selector,
                    |txn| auth.credential_is_live_in_write_txn(&server.vault, txn),
                    &operation,
                )
                .map_err(|error| ProtocolError::Persistence(error.to_string()))?;
            // Queue an invalidation before the receipt on the SAME ordered
            // channel, even for idempotent replay. Direct delivery reauthorizes
            // and exports the current state; eager bytes here would be discarded.
            // A broadcast alone cannot guarantee state-before-receipt ordering.
            let notice = transport::encode_document(entity, document_sub_tags::UPDATE, &[])
                .into_result()
                .map_err(|_| ProtocolError::InvalidPayload("invalid document notice"))?;
            let _ = direct.send(notice);
            let payload = serde_json::to_vec(&receipt)
                .map_err(|_| ProtocolError::InvalidPayload("NOTE receipt encode"))?;
            let frame =
                transport::encode_document(entity, document_sub_tags::NOTE_RECEIPT, &payload)
                    .into_result()
                    .map_err(|_| ProtocolError::InvalidPayload("NOTE receipt too large"))?;
            let _ = direct.send(frame);
            Ok(())
        }
        document_sub_tags::UPDATE => {
            if is_note(server, entity)? {
                return Err(ProtocolError::InvalidPayload(
                    "raw NOTE updates require authenticated NOTE_OPS",
                ));
            }
            let request = state
                .documents
                .get(&entity)
                .ok_or(ProtocolError::InvalidPayload("document not admitted"))?;
            // Cached subscription state is only the requested selector. The
            // committing engine writer re-reads its role, scope, expiry, pact
            // and live entity selection; an earlier export is not authority.
            server
                .reassert_manager
                .documents()
                .open(entity)
                .map_err(storage_error)?
                .import_from_peer(kind, payload, selector_grant_scope(), &request.selector)
                .map_err(storage_error)?;
            let vv = server
                .reassert_manager
                .documents()
                .open(entity)
                .map_err(storage_error)?
                .version_vector()
                .map_err(storage_error)?;
            let ack = transport::encode_document(entity, document_sub_tags::ACK, &vv)
                .into_result()
                .map_err(|_| ProtocolError::InvalidPayload("invalid document ack"))?;
            let _ = direct.send(ack);
            let frame = transport::encode_document(entity, kind, payload)
                .into_result()
                .map_err(|_| ProtocolError::InvalidPayload("invalid document frame"))?;
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, frame);
            Ok(())
        }
        _ => Err(ProtocolError::InvalidPayload(
            "client cannot replace a document",
        )),
    }
}

/// Raw notices are not exports. Every recipient re-runs admission and the
/// shallow-since check. Unsubscribed peers receive nothing, including legacy peers.
pub(super) fn document_delivery(
    server: &SyncServer,
    state: &ConnState,
    data: &[u8],
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let docs = match data.first() {
        Some(&transport::TAG_DOCUMENT) => vec![transport::decode_document(&data[1..])],
        Some(&transport::TAG_BATCH) => transport::decode_document_batch(&data[1..])
            .map_err(|_| ProtocolError::InvalidPayload("invalid document batch"))?
            .into_iter()
            .map(Ok)
            .collect(),
        _ => return Ok(Vec::new()),
    };
    if state.documents.is_empty() {
        return Ok(Vec::new());
    }
    let principal = document_principal(server, state)?;
    let mut out = Vec::new();
    for doc in docs {
        let doc = doc.map_err(|_| ProtocolError::InvalidPayload("invalid document notice"))?;
        if let Some(request) = state.documents.get(&doc.entity)
            && request.selector.member_ref == principal
        {
            if is_note(server, doc.entity)?
                && require_note_auth(server, state, &request.selector, false).is_err()
            {
                continue;
            }
            // Denial withholds this entity; it never falls back to the raw notice.
            if let Ok(frame) = server.reassert_manager.export_document(
                doc.entity,
                selector_grant_scope(),
                &request.selector,
                &request.remote_vv,
            ) {
                if doc.kind == document_sub_tags::NOTE_RECEIPT {
                    let receipt: oneiron::note::NoteOperationReceipt =
                        serde_json::from_slice(doc.payload)
                            .map_err(|_| ProtocolError::InvalidPayload("invalid NOTE receipt"))?;
                    // The current document may now be exportable because erasure
                    // removed a hidden pin. Never send its pre-erasure queued view.
                    if !server
                        .vault
                        .note_receipt_is_current(doc.entity, &receipt)
                        .map_err(storage_error)?
                    {
                        continue;
                    }
                    out.push(
                        transport::encode_document(doc.entity, doc.kind, doc.payload)
                            .into_result()
                            .map_err(|_| ProtocolError::InvalidPayload("invalid NOTE receipt"))?,
                    );
                } else if doc.kind == document_sub_tags::ACK {
                    let vv = server
                        .reassert_manager
                        .documents()
                        .open(doc.entity)
                        .map_err(storage_error)?
                        .version_vector()
                        .map_err(storage_error)?;
                    out.push(
                        transport::encode_document(doc.entity, document_sub_tags::ACK, &vv)
                            .into_result()
                            .map_err(|_| ProtocolError::InvalidPayload("invalid document ack"))?,
                    );
                } else {
                    out.push(frame);
                }
            }
        }
    }
    Ok(out)
}

fn document_principal(server: &SyncServer, state: &ConnState) -> Result<EntityId, ProtocolError> {
    let auth = require_bound_app_auth(server, state)?;
    auth.require(CoreScope::Read)
        .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    EntityId::from_hex(
        auth.require_registered_principal()
            .map_err(|_| ProtocolError::RpcNoPrincipal)?,
    )
    .map_err(|_| ProtocolError::RpcNoPrincipal)
}

fn storage_error(error: oneiron::Error) -> ProtocolError {
    ProtocolError::Persistence(error.to_string())
}

fn is_note(server: &SyncServer, entity: EntityId) -> Result<bool, ProtocolError> {
    Ok(server
        .vault
        .get_entity_type(&entity)
        .map_err(storage_error)?
        == Some(oneiron::registry::ENTITY_TYPE_NOTE))
}

fn require_note_auth<'a>(
    server: &SyncServer,
    state: &'a ConnState,
    selector: &oneiron::sync::SyncSelector,
    write: bool,
) -> Result<&'a crate::auth::CoreAuth, ProtocolError> {
    let auth = super::app_tier::require_bound_app_auth(server, state)?;
    auth.require(crate::auth::CoreScope::Read)
        .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    if write {
        auth.require(crate::auth::CoreScope::Write)
            .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    }
    let actor = auth
        .require_registered_principal()
        .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    if actor != selector.member_ref.to_hex() || auth.jti().is_none() || auth.actor_class().is_none()
    {
        return Err(ProtocolError::RpcNoPrincipal);
    }
    Ok(auth)
}
