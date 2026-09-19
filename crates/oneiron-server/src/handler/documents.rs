//! Per-entity selector admission and scope-filtered document delivery on the sync socket.
use super::{conn_state::ConnState, window_sync::selector_grant_scope};
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
    if state.protocol_version != transport::PROTOCOL_VERSION {
        return Err(ProtocolError::InvalidPayload("document sync requires v9"));
    }
    if payload.len() > server.config.max_update_payload {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_update_payload,
        });
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
        document_sub_tags::UPDATE => {
            let request = state
                .documents
                .get(&entity)
                .ok_or(ProtocolError::InvalidPayload("document not admitted"))?;
            let body = server
                .vault
                .get(&request.selector.grant_id)
                .map_err(storage_error)?
                .ok_or(ProtocolError::InvalidPayload("document grant missing"))?;
            let grant =
                oneiron::federation::decode_federation_grant_body(&body).map_err(storage_error)?;
            if !matches!(
                grant.role,
                oneiron::federation::FederationGrantRole::Owner
                    | oneiron::federation::FederationGrantRole::Admin
                    | oneiron::federation::FederationGrantRole::Member
            ) {
                return Err(ProtocolError::InvalidPayload("document grant is read-only"));
            }
            // Re-consult the same selector before each write; revocation and narrowing
            // cannot be bypassed by a subscription admitted earlier on this socket.
            server
                .reassert_manager
                .export_document(
                    entity,
                    selector_grant_scope(),
                    &request.selector,
                    &request.remote_vv,
                )
                .map_err(storage_error)?;
            server
                .reassert_manager
                .documents()
                .open(entity)
                .map_err(storage_error)?
                .import(kind, payload)
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
    let mut out = Vec::new();
    for doc in docs {
        let doc = doc.map_err(|_| ProtocolError::InvalidPayload("invalid document notice"))?;
        if let Some(request) = state.documents.get(&doc.entity) {
            // Denial withholds this entity; it never falls back to the raw notice.
            if let Ok(frame) = server.reassert_manager.export_document(
                doc.entity,
                selector_grant_scope(),
                &request.selector,
                &request.remote_vv,
            ) {
                if doc.kind == document_sub_tags::ACK {
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

fn storage_error(error: oneiron::Error) -> ProtocolError {
    ProtocolError::Persistence(error.to_string())
}
