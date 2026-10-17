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
        && !transport::is_owner_window_version(state.protocol_version)
        && !transport::is_residence_version(state.protocol_version)
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
    if kind == document_sub_tags::ARTIFACT_PUBLICATION {
        return artifact_publication(server, state, entity, payload, direct);
    }
    let principal = document_principal(server, state)?;
    let peer = state.peer_machine(server.vault());
    if kind == document_sub_tags::REQUEST && payload.get(..4) == Some(&[0; 4]) {
        return owner_request(server, state, entity, &payload[4..], direct);
    }
    if state.owner_documents.contains_key(&entity) {
        return owner_document(server, state, entity, kind, payload, direct);
    }
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
            if state.lfs_owner_mode {
                return Err(ProtocolError::InvalidPayload(
                    "owner connection cannot become selector-scoped",
                ));
            }
            let request = decode_selector_vv_request(payload).map_err(storage_error)?;
            if request.selector.member_ref != principal {
                return Err(ProtocolError::InvalidPayload("selector principal mismatch"));
            }
            if is_note(server, entity)? {
                require_note_auth(server, state, &request.selector, false)?;
            }
            // An export opens the document: past the live-document row it
            // waits its turn off the runtime worker (rule 5).
            let frame = crate::server::blocking(|| {
                server.reassert_manager.export_document_for_peer(
                    entity,
                    selector_grant_scope(),
                    &request.selector,
                    &request.remote_vv,
                    peer,
                )
            })
            .map_err(storage_error)?;
            state.documents.insert(entity, request);
            let held = state.documents.len();
            ask_past_row(server, state, held);
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
                    |txn| {
                        auth.credential_is_live_in_write_txn(&server.vault, txn)
                            && oneiron::sync::documents::admit_document_destination_in_txn(
                                &server.vault,
                                txn,
                                entity,
                                peer,
                            )
                            .is_ok()
                    },
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
            let document = open_for(server, entity, &request.selector.member_ref)?;
            document
                .import_from_peer(
                    kind,
                    payload,
                    selector_grant_scope(),
                    &request.selector,
                    peer,
                )
                .map_err(storage_error)?;
            let vv = document.version_vector().map_err(storage_error)?;
            drop(document);
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

/// An own device's owner REQUEST: a v11 connection that is not
/// selector-scoped, with a bound NOTE session whose principal is the vault
/// owner. The connection is then an owner connection for good. A REQUEST for
/// a NOTE this server does not hold yet waits for the NOTE's next notice.
fn owner_request(
    server: &SyncServer,
    state: &mut ConnState,
    entity: EntityId,
    remote_vv: &[u8],
    direct: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    owner_auth(server, state, false)?;
    loro::VersionVector::decode(remote_vv).map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
    state.lfs_owner_mode = true;
    state.owner_documents.insert(entity, remote_vv.to_vec());
    let held = state.owner_documents.len();
    ask_past_row(server, state, held);
    let peer = state.peer_machine(server.vault());
    if server
        .vault
        .get_raw(&entity)
        .map_err(storage_error)?
        .is_some()
    {
        let frame = crate::server::blocking(|| {
            server
                .reassert_manager
                .export_owner_document_for(entity, remote_vv, peer)
        })
        .map_err(storage_error)?;
        let _ = direct.send(frame);
    }
    Ok(())
}

/// An own device's pinned artifact pointer change, with the rows that serve
/// it. Only the vault owner's bound session on an owner lane may carry one:
/// a publication is the owner's, already gated where it was made. The vault
/// applies it once window sync has delivered every row it names, and the
/// receipt goes back on this socket alone.
fn artifact_publication(
    server: &SyncServer,
    state: &mut ConnState,
    entity: EntityId,
    payload: &[u8],
    direct: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    owner_auth(server, state, true)?;
    let receipt = server
        .vault
        .import_artifact_publication(entity, payload)
        .map_err(storage_error)?;
    let _ = direct.send(receipt);
    Ok(())
}

/// A socket's document subscriptions past `max_windows_per_connection` ask the row's question
/// once, and the socket keeps every one: the row is never a refusal.
fn ask_past_row(server: &SyncServer, state: &mut ConnState, held: usize) {
    let bound = server.config.max_windows_per_connection;
    if held > bound
        && let Some(held) = state.crossed_limit(held)
    {
        super::window_sync::ask_window_row(server, bound, held);
    }
}

/// ACK and NOTE_OPS on an owner subscription.
fn owner_document(
    server: &SyncServer,
    state: &mut ConnState,
    entity: EntityId,
    kind: u8,
    payload: &[u8],
    direct: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    match kind {
        document_sub_tags::ACK => {
            loro::VersionVector::decode(payload)
                .map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
            state.owner_documents.insert(entity, payload.to_vec());
            Ok(())
        }
        document_sub_tags::NOTE_OPS => {
            let auth = owner_auth(server, state, true)?;
            let actor = EntityId::from_hex(
                auth.require_registered_principal()
                    .map_err(|_| ProtocolError::RpcNoPrincipal)?,
            )
            .map_err(|_| ProtocolError::RpcNoPrincipal)?;
            let operation = oneiron::note::NoteOperation::decode(payload).map_err(storage_error)?;
            let receipt = server
                .vault
                .memory(actor, oneiron::EdgeActorClass::Human)
                .admit_owner_note_operation(
                    entity,
                    |txn| auth.credential_is_live_in_write_txn(&server.vault, txn),
                    &operation,
                )
                .map_err(|error| ProtocolError::Persistence(error.to_string()))?;
            // State before receipt on the same ordered channel, as on the
            // selector lane.
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
        _ => Err(ProtocolError::InvalidPayload(
            "owner lane carries requests, acks and NOTE operations",
        )),
    }
}

/// The owner lane's gate: v11, never selector-scoped, and a bound NOTE
/// session whose principal is the vault owner.
fn owner_auth<'a>(
    server: &SyncServer,
    state: &'a ConnState,
    write: bool,
) -> Result<&'a crate::auth::CoreAuth, ProtocolError> {
    if (!transport::is_owner_window_version(state.protocol_version)
        && !transport::is_residence_version(state.protocol_version))
        || state.window_sync_mode == super::conn_state::WindowSyncMode::Selector
        || !state.documents.is_empty()
    {
        return Err(ProtocolError::InvalidPayload(
            "owner lane needs an owner connection",
        ));
    }
    let auth = super::app_tier::require_bound_app_auth(server, state)?;
    auth.require(CoreScope::Read)
        .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    if write {
        auth.require(CoreScope::Write)
            .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    }
    if auth.jti().is_none() || auth.actor_class() != Some("human") {
        return Err(ProtocolError::RpcNoPrincipal);
    }
    let actor = EntityId::from_hex(
        auth.require_registered_principal()
            .map_err(|_| ProtocolError::RpcNoPrincipal)?,
    )
    .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    server
        .vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .verify_owner()
        .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    Ok(auth)
}

/// Raw notices are not exports. Every recipient re-runs admission and the
/// shallow-since check. Unsubscribed peers receive nothing, including legacy peers.
#[cfg(test)]
pub(super) fn document_delivery(
    server: &SyncServer,
    state: &ConnState,
    data: &[u8],
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    document_delivery_retrying(server, state, data, &mut Vec::new())
}

/// [`document_delivery`] that keeps, in `retry`, the notice of each document
/// whose export waited for its turn past its deadline (rule 5): the caller
/// queues it again rather than consume the only notice of a change.
pub(super) fn document_delivery_retrying(
    server: &SyncServer,
    state: &ConnState,
    data: &[u8],
    retry: &mut Vec<Vec<u8>>,
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
    if state.documents.is_empty() && state.owner_documents.is_empty() {
        return Ok(Vec::new());
    }
    let principal = document_principal(server, state)?;
    let peer = state.peer_machine(server.vault());
    let mut out = Vec::new();
    for doc in docs {
        let doc = doc.map_err(|_| ProtocolError::InvalidPayload("invalid document notice"))?;
        if let Some(remote_vv) = state.owner_documents.get(&doc.entity) {
            if owner_auth(server, state, false).is_err() {
                continue;
            }
            if doc.kind == document_sub_tags::NOTE_RECEIPT {
                continue;
            }
            // Denial withholds this entity; it never falls back to the raw notice.
            match crate::server::blocking(|| {
                server
                    .reassert_manager
                    .export_owner_document_for(doc.entity, remote_vv, peer)
            }) {
                Ok(frame) => out.push(frame),
                Err(error) if waited_out(&error) => retry.extend(notice(&doc)),
                Err(_) => {}
            }
            continue;
        }
        if let Some(request) = state.documents.get(&doc.entity)
            && request.selector.member_ref == principal
        {
            if is_note(server, doc.entity)?
                && require_note_auth(server, state, &request.selector, false).is_err()
            {
                continue;
            }
            // Denial withholds this entity; it never falls back to the raw notice.
            let exported = crate::server::blocking(|| {
                server.reassert_manager.export_document_for_peer(
                    doc.entity,
                    selector_grant_scope(),
                    &request.selector,
                    &request.remote_vv,
                    peer,
                )
            });
            if let Err(error) = &exported
                && waited_out(error)
            {
                retry.extend(notice(&doc));
            }
            if let Ok(frame) = exported {
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
                    let document = match open_for(server, doc.entity, &request.selector.member_ref)
                    {
                        Err(ProtocolError::WaitedOut) => {
                            retry.extend(notice(&doc));
                            continue;
                        }
                        document => document?,
                    };
                    let vv = document.version_vector().map_err(storage_error)?;
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

/// Whether a document's open ended at its turn's deadline: a notice is tried
/// again, and a peer's frame is answered [`ProtocolError::WaitedOut`].
fn waited_out(error: &oneiron::Error) -> bool {
    error.kind() == oneiron::ErrorKind::LiveDocumentWaitedOut
}

/// Queues the notices whose export waited out its turn again after a pause,
/// so a retried export never starves the socket's own input (rule 5).
pub(super) fn retry_later(
    direct: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    notices: Vec<Vec<u8>>,
) {
    if notices.is_empty() {
        return;
    }
    let direct = direct.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        for notice in notices {
            let _ = direct.send(notice);
        }
    });
}

/// The notice of one document, to queue again.
fn notice(doc: &transport::DocumentFrame<'_>) -> Option<Vec<u8>> {
    transport::encode_document(doc.entity, doc.kind, doc.payload)
        .into_result()
        .ok()
}

fn document_principal(server: &SyncServer, state: &ConnState) -> Result<EntityId, ProtocolError> {
    let auth = require_bound_app_auth(server, state)?;
    // A selector export serves its grant's rows, not the credential's lane,
    // so a credential limited to facets is refused here (owner ruling
    // FACET-READ), as the raw HTTP doors refuse it.
    auth.require(CoreScope::Read)
        .and_then(|()| auth.require_unnarrowed_facets())
        .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    EntityId::from_hex(
        auth.require_registered_principal()
            .map_err(|_| ProtocolError::RpcNoPrincipal)?,
    )
    .map_err(|_| ProtocolError::RpcNoPrincipal)
}

/// Opens `entity` for `member`'s work. Past the vault's live-document row the
/// open waits its turn, off the runtime worker; it is never refused for the
/// count (rule 5), and a wait past its deadline ends the request with
/// [`ProtocolError::WaitedOut`].
fn open_for(
    server: &SyncServer,
    entity: EntityId,
    member: &EntityId,
) -> Result<std::sync::Arc<oneiron::sync::documents::EntityDocument>, ProtocolError> {
    crate::server::blocking(|| {
        server
            .reassert_manager
            .documents()
            .open_for(entity, member.as_bytes())
    })
    .map_err(storage_error)
}

fn storage_error(error: oneiron::Error) -> ProtocolError {
    if waited_out(&error) {
        return ProtocolError::WaitedOut;
    }
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
