//! A typed body's upload on the owner lane (FIX 2458): the home takes an
//! office body's frame from the owner's own proven device.

use oneiron::EntityId;
use oneiron::sync::transport::{self, document_sub_tags};

use super::{ConnState, open_for, owner_auth, storage_error};
use crate::{protocol::ProtocolError, server::SyncServer};

/// A typed body's frame from the owner's own proven device (FIX 2458), past
/// the gate a NOTE_OPS upload passes: it joins the body here through the
/// office merge preflight, a fork where it fails, never an overwrite. A frame
/// that moved the body, or opened a fork, sends the merged body on: back to
/// this device, and to every other socket that holds the document, each
/// exported for its own lane.
pub(super) fn owner_body_update(
    server: &SyncServer,
    conn_id: u32,
    state: &ConnState,
    entity: EntityId,
    payload: &[u8],
    direct: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    let auth = owner_auth(server, state, true)?;
    let peer = state.peer_machine(server.vault());
    if !matches!(peer, oneiron::authority::PeerMachine::Proven { .. }) {
        return Err(ProtocolError::InvalidPayload(
            "a typed body update needs a proven own device",
        ));
    }
    let actor = EntityId::from_hex(
        auth.require_registered_principal()
            .map_err(|_| ProtocolError::RpcNoPrincipal)?,
    )
    .map_err(|_| ProtocolError::RpcNoPrincipal)?;
    let document = open_for(server, entity, &actor)?;
    let moved = document
        .import_owner_body(payload, peer, |txn| {
            auth.credential_is_live_in_write_txn(&server.vault, txn)
        })
        .map_err(storage_error)?;
    drop(document);
    if moved {
        let notice = transport::encode_document(entity, document_sub_tags::UPDATE, &[])
            .into_result()
            .map_err(|_| ProtocolError::InvalidPayload("invalid document notice"))?;
        let _ = direct.send(notice.clone());
        let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, notice);
    }
    Ok(())
}
