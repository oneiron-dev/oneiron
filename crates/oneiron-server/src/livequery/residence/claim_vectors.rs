//! Default CLAIM derivations are a machine-only read. The engine judges the
//! actual current source and peer; the reply retains its source-row identity.

use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use serde::Deserialize;
use serde_json::Value;

use super::{Answer, AppError};
use crate::server::SyncServer;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    entity_id: String,
}

pub(super) fn read(
    server: &SyncServer,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    let input: Request = serde_json::from_value(params).map_err(|_| AppError::invalid_params())?;
    let id = EntityId::from_hex(&input.entity_id).map_err(|_| AppError::invalid_params())?;
    let vector = server
        .vault
        .home_claim_vector_for_peer(peer, &id)
        .map_err(|_| AppError::internal_server_error("claim vector unavailable"))?;
    let rows = vector
        .as_ref()
        .map_or_else(Vec::new, |vector| vector.release_rows.clone());
    let value = serde_json::to_value(vector)
        .map_err(|_| AppError::internal_server_error("claim vector does not encode"))?;
    Ok((value, Some(rows)))
}
