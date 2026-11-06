//! Own-peer text media-vector reuse, separate from canonical window bytes.

use base64::Engine;
use serde_json::json;

use super::rpc::{ResidenceRpc, refused, residence_budgets};
use crate::authority::PeerMachine;
use crate::embed::MediaVectorReplica;
use crate::sync::client::{SyncClientConfig, SyncResidenceMode};
use crate::sync::residence::rows_may_reach;
use crate::sync::selector::encode_sync_selector;
use crate::sync::transport::TransportError;
use crate::{EntityId, Vault};

pub(crate) async fn request_media_vectors(
    vault: &Vault,
    config: &SyncClientConfig,
    space: &str,
    ids: &[EntityId],
) -> Result<Vec<(EntityId, MediaVectorReplica)>, TransportError> {
    if config.residence_mode != SyncResidenceMode::Opened || config.transport_credential.is_none() {
        return Err(refused());
    }
    let selector = config.residence_selector.as_ref().ok_or_else(refused)?;
    let selector = encode_sync_selector(selector).map_err(|_| refused())?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, residence_budgets(vault)?).await?
    else {
        return Ok(Vec::new());
    };
    if !matches!(
        vault.peer_machine_stands(rpc.home),
        PeerMachine::Proven { .. }
    ) {
        return Err(refused());
    }
    let mut replicas = Vec::new();
    for id in ids {
        let rows = {
            let txn = vault.store.env.read_txn().map_err(|_| refused())?;
            crate::embed::text_vector_sources_in_txn(vault, &txn, id)
                .map_err(|_| refused())?
                .map(|(_, rows)| rows)
        };
        let Some(rows) = rows else {
            continue;
        };
        if !matches!(
            vault.peer_machine_stands(rpc.home),
            PeerMachine::Proven { .. }
        ) {
            return Err(refused());
        }
        if !rows_may_reach(vault, rpc.home, &rows).map_err(|_| refused())? {
            continue;
        }
        let value = rpc
            .request(
                "residence.media_vectors",
                json!({
                    "selector": base64::engine::general_purpose::STANDARD.encode(&selector),
                    "space": space,
                    "id": id,
                }),
            )
            .await?;
        if !matches!(
            vault.peer_machine_stands(rpc.home),
            PeerMachine::Proven { .. }
        ) {
            return Err(refused());
        }
        let received: Vec<MediaVectorReplica> = serde_json::from_value(value)
            .map_err(|_| TransportError::InvalidPayload("invalid home media vectors"))?;
        replicas.extend(received.into_iter().map(|replica| (*id, replica)));
    }
    Ok(replicas)
}
