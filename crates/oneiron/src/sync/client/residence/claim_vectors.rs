//! A single leased default CLAIM asks the live home once. No window history,
//! selector, actor session or new queue is involved.

use crate::embed::home_vectors::{ReceivedHomeClaimVector, own_peer};
use crate::sync::client::SyncClientConfig;
use crate::{EntityId, Result, Vault};

pub(crate) async fn default_claim_vector(
    vault: &Vault,
    config: &SyncClientConfig,
    id: EntityId,
) -> Result<Option<ReceivedHomeClaimVector>> {
    let Some(budgets) = vault.residence_operation_budgets()? else {
        return Ok(None);
    };
    if config.transport_credential.is_none() {
        return Ok(None);
    }
    let mut rpc = match super::rpc::ResidenceRpc::connect_machine(vault, config, budgets).await {
        Ok(Some(rpc)) => rpc,
        Ok(None) | Err(_) => return Ok(None),
    };
    if !own_peer(vault, rpc.home)? {
        return Ok(None);
    }
    if !vault.rows_may_leave_for(&[id], &crate::settings::ReadDestination::toward(rpc.home))? {
        return Ok(None);
    }
    let value = match rpc
        .call(
            "residence.claim.vector",
            serde_json::json!({"entityId": id.to_hex()}),
        )
        .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(_)) | Err(_) => return Ok(None),
    };
    let Ok(Some(vector)) = serde_json::from_value::<Option<crate::embed::HomeClaimVector>>(value)
    else {
        return Ok(None);
    };
    if vector.entity_id != id {
        return Ok(None);
    }
    Ok(Some(ReceivedHomeClaimVector {
        peer: rpc.home,
        vector,
    }))
}
