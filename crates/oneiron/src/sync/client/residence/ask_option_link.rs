//! A bearer call to its issuing install, not the current residence home.

use std::sync::Arc;

use crate::sync::ask_option_link::{AskOptionLinkReply, AskOptionLinkRequest};
use crate::sync::transport::TransportError;
use crate::{EntityId, Vault};

use super::super::types::SyncClientConfig;
use super::rpc::{ResidenceRpc, residence_budgets};

/// Routes to the issuing install using a host-supplied origin endpoint/carrier.
/// The mesh host pins its dialer to `admitting_machine`; a URL host supplies
/// that install's URL. A changed elected home never substitutes for it.
///
/// `None` is an outage. The reply keeps the original typed bearer result.
/// A failed call is not evidence that an answer or void did not commit, and
/// this function never retries it. Existing residence RPC byte limits apply.
pub async fn request_ask_option_link(
    vault: Arc<Vault>,
    config: &SyncClientConfig,
    admitting_machine: EntityId,
    request: AskOptionLinkRequest,
) -> Result<Option<AskOptionLinkReply>, TransportError> {
    let local = {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        crate::store::install_identity::read_machine_id_in_txn(&vault, &txn)
            .map_err(|error| TransportError::Storage(error.to_string()))?
    };
    if local == Some(admitting_machine) {
        return tokio::task::spawn_blocking(move || request.execute(&vault))
            .await
            .map(Some)
            .map_err(|error| TransportError::Storage(error.to_string()));
    }
    let mut origin = config.clone();
    origin.residence_home_route = None;
    let budgets = residence_budgets(&vault)?;
    let Some(mut rpc) = ResidenceRpc::connect_machine(&vault, &origin, budgets).await? else {
        return Ok(None);
    };
    // The RPC's actual ready/start_send rejudges the exact issuing machine.
    let params = serde_json::to_value(&request)
        .map_err(|_| TransportError::InvalidPayload("invalid option link request"))?;
    let reply = rpc
        .request_for_machine(
            &vault,
            admitting_machine,
            "residence.ask.option_link",
            params,
        )
        .await?;
    let reply: AskOptionLinkReply = serde_json::from_value(reply)
        .map_err(|_| TransportError::InvalidPayload("invalid option link reply"))?;
    if !matches!(
        (&request, &reply),
        (
            AskOptionLinkRequest::View { .. },
            AskOptionLinkReply::View(_)
        ) | (
            AskOptionLinkRequest::Answer { .. },
            AskOptionLinkReply::Answer(_)
        ) | (
            AskOptionLinkRequest::Void { .. },
            AskOptionLinkReply::Void(_)
        )
    ) {
        return Err(TransportError::InvalidPayload(
            "option link reply operation differs",
        ));
    }
    Ok(Some(reply))
}
