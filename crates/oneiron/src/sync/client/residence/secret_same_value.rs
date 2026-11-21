//! This machine's same-value statement to its residence home, and the home's statements to it,
//! once each steady pass (FIX [SECRETS-SAME-VALUE-FACT]; Engine RULINGS SECRETS-LIST-DUP-GROUPING
//! = A and SECRET-SAMEFACT-HOST-SEES = B).

use serde_json::{Value, json};

use super::{ResidenceRpc, residence_budgets};
use crate::Vault;
use crate::secret_custody::SameValueStatement;
use crate::sync::TransportError;
use crate::sync::client::SyncClientConfig;

/// Sends the home this machine's statement, if it has one, first brought up to the pairs it proves
/// now, and takes every statement the home holds. Own residence only: a federation peer is not
/// asked, nor is the home while this install serves no machine of the fold. A home that refuses
/// the call (an older one answers an unknown method) changes nothing here, and the next pass sends
/// the statement again. A statement this machine cannot read is left out. Returns how many
/// statements changed here.
///
/// # Errors
///
/// A home out of reach, an answer without its statements, storage errors.
pub(crate) async fn exchange_secret_same_value(
    vault: &Vault,
    config: &SyncClientConfig,
) -> Result<usize, TransportError> {
    if config.federation_peer.is_some() {
        return Ok(0);
    }
    let Some(statements) = vault
        .same_value_statements_written_here()
        .map_err(storage)?
    else {
        return Ok(0);
    };
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Err(TransportError::home_offline());
    };
    let Ok(reply) = rpc
        .call(
            "residence.secret_same_value.exchange",
            json!({ "statements": statements }),
        )
        .await?
    else {
        tracing::debug!("the residence home refused the same-value exchange");
        return Ok(0);
    };
    let held = reply
        .get("statements")
        .and_then(Value::as_array)
        .ok_or_else(|| TransportError::InvalidPayload("same-value statements missing"))?
        .iter()
        .filter_map(|held| serde_json::from_value::<SameValueStatement>(held.clone()).ok())
        .collect();
    vault.take_same_value_statements(held).map_err(storage)
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}
