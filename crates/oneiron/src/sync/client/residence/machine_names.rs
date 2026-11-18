//! This machine's machine-name cells to its residence home, and the home's to it, once each
//! steady pass (FIX [DEVICE-DISPLAY-NAME]; Engine RULING MACHINE-NAMES-CARRIER = B).

use serde_json::{Value, json};

use super::{ResidenceRpc, residence_budgets};
use crate::Vault;
use crate::machine_names::MachineNameCell;
use crate::sync::TransportError;
use crate::sync::client::SyncClientConfig;

/// Sends the home the cells this machine wrote and takes every cell the home holds. Own
/// residence only: a federation peer is not asked, nor is the home while this install serves no
/// machine of the fold. A home that refuses the call (an older one answers an unknown method)
/// changes nothing here, and the next pass sends the same cells again. A cell this machine
/// cannot read (a kind a later version adds) is left out. Returns how many cells changed here.
///
/// # Errors
///
/// A home out of reach, an answer without its cells, storage errors.
pub(crate) async fn exchange_machine_names(
    vault: &Vault,
    config: &SyncClientConfig,
) -> Result<usize, TransportError> {
    if config.federation_peer.is_some() {
        return Ok(0);
    }
    let Some(cells) = vault.machine_name_cells_written_here().map_err(storage)? else {
        return Ok(0);
    };
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Err(TransportError::home_offline());
    };
    let Ok(reply) = rpc
        .call(
            "residence.machine_names.exchange",
            json!({ "cells": cells }),
        )
        .await?
    else {
        tracing::debug!("the residence home refused the machine name exchange");
        return Ok(0);
    };
    let held = reply
        .get("cells")
        .and_then(Value::as_array)
        .ok_or_else(|| TransportError::InvalidPayload("machine name cells missing"))?
        .iter()
        .filter_map(|cell| serde_json::from_value::<MachineNameCell>(cell.clone()).ok())
        .collect();
    vault.take_machine_name_cells(held).map_err(storage)
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}
