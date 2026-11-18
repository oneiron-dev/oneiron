//! `residence.machine_names.exchange`: this home as the meeting point of its owner's machines'
//! machine-name cells (FIX [DEVICE-DISPLAY-NAME]; Engine RULING MACHINE-NAMES-CARRIER = B). A
//! machine sends the cells it wrote and takes every cell the home holds: display text, dates and
//! machine ids. A refused call looks missing.

use oneiron::authority::PeerMachine;
use oneiron::machine_names::MachineNameCell;
use oneiron::sync::residence::machine_names_residence_exchange;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, CoreScope};
use crate::server::SyncServer;

/// Keeps the cells `peer` wrote and answers every cell this home holds. A cell this home cannot
/// read (a kind a later version adds) is left out, so the caller's other cells still land.
pub(super) fn exchange(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    auth.require(CoreScope::Write)?;
    let cells = params
        .get("cells")
        .and_then(Value::as_array)
        .ok_or_else(AppError::invalid_params)?
        .iter()
        .filter_map(|cell| serde_json::from_value::<MachineNameCell>(cell.clone()).ok())
        .collect();
    let held = machine_names_residence_exchange(&server.vault, peer, cells)
        .map_err(|_| AppError::not_found("machine names", None))?;
    Ok((json!({ "cells": held }), Some(Vec::new())))
}
