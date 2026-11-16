//! `residence.secret_same_value.exchange`: this home as the meeting point of its owner's machines'
//! same-value statements (FIX [SECRETS-SAME-VALUE-FACT]; Engine RULINGS
//! SECRETS-LIST-DUP-GROUPING = A and SECRET-SAMEFACT-HOST-SEES = B). A machine sends the statement
//! it signed and takes every statement the home holds: writer ids, times and sealed bytes the home
//! never opens. A refused call looks missing.

use oneiron::authority::PeerMachine;
use oneiron::secret_custody::SameValueStatement;
use oneiron::sync::residence::secret_same_value_residence_exchange;
use serde_json::{Value, json};

use super::{Answer, AppError, CoreAuth, CoreScope};
use crate::server::SyncServer;

/// Keeps the statements `peer` signed and answers every statement this home holds. A statement this
/// home cannot read (a shape a later version adds) is left out, so the caller's others still land.
pub(super) fn exchange(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    params: Value,
) -> Result<Answer, AppError> {
    auth.require(CoreScope::Write)?;
    let statements = params
        .get("statements")
        .and_then(Value::as_array)
        .ok_or_else(AppError::invalid_params)?
        .iter()
        .filter_map(|statement| {
            serde_json::from_value::<SameValueStatement>(statement.clone()).ok()
        })
        .collect();
    let held = secret_same_value_residence_exchange(&server.vault, peer, statements)
        .map_err(|_| AppError::not_found("same-value statements", None))?;
    Ok((json!({ "statements": held }), Some(Vec::new())))
}
