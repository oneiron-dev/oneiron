//! Door for `tests/connector_key_suspend_admission.rs` (FIX 22392): the
//! shared suspend writer, as a budget exhaustion calls it.

use crate::Vault;
use crate::connector_key::{
    ConnectorKeyRecord, EffectorBudgetLocation, EffectorBudgetRowId, EffectorBudgetRowSource,
    SuspendCause, suspend_connector_key_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Suspends `id`'s key in a write transaction of its own, as an exhausted
/// `on_exhaust: Suspend` row (the key's row 0) does: the record the writer
/// wrote, or an error when it wrote nothing.
///
/// # Errors
///
/// No such key; the writer refused the key's from-state; storage errors.
pub fn suspend_on_budget_exhaustion(
    vault: &Vault,
    id: &EntityId,
    at: u64,
) -> Result<ConnectorKeyRecord> {
    let record = vault.get_connector_key(id)?.ok_or(Error::EntityNotFound)?;
    let location = EffectorBudgetLocation {
        key_ref: *id,
        row: EffectorBudgetRowId {
            source: EffectorBudgetRowSource::Key,
            index: 0,
        },
    };
    let mut wtxn = vault.store.env.write_txn()?;
    let suspended = suspend_connector_key_in_txn(
        &vault.store,
        &mut wtxn,
        id,
        &record,
        SuspendCause::BudgetExhausted(&location),
        at,
    )?
    .into_suspended()?;
    wtxn.commit()?;
    Ok(suspended)
}
