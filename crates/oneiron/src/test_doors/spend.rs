//! Spend scopes for integration tests (primitive D, slice 6.5a: the run's own
//! actor reads its own scope tree through `vault.budgets.lease`).

use crate::agent_dispatch::{AgentDispatcher, ChildSpend, SpendScope, SpendScopeId};
use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::vault::Vault;

/// Reserves `child`'s spend scope under `parent` as a hard carve of
/// `cap_units`, as a spawn that pins a budget does, and commits it.
///
/// # Errors
///
/// A carve the nearest hard ancestor cannot cover, a scope already reserved,
/// and the vault's.
pub fn reserve_child_scope(
    vault: &Vault,
    parent: &SpendScopeId,
    child: &AttemptId,
    cap_units: u64,
    now: u64,
) -> Result<SpendScope> {
    let mut txn = vault.store.env.write_txn()?;
    let scope = AgentDispatcher::new(vault).reserve_child_in_txn(
        &mut txn,
        parent,
        child,
        ChildSpend::Carve { cap_units },
        now,
    )?;
    txn.commit()?;
    Ok(scope)
}
