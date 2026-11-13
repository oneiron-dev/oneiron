//! Spend scopes for integration tests (primitive D, slice 6.5a: the run's own
//! actor reads its own scope tree through `vault.budgets.lease`; row B1 of
//! BUDGET-TRAP-UNTYPED-NO-SENDER: a scope's ceiling refuses a step typed;
//! LIVE-RUN-PAYER-REQUIRED: an actor erase clears a root's payer while a run
//! still holds its lease).

use crate::agent_dispatch::{AgentDispatcher, ChildSpend, SpendScope, SpendScopeId};
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
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

/// Sets `scope`'s ceiling to `ceiling_units`, as a launch that states a token
/// ceiling does, and commits it.
///
/// # Errors
///
/// A scope that is missing, and the vault's.
pub fn set_scope_ceiling(
    vault: &Vault,
    scope: &SpendScopeId,
    ceiling_units: u64,
) -> Result<SpendScope> {
    let mut txn = vault.store.env.write_txn()?;
    let scope =
        AgentDispatcher::new(vault).set_scope_ceiling_in_txn(&mut txn, scope, ceiling_units)?;
    txn.commit()?;
    Ok(scope)
}

/// Forgets `actor` in every spend scope, as the spend-scope table's hook in
/// an actor erase does in that erase's transaction (FIX 11777): a root whose
/// payer `actor` is names no payer after it. Commits it.
///
/// # Errors
///
/// The vault's.
pub fn erase_actor_from_spend_scopes(vault: &Vault, actor: &EntityId) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::agent_dispatch::erase_spend_scope_actor_in_txn(vault, &mut txn, actor)?;
    txn.commit()?;
    Ok(())
}
