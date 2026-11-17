//! The live agent Grants naming one holder, for the failed-mint test: a
//! `token agent` mint that fails after its link keeps none of them.

use crate::{EntityId, Result, Vault};

/// The live agent Grants naming `holder`, in id order
/// (`Vault::agent_grants_reporting_in_txn`, decoded rows only).
///
/// # Errors
/// The scan's.
#[doc(hidden)]
pub fn live_agent_grants_for_holder(vault: &Vault, holder: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let (standings, _) = vault.agent_grants_reporting_in_txn(&txn)?;
    Ok(standings
        .into_iter()
        .filter(|standing| standing.grant.member_ref == holder)
        .map(|standing| standing.id)
        .collect())
}
