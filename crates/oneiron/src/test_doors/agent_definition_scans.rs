//! The two scans that walk every agent definition by its wake cadence, for
//! the proposed-change tests: the agents a surprise wakes, and the vault's
//! companions.

use crate::{EntityId, Result, Vault};

/// The agents a re-tag that measured `surprise` wakes
/// (`Vault::surprise_wakeable_agents`).
///
/// # Errors
/// The scan's.
#[doc(hidden)]
pub fn surprise_wakeable_agents(vault: &Vault, surprise: f32) -> Result<Vec<EntityId>> {
    vault.surprise_wakeable_agents(surprise)
}

/// The vault's companion agents, in id order (`Vault::companion_agents_in`).
///
/// # Errors
/// The scan's.
#[doc(hidden)]
pub fn companion_agents(vault: &Vault) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    vault.companion_agents_in(&txn)
}
