//! A witnessed MESSAGE's place, for the tests that check a record derived
//! from its words is born there (FIX INTENT-DISTINCT-PROJECT-WORLD).

use crate::{EntityId, Result, Vault};

/// Settles each witnessed TURN or MESSAGE of `records` into `project`, as the
/// leader-chat door settles a project's turn
/// (`federation::record_scope::stamp_leader_project`).
///
/// # Errors
///
/// The vault's, or a record that is no TURN or MESSAGE or that another
/// project already holds.
pub fn settle_into_project(vault: &Vault, records: &[EntityId], project: EntityId) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        for id in records {
            crate::federation::record_scope::stamp_leader_project(&vault.store, txn, *id, project)?;
        }
        Ok(())
    })
}
