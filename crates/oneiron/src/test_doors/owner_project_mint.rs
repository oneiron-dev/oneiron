//! Door for `tests/project_owner_mint.rs` (FIX [OWNER-PROJECT-MINT-DOOR]):
//! whether one project's owner mint row is still stored, so the test sees
//! the row, and the name in it, leave with its project.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{Named, SideTable};

/// The owner mint rows by their declared table, as
/// `workspace_roster::project::owner_mint` binds them; the value is never
/// decoded here.
const OWNER_MINTS: SideTable<EntityId, serde_json::Value, Named> =
    SideTable::new(&crate::side_table::PROJECT_OWNER_MINT);

/// Whether `project`'s owner mint row is stored.
///
/// # Errors
///
/// The vault's.
pub fn mint_row_stored(vault: &Vault, project: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    OWNER_MINTS.contains(&vault.store, &txn, &project)
}
