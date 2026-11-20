//! Doors for `tests/companion_grant_index.rs` (census L3-28E): the grants
//! the companion grant index names for one principal and PERSON, the
//! index's drop, rebuild and completeness flag, and an undecodable grant
//! row stored past the write door's validation.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The grant ids the index names for `principal` and `person`, in grant id
/// order: `None` when the companion grant reads would walk every grant.
pub fn indexed_grants(
    vault: &Vault,
    principal: &EntityId,
    person: &EntityId,
) -> Result<Option<Vec<EntityId>>> {
    vault.indexed_companion_grant_ids_for_test(principal, person)
}

/// Drops the index, its undecodable rows and its completeness flag, as a
/// vault older than the index holds them.
pub fn drop_index(vault: &Vault) -> Result<()> {
    vault.drop_companion_grant_index_for_test()
}

/// Rebuilds the index from the ACCESS_GRANT rows, as a checkpoint restore
/// does.
pub fn rebuild_index(vault: &Vault) -> Result<()> {
    vault.backfill_companion_grant_index(true)
}

/// Whether the index is complete.
pub fn index_complete(vault: &Vault) -> Result<bool> {
    vault.companion_grant_index_complete_for_test()
}

/// Every `(principal, PERSON, grant)` row the index holds.
pub fn index_rows(vault: &Vault) -> Result<Vec<(EntityId, EntityId, EntityId)>> {
    vault.companion_grant_index_rows_for_test()
}

/// Stores `body` as the ACCESS_GRANT row `id` past the write door's
/// validation, through the body stage's index writer.
pub fn put_undecodable_grant(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    vault.put_undecodable_access_grant_for_test(id, body)
}
