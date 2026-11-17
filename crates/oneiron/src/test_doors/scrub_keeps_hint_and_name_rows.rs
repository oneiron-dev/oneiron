//! Doors for `tests/scrub_keeps_hint_and_name_rows.rs`: the raw identity
//! hint and named-entity index rows, which the public lookups verify away
//! against the stored record and so cannot show as stale.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Every `(kind, hint digest, entity)` row the identity hint index holds.
pub fn identity_hint_rows(vault: &Vault) -> Result<Vec<([u8; 1], [u8; 32], EntityId)>> {
    vault.identity_hint_index_rows_for_test()
}

/// Every named-entity index row's full `named_entity:v1:` key.
pub fn named_entity_rows(vault: &Vault) -> Result<Vec<Vec<u8>>> {
    vault.named_entity_index_rows_for_test()
}
