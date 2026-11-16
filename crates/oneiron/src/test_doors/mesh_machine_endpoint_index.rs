//! Doors for `tests/mesh_machine_endpoint_index.rs` (census L3-28B): the
//! endpoint lookup as the MACHINE endpoint index answers it and as the walk
//! of every MACHINE row answers it, and the index's drop and completeness
//! flag.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// How the endpoint index answers one lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexedEndpoint {
    /// The index cannot serve it: the lookup walks every MACHINE row.
    Walk,
    /// Two MACHINE rows name the key: the lookup refuses, as the walk does.
    Refused,
    /// The MACHINE that names the key, or `None` when none does.
    Found(Option<EntityId>),
}

/// The MACHINE naming endpoint `key` as the index answers.
pub fn indexed_machine(vault: &Vault, key: [u8; 32]) -> Result<IndexedEndpoint> {
    let answer = match vault.indexed_mesh_machine_by_endpoint_for_test(key)? {
        None => IndexedEndpoint::Walk,
        Some(Err(_)) => IndexedEndpoint::Refused,
        Some(Ok(found)) => IndexedEndpoint::Found(found),
    };
    Ok(answer)
}

/// The MACHINE naming endpoint `key` as the walk of every MACHINE row
/// answers, bounded as a stranger's lookup is; `Err` when two name it.
pub fn walked_machine(vault: &Vault, key: [u8; 32]) -> Result<Option<EntityId>> {
    vault.walked_mesh_machine_by_endpoint_for_test(key)
}

/// Drops the index and its completeness flag, as a vault older than the
/// index holds them.
pub fn drop_index(vault: &Vault) -> Result<()> {
    vault.drop_mesh_machine_endpoint_index_for_test()
}

/// Whether the index is complete.
pub fn index_complete(vault: &Vault) -> Result<bool> {
    vault.mesh_machine_endpoint_index_complete_for_test()
}

/// Every `(endpoint key, MACHINE id)` row the index holds.
pub fn index_rows(vault: &Vault) -> Result<Vec<([u8; 32], EntityId)>> {
    vault.mesh_machine_endpoint_index_rows_for_test()
}
