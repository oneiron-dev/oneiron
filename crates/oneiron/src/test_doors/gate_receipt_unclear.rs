//! Door for `tests/gate_receipt_unclear_record_removal.rs`: the write of the
//! owner's discard of a world copy that takes the Gate decisions of the
//! claims its windows' writes removed to their retention skeletons, run on a
//! set of claims without a world fixture.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Runs the bundle write `discard_world_copy_as` runs once its windows'
/// writes took `claims`: each Gate decision bound to one of them, or citing
/// only them, becomes its retention skeleton.
pub fn discard_claims_gate_payload(vault: &Vault, claims: &BTreeSet<EntityId>) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        crate::store::local_replica::discard_bundle_payload_in_txn(&vault.store, wtxn, claims)
    })
}
