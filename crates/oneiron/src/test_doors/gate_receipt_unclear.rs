//! Door for `tests/gate_receipt_unclear_record_removal.rs`: the write of the
//! owner's discard of a world copy that takes the Gate decisions of the
//! claims its windows' writes removed to their retention skeletons, run on a
//! set of claims without a world fixture, the Coach's filing of a label
//! proposal that quotes an amendment's unclear note, and the signed history
//! controls of a MACHINE claim.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Runs the bundle write `discard_world_copy_as` runs once its windows'
/// writes took `claims`: each Gate decision bound to one of them, or citing
/// only them, becomes its retention skeleton, and the unclear row filed
/// under its receipt goes, local only.
pub fn discard_claims_gate_payload(vault: &Vault, claims: &BTreeSet<EntityId>) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        crate::store::local_replica::discard_bundle_payload_in_txn(&vault.store, wtxn, claims)
    })
}

/// Files `proposal`, a claim waiting on its owner, as the Coach's label
/// proposal for a pattern whose filing quotes the amendment note under the
/// receipt `receipt` (`gate:<hex>`), as the clustering pass records a filing.
pub fn file_label_proposal(vault: &Vault, receipt: &str, proposal: EntityId) -> Result<()> {
    let outcome = crate::skill_attribution::unclear_key(
        crate::skill_attribution::AttributionLane::Amendment,
        receipt,
    );
    crate::dreamer_runner::maintenance::attribution_labels::file_label_proposal_for_test(
        vault, &outcome, proposal,
    )
}

/// The signed history controls of the MACHINE claim `target`, in its index:
/// its birth and each later transition.
pub fn machine_history_controls(vault: &Vault, target: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::claim::history_store::machine_history_ids_for_target(&vault.store, &txn, target)
}
