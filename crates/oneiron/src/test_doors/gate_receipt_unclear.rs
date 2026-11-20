//! Door for `tests/gate_receipt_unclear_record_removal.rs`: the write of the
//! owner's discard of a world copy that takes the Gate decisions of the
//! claims its windows' writes removed to their retention skeletons, run on a
//! set of claims without a world fixture, and the Coach's filing of a label
//! proposal that quotes an amendment's unclear note.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Runs the bundle write `discard_world_copy_as` runs once its windows'
/// writes took `claims`: each Gate decision bound to one of them, or citing
/// only them, becomes its retention skeleton, and the unclear row filed
/// under its receipt goes.
pub fn discard_claims_gate_payload(vault: &Vault, claims: &BTreeSet<EntityId>) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        crate::sync::residence::discard_bundle_payload_and_unclear_in_txn(vault, wtxn, claims)
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
