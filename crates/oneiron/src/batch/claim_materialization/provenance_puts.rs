//! The edge provenance writer's claim puts (`crate::provenance::writes`).

use super::{
    ApplyOpsGateMode, BatchOp, ClaimMaterialization, apply_owner_bound_claim_puts_in_mode,
};
use crate::Vault;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::error::Result;

/// [`super::apply_owner_bound_claim_puts`] for the edge provenance writer.
/// `restore_permit` is the owner's restore permit when a whole-vault import
/// is that restore: the batch then judges each put's claim under the permit
/// bound to the put's own annotator, as the writer's own precheck judged it
/// (REVIEW-9687 round 2 P1; Engine ANSWER
/// PROVENANCE-RESTORE-UNDER-TRUSTED-MANIFEST = A). Without it the batch
/// judges every put under the vault's manifest alone, as before.
pub(crate) fn apply_provenance_claim_puts(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ops: Vec<BatchOp>,
    bindings: Vec<ClaimMaterialization>,
    restore_permit: Option<&OwnerArchiveRestorePermit>,
) -> Result<()> {
    let Some(permit) = restore_permit else {
        return super::apply_owner_bound_claim_puts(vault, txn, ops, bindings, true);
    };
    let annotators = bindings
        .iter()
        .map(|binding| binding.envelope.actor().entity_ref())
        .collect();
    let gate_mode = ApplyOpsGateMode::new(false, true)
        .with_owner_archive_restore_for_annotators(permit, annotators);
    apply_owner_bound_claim_puts_in_mode(vault, txn, ops, bindings, gate_mode)
}
