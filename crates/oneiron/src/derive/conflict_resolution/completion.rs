//! The replacement grants and conflict closes after every output has landed.

use super::super::commit::ItemContext;
use super::LandedOutput;
use crate::dreamer_consolidation::resources::ConsolidationFence;
use crate::dreamer_promotion::{
    CloseConflictsRequest, DreamerRunContext, close_conflicts_naming_in_txn,
    grant_allowed_replacement_in_txn,
};
use crate::error::Result;
use crate::{EntityId, Vault};

/// Grants landed replacements and closes their open conflicts inside the
/// caller's item savepoint. Grant receipts stay queued for post-commit metrics.
pub(super) fn grant_and_close_in_txn<'txn>(
    vault: &Vault,
    mut savepoint: heed::RwTxn<'txn>,
    context: &ItemContext<'_>,
    run: DreamerRunContext,
    fence: ConsolidationFence,
    provenance: rmpv::Value,
    mut landed: Vec<LandedOutput>,
) -> Result<(heed::RwTxn<'txn>, Vec<LandedOutput>)> {
    let mut granted: Vec<(EntityId, EntityId, Vec<EntityId>)> = Vec::new();
    for output in &mut landed {
        if output.approval != crate::claim::ClaimApprovalStatus::Proposed || output.prior.is_none()
        {
            continue;
        }
        let (closed, receipts) =
            grant_allowed_replacement_in_txn(vault, &mut savepoint, &run, &fence, output.claim)?;
        context.grant_receipts.borrow_mut().extend(receipts);
        if let Some(prior_closed) = closed {
            output.approval = crate::claim::ClaimApprovalStatus::Auto;
            granted.push((
                output.claim,
                prior_closed,
                std::mem::take(&mut output.evidence),
            ));
        }
    }
    for (replacement, prior, evidence_refs) in &granted {
        let request = CloseConflictsRequest {
            run: &run,
            fence: &fence,
            replacement: *replacement,
            prior: *prior,
            evidence: evidence_refs,
            provenance: provenance.clone(),
        };
        close_conflicts_naming_in_txn(vault, &mut savepoint, &request)?;
    }
    Ok((savepoint, landed))
}
