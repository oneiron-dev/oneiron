//! The replacement grants and conflict closes after every output has landed.

use std::collections::BTreeMap;

use super::super::commit::ItemContext;
use super::LandedOutput;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, PREDICATE_CONFLICT_OPEN};
use crate::dreamer_consolidation::evidence::ResolvedConflictOutput;
use crate::dreamer_consolidation::resources::ConsolidationFence;
use crate::dreamer_promotion::{
    CloseConflictsRequest, CloseMarkerRequest, DreamerRunContext, ResolvedClose,
    close_conflicts_naming_in_txn, close_marker_in_txn, grant_allowed_replacement_in_txn,
    resolved_close_in_txn,
};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// The completed item's context, landed outputs and close inputs. The marker
/// belongs to the original rebuilt set, before a kept merge changes identity.
pub(super) struct CompletionRequest<'a> {
    pub(super) context: &'a ItemContext<'a>,
    pub(super) run: DreamerRunContext,
    pub(super) fence: ConsolidationFence,
    pub(super) provenance: rmpv::Value,
    pub(super) landed: Vec<LandedOutput>,
    pub(super) marker: EntityId,
    pub(super) resolution: &'static str,
}

/// Grants landed replacements and closes their open conflicts inside the
/// caller's item savepoint, then closes the first try's marker. Grant receipts
/// stay queued for post-commit metrics; neither close records an output.
pub(super) fn grant_and_close_in_txn<'txn>(
    vault: &Vault,
    mut savepoint: heed::RwTxn<'txn>,
    mut request: CompletionRequest<'_>,
) -> Result<(heed::RwTxn<'txn>, Vec<LandedOutput>)> {
    let mut granted: Vec<(EntityId, EntityId, Vec<EntityId>)> = Vec::new();
    for output in &mut request.landed {
        if output.approval != ClaimApprovalStatus::Proposed || output.prior.is_none() {
            continue;
        }
        let (closed, receipts) = grant_allowed_replacement_in_txn(
            vault,
            &mut savepoint,
            &request.run,
            &request.fence,
            output.claim,
        )?;
        request.context.grant_receipts.borrow_mut().extend(receipts);
        if let Some(prior_closed) = closed {
            output.approval = ClaimApprovalStatus::Auto;
            granted.push((output.claim, prior_closed, output.evidence.clone()));
        }
    }
    for (replacement, prior, evidence_refs) in &granted {
        let close = CloseConflictsRequest {
            run: &request.run,
            fence: &request.fence,
            replacement: *replacement,
            prior: *prior,
            evidence: evidence_refs,
            provenance: request.provenance.clone(),
        };
        close_conflicts_naming_in_txn(vault, &mut savepoint, &close)?;
    }
    close_first_try_in_txn(vault, &mut savepoint, &request)?;
    Ok((savepoint, request.landed))
}

/// Binds only an eligible first-try marker, as native does, and closes it only
/// when at least one output landed and all outputs are Auto after grants.
/// Read/domain refusals leave the item intact; a store error aborts the commit.
fn close_first_try_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &CompletionRequest<'_>,
) -> Result<()> {
    if request.landed.is_empty()
        || request
            .landed
            .iter()
            .any(|output| output.approval != ClaimApprovalStatus::Auto)
    {
        return Ok(());
    }
    let inputs = (|| -> Result<ResolvedClose> {
        let Some(marker) = vault.get_claim_in_txn(txn, &request.marker)? else {
            return Ok(ResolvedClose::Nothing);
        };
        if marker.predicate != PREDICATE_CONFLICT_OPEN
            || marker.lifecycle != ClaimLifecycleStatus::Active
            || marker.approval == ClaimApprovalStatus::Rejected
        {
            return Ok(ResolvedClose::Nothing);
        }
        let answer = ResolvedConflictOutput {
            marker: request.marker,
            outputs: request.landed.iter().map(|output| output.claim).collect(),
            resolution: request.resolution.to_owned(),
        };
        let stood: BTreeMap<EntityId, Vec<EntityId>> = request
            .landed
            .iter()
            .map(|output| (output.claim, output.evidence.clone()))
            .collect();
        resolved_close_in_txn(vault, txn, &answer, &stood)
    })();
    let inputs = match inputs {
        Ok(ResolvedClose::Nothing) => return Ok(()),
        Ok(ResolvedClose::Refused(reason)) => {
            tracing::warn!(reason, marker = %request.marker.to_hex(), "an open conflict a retried try answered stayed open");
            return Ok(());
        }
        Ok(ResolvedClose::Ready(inputs)) => inputs,
        Err(error @ (Error::Gate(_) | Error::Claim(_) | Error::InvalidClaimBody(_))) => {
            tracing::warn!(reason = "close_read_failed", error_kind = ?error.kind(), marker = %request.marker.to_hex(), "an open conflict a retried try answered stayed open");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    for (output, revision) in inputs.outputs {
        request.fence.relies_on(output, revision);
    }
    let close = close_marker_in_txn(
        vault,
        txn,
        &CloseMarkerRequest {
            run: &request.run,
            fence: &request.fence,
            marker: request.marker,
            resolution: inputs.resolution,
            evidence: &inputs.evidence,
            provenance: request.provenance.clone(),
            log_message: "an open conflict a retried try answered stayed open",
        },
    );
    for output in &request.landed {
        request.fence.released(output.claim);
    }
    close.map_err(|failure| failure.error)?;
    Ok(())
}
