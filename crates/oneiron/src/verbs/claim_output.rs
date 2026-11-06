//! Move native claim payloads through the core SDK result boundary.

use serde_json::Value;

use crate::claim::ScopedReadResult;
use crate::memory::{
    ClaimProposalReview, ClaimSettlement, ClaimView, CoachInspectionView, MemoryResult,
    SignalExtractionResult,
};

use super::encode;

type ClaimPayload = (Value, Option<Value>);

pub(super) fn review(mut output: ClaimProposalReview) -> MemoryResult<Value> {
    let payload = take_claim(&mut output.claim);
    let mut encoded = encode(output)?;
    restore_claim(&mut encoded["claim"], payload);
    Ok(encoded)
}

pub(super) fn settlement(mut output: ClaimSettlement) -> MemoryResult<Value> {
    let payload = take_claim(&mut output.claim);
    let mut encoded = encode(output)?;
    restore_claim(&mut encoded["claim"], payload);
    Ok(encoded)
}

pub(super) fn list(mut output: ScopedReadResult<Vec<ClaimView>>) -> MemoryResult<Value> {
    let payloads: Vec<_> = output.value.iter_mut().map(take_claim).collect();
    let mut encoded = encode(output)?;
    for (index, payload) in payloads.into_iter().enumerate() {
        restore_claim(&mut encoded["value"][index], payload);
    }
    Ok(encoded)
}

pub(super) fn read(mut output: ScopedReadResult<Option<ClaimView>>) -> MemoryResult<Value> {
    let payload = output.value.as_mut().map(take_claim);
    let mut encoded = encode(output)?;
    if let Some(payload) = payload {
        restore_claim(&mut encoded["value"], payload);
    }
    Ok(encoded)
}

pub(super) fn extraction(mut output: Option<SignalExtractionResult>) -> MemoryResult<Value> {
    let payloads: Vec<_> = output
        .iter_mut()
        .flat_map(|result| result.claims.iter_mut())
        .map(|entry| take_claim(&mut entry.claim))
        .collect();
    let mut encoded = encode(output)?;
    for (index, payload) in payloads.into_iter().enumerate() {
        restore_claim(&mut encoded["claims"][index]["claim"], payload);
    }
    Ok(encoded)
}

pub(super) fn coach(mut output: ScopedReadResult<CoachInspectionView>) -> MemoryResult<Value> {
    let payload = output.value.proposal.as_mut().map(|proposal| {
        (
            take_claim(&mut proposal.claim),
            proposal.repair.as_mut().map(Value::take),
        )
    });
    let mut encoded = encode(output)?;
    if let Some((claim, repair)) = payload {
        let proposal = &mut encoded["value"]["proposal"];
        restore_claim(&mut proposal["claim"], claim);
        if let Some(repair) = repair {
            proposal["repair"] = repair;
        }
    }
    Ok(encoded)
}

fn take_claim(claim: &mut ClaimView) -> ClaimPayload {
    (claim.value.take(), claim.scope.take())
}

fn restore_claim(encoded: &mut Value, (value, scope): ClaimPayload) {
    encoded["value"] = value;
    if let Some(scope) = scope {
        encoded["scope"] = scope;
    }
}
