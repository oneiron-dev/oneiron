//! FIX 10176: a settlement measures the proposal it names, never a document
//! minted for it.

use super::{ProposalDeltaSettleRequest, settlement_receipt};
use crate::Vault;
use crate::edit_distance::delta::{
    AmendmentDelta, DeltaCaptureContext, DeltaSource, EndpointRef, MeasuredEnd, capture_delta_best,
};
use crate::edit_distance::{
    LoroOpRef, OpAttribution, ProposalArtifactRef, RetainedProposal, TextRead, retained_proposal,
};
use crate::error::Result;

/// What one settlement measured: the receipt it rides, the original artifact
/// when the request names one the vault holds, and the Δ.
pub(super) struct SettledWindow {
    pub(super) receipt_id: String,
    pub(super) artifact: Option<RetainedProposal>,
    /// `None` when no lane measured the window.
    pub(super) delta: Option<AmendmentDelta>,
}

/// Measures a settlement through [`capture_delta_best`].
///
/// The named artifact's recorded window measures it when that window is this
/// edit: its proposed and final texts are the settled endpoints. Otherwise the
/// endpoints were edited outside the recorded window (an imported,
/// endpoint-only edit) and are measured as `reconstructed` (ARCH-0056 §3,
/// ruling r2). An end the artifact holds is named there; an imported end is
/// named on the settlement receipt beside its content hash.
///
/// # Errors
///
/// Storage errors.
pub(super) fn settle_window(
    vault: &Vault,
    input: &ProposalDeltaSettleRequest,
    expected_final: &str,
) -> Result<SettledWindow> {
    let original = match input.artifact_ref {
        Some(id) => retained_proposal(vault, ProposalArtifactRef::new(id))?,
        None => None,
    };
    let subject = match &original {
        Some(original) => original.record.artifact_ref.entity_id(),
        None => vault.new_entity_id()?,
    };
    let receipt_id = settlement_receipt(subject);
    let proposed_at = original.as_ref().and_then(|original| {
        held_end(
            original,
            original.proposed_text(),
            &original.record.proposed_ref,
            &input.proposed_text,
        )
    });
    let final_at = original.as_ref().and_then(|original| {
        held_end(
            original,
            original.final_text(),
            &original.record.final_ref,
            expected_final,
        )
    });
    let recorded = original
        .as_ref()
        .filter(|_| proposed_at.is_some() && final_at.is_some());
    let context = DeltaCaptureContext {
        recorded,
        bodies: None,
        texts: Some((
            MeasuredEnd {
                at: proposed_at.unwrap_or_else(|| EndpointRef::receipt(&receipt_id)),
                content: input.proposed_text.as_str(),
            },
            MeasuredEnd {
                at: final_at.unwrap_or_else(|| EndpointRef::receipt(&receipt_id)),
                content: expected_final,
            },
        )),
    };
    let delta = capture_delta_best(context).ok();
    Ok(SettledWindow {
        receipt_id,
        artifact: original,
        delta,
    })
}

/// The artifact version that holds `settled` as this end of its window.
fn held_end(
    original: &RetainedProposal,
    read: TextRead,
    frontier: &LoroOpRef,
    settled: &str,
) -> Option<EndpointRef> {
    (read.into_text().as_deref() == Some(settled))
        .then(|| EndpointRef::proposal(original.record.artifact_ref, frontier))
}

/// The attribution every recorded change of a recorded-ops window carries,
/// which is then every hunk's; `None` for a reconstructed Δ or a window of
/// more than one attribution, where no hunk maps onto one change.
pub(super) fn sole_attribution(window: &SettledWindow) -> Option<OpAttribution> {
    if window.delta.as_ref()?.source != DeltaSource::RecordedOps {
        return None;
    }
    let mut changes = window
        .artifact
        .as_ref()?
        .record
        .ops_by_actor
        .iter()
        .map(|(attribution, _)| *attribution);
    let first = changes.next()?;
    changes
        .all(|attribution| attribution == first)
        .then_some(first)
}
