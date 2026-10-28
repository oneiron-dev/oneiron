//! FIX 10176: a settlement measures the proposal it names, never a document
//! minted for it.

use super::{ProposalDeltaSettleRequest, ProposalReplacement, settlement_receipt};
use crate::Vault;
use crate::edit_distance::delta::{
    AmendmentDelta, DeltaCaptureContext, DeltaSource, EndpointRef, MeasuredEnd, amendment_delta,
    capture_delta_best, delta_from_recorded_ops,
};
use crate::edit_distance::{
    OpAttribution, ProposalArtifactRef, RetainedProposal, TextRead, put_imported_endpoints,
    retained_proposal,
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
/// edit: its proposed and final texts are the settled endpoints. The receipt
/// is the artifact's own, reused only for an identical measurement; a
/// different one stored there (another engine version) takes a receipt of
/// its own, still naming the artifact in its refs.
///
/// Otherwise the endpoints were edited outside the recorded window (an
/// imported, endpoint-only edit). Both texts are retained under the
/// settlement's own record and measured as `reconstructed` (ARCH-0056 §3,
/// ruling r2) under that record's receipt. The proposed end stays named in
/// the original artifact when that artifact holds it.
///
/// A named artifact that does not read settles as endpoint-only.
///
/// # Errors
///
/// Storage errors.
pub(super) fn settle_window(
    vault: &Vault,
    input: &ProposalDeltaSettleRequest,
    expected_final: &str,
) -> Result<SettledWindow> {
    let original = input.artifact_ref.and_then(|id| {
        match retained_proposal(vault, ProposalArtifactRef::new(id)) {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a settlement's named artifact does not read; it settles endpoint-only"
                );
                None
            }
        }
    });
    let held_proposed = original
        .as_ref()
        .is_some_and(|original| holds(original.proposed_text(), &input.proposed_text));
    let recorded = original
        .as_ref()
        .filter(|original| held_proposed && holds(original.final_text(), expected_final))
        .and_then(|original| {
            let delta = delta_from_recorded_ops(original).ok()?;
            Some((original.record.artifact_ref, delta))
        });
    if let Some((artifact, delta)) = recorded {
        let own = settlement_receipt(artifact.entity_id());
        let receipt_id = match amendment_delta(vault, &own)? {
            Some(stored) if stored != delta => settlement_receipt(vault.new_entity_id()?),
            _ => own,
        };
        return Ok(SettledWindow {
            receipt_id,
            artifact: original,
            delta: Some(delta),
        });
    }
    let record = ProposalArtifactRef::new(vault.new_entity_id()?);
    put_imported_endpoints(
        vault,
        record,
        original
            .as_ref()
            .and_then(|original| original.record.source_turn_ref),
        &input.proposed_text,
        expected_final,
    )?;
    let proposed_at = match &original {
        Some(original) if held_proposed => {
            EndpointRef::proposal(original.record.artifact_ref, &original.record.proposed_ref)
        }
        _ => EndpointRef::imported_proposed(record),
    };
    let context = DeltaCaptureContext::from_texts(
        MeasuredEnd {
            at: proposed_at,
            content: input.proposed_text.as_str(),
        },
        MeasuredEnd {
            at: EndpointRef::imported_final(record),
            content: expected_final,
        },
    );
    Ok(SettledWindow {
        receipt_id: settlement_receipt(record.entity_id()),
        artifact: original,
        delta: capture_delta_best(context).ok(),
    })
}

/// Whether `read` is the settled text.
fn holds(read: TextRead, settled: &str) -> bool {
    read.into_text().as_deref() == Some(settled)
}

/// Each supplied hunk's attribution, given only where the recorded window
/// verifies it: the window has one change per hunk, in order, and change `i`
/// is exactly hunk `i` applied once to its own before text. A hunk that does
/// not verify, and every hunk of a reconstructed settlement, names no one.
pub(super) fn hunk_attributions(
    window: &SettledWindow,
    replacements: &[ProposalReplacement],
) -> Vec<Option<OpAttribution>> {
    let recorded = window
        .delta
        .as_ref()
        .is_some_and(|delta| delta.source == DeltaSource::RecordedOps);
    let artifact = window
        .artifact
        .as_ref()
        .filter(|artifact| recorded && artifact.record.ops_by_actor.len() == replacements.len());
    replacements
        .iter()
        .enumerate()
        .map(|(index, replacement)| {
            let artifact = artifact?;
            let (attribution, span) = artifact.record.ops_by_actor.get(index)?;
            let (TextRead::Text(before), TextRead::Text(after)) = artifact.change_texts(span)
            else {
                return None;
            };
            let applied = before.matches(replacement.before.as_str()).count() == 1
                && before.replacen(replacement.before.as_str(), &replacement.after, 1) == after;
            applied.then_some(*attribution)
        })
        .collect()
}
