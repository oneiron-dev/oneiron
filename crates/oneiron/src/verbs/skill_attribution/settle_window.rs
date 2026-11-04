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
    /// The recorded window's Δ when the settlement splits (FIX 11540): the
    /// artifact holds the proposed text but not the settled final, so `delta`
    /// is the imported tail and this is the recorded part. `None` unsplit.
    pub(super) recorded_delta: Option<AmendmentDelta>,
    /// The receipt the recorded Δ rides when the settlement splits. `None`
    /// unsplit.
    pub(super) recorded_receipt_id: Option<String>,
}

/// Measures a settlement through [`capture_delta_best`].
///
/// The named artifact's recorded window measures it when that window is this
/// edit: its proposed and final texts are the settled endpoints. The receipt
/// is the artifact's own, reused only for an identical measurement; a
/// different one stored there (another engine version) takes a receipt of
/// its own, still naming the artifact in its refs.
///
/// When the artifact holds the proposed text but not the settled final (a
/// second edit after finalize), the settlement splits (FIX 11540): the
/// recorded window keeps its Δ under the artifact's receipt, and the tail
/// (recorded-final → settled-final) measures `reconstructed` under a fresh
/// settlement receipt, its proposed end named in the original artifact.
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
            recorded_delta: None,
            recorded_receipt_id: None,
        });
    }
    // Split probe (FIX 11540): owned values only, so the borrow ends and the
    // split return below can move `original`. A recorded Δ that does not
    // measure, or a recorded-final that does not read, is no split: the
    // settlement falls through to endpoint-only, as before.
    let split = original.as_ref().and_then(|original| {
        if !(held_proposed && !holds(original.final_text(), expected_final)) {
            return None;
        }
        let recorded = delta_from_recorded_ops(original).ok()?;
        let TextRead::Text(recorded_final) = original.final_text() else {
            return None;
        };
        Some((
            original.record.artifact_ref,
            original.record.source_turn_ref,
            original.record.final_ref.clone(),
            recorded,
            recorded_final,
        ))
    });
    if let Some((artifact, source_turn_ref, final_ref, recorded, recorded_final)) = split {
        // The recorded Δ rides the artifact's receipt under the existing
        // reuse-or-own rule; the tail takes a fresh settlement receipt.
        let own = settlement_receipt(artifact.entity_id());
        let recorded_receipt_id = match amendment_delta(vault, &own)? {
            Some(stored) if stored != recorded => settlement_receipt(vault.new_entity_id()?),
            _ => own,
        };
        let tail = ProposalArtifactRef::new(vault.new_entity_id()?);
        put_imported_endpoints(
            vault,
            tail,
            source_turn_ref,
            &recorded_final,
            expected_final,
        )?;
        let context = DeltaCaptureContext::from_texts(
            MeasuredEnd {
                at: EndpointRef::proposal(artifact, &final_ref),
                content: recorded_final.as_str(),
            },
            MeasuredEnd {
                at: EndpointRef::imported_final(tail),
                content: expected_final,
            },
        );
        return Ok(SettledWindow {
            receipt_id: settlement_receipt(tail.entity_id()),
            artifact: original,
            delta: capture_delta_best(context).ok(),
            recorded_delta: Some(recorded),
            recorded_receipt_id: Some(recorded_receipt_id),
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
        recorded_delta: None,
        recorded_receipt_id: None,
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
/// A split settlement (FIX 11540) verifies the recorded prefix the same way;
/// hunks past the recorded changes are the imported tail and name no one.
pub(super) fn hunk_attributions(
    window: &SettledWindow,
    replacements: &[ProposalReplacement],
) -> Vec<Option<OpAttribution>> {
    if window
        .recorded_delta
        .as_ref()
        .is_some_and(|delta| delta.source == DeltaSource::RecordedOps)
    {
        let artifact = window.artifact.as_ref();
        return replacements
            .iter()
            .enumerate()
            .map(|(index, replacement)| verify_hunk(artifact?, index, replacement))
            .collect();
    }
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
        .map(|(index, replacement)| verify_hunk(artifact?, index, replacement))
        .collect()
}

/// Change `index`'s attribution when that change is exactly `replacement`
/// applied once to its own before text; `None` otherwise, and `None` for an
/// index past the recorded changes.
fn verify_hunk(
    artifact: &RetainedProposal,
    index: usize,
    replacement: &ProposalReplacement,
) -> Option<OpAttribution> {
    let (attribution, span) = artifact.record.ops_by_actor.get(index)?;
    let (TextRead::Text(before), TextRead::Text(after)) = artifact.change_texts(span) else {
        return None;
    };
    let applied = before.matches(replacement.before.as_str()).count() == 1
        && before.replacen(replacement.before.as_str(), &replacement.after, 1) == after;
    applied.then_some(*attribution)
}
